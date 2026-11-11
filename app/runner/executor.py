"""受控执行器：核验-封印-执行的完整闭环。

安全性按下列顺序保证（每一步失败都直接拒绝，绝不执行）：

1. 调用方只提供助手 ID；路径、SHA-256、参数全部来自镜像内只读可信配置。
2. 以 ``O_RDONLY | O_NOFOLLOW | O_CLOEXEC`` 打开源路径：拒绝符号链接，
   且确认是常规文件、无 SUID/SGID/粘滞位。
3. 以 ``fstat`` 的真实尺寸做 8 MiB 上限校验，再分块读入内存；读取期间
   源文件被替换/截断/改写只会导致读到的字节与哈希不符而被拒绝。
4. 把字节写入新建的 ``memfd``，施加 ``F_SEAL_SHRINK | F_SEAL_GROW |
   F_SEAL_WRITE | F_SEAL_SEAL`` 封印：此后任何进程（含 root）都无法修改、
   截断或追加这份字节，也无法再加/解封印。
5. **对封印后的 memfd 重新完整读取**并计算 SHA-256，与可信配置比对；
   通过后再做普通 ELF 校验。哈希与 ELF 校验的对象就是即将执行的同一份
   不可变字节，而不是某个可能再次变化的源路径。
6. 子进程 ``preexec_fn`` 中安装 seccomp 禁派生/禁执行过滤器、设置资源
   上限与独立进程组，然后以 ``/proc/self/fd/<memfd>`` 启动 —— 内核直接
   从已封印的匿名内存文件加载映像，不再触碰可写工具目录。
7. 父进程在超时（3s）、两路输出合计超限（64 KiB）或客户端取消时，
   对整个进程组发 SIGKILL 并回收，不返回任何部分结果。
"""

from __future__ import annotations

import errno
import fcntl
import hashlib
import os
import platform
import resource
import select
import signal
import subprocess
import threading
import time
from dataclasses import dataclass

from . import elf as elf_check
from .config import AssistantSpec, TrustedConfig
from .seccomp import install_no_process_filter

# memfd_create(2) 标志与系统调用号
MFD_CLOEXEC = 0x0001
MFD_ALLOW_SEALING = 0x0002
_SYS_MEMFD_CREATE = {"x86_64": 319, "aarch64": 279}

# memfd 封印集合：禁止缩/扩/写，并封印“加封印”这个动作本身
_ALL_SEALS = (
    fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE | fcntl.F_SEAL_SEAL
)

# 输出轮询粒度
_POLL_INTERVAL = 0.02
# 发送 SIGKILL 后等待回收的最长时间
_REAP_TIMEOUT = 1.0
# 子进程资源上限（8 MiB ELF 的诊断助手足够使用）
_RLIMIT_AS_BYTES = 512 * 1024 * 1024
_RLIMIT_NOFILE = 64
_RLIMIT_NPROC = 1  # 禁止 fork：配合 seccomp 双保险
_RLIMIT_CORE = 0


class AssistantError(Exception):
    """助手未能通过核验或无法启动（HTTP 409）。"""


class UnknownAssistant(AssistantError):
    """助手 ID 不在可信配置中（HTTP 404）。"""


class TimeoutExceeded(AssistantError):
    """运行超过配置时限，进程已被回收（HTTP 504）。"""


class OutputLimitExceeded(AssistantError):
    """两路输出合计超过上限，进程已被回收（HTTP 413）。"""


class ClientDisconnected(AssistantError):
    """客户端断连，进程已被回收，不返回部分结果（HTTP 499 语义）。"""


@dataclass(frozen=True)
class RunResult:
    returncode: int
    stdout_b64: str
    stderr_b64: str
    sha256: str
    elapsed_ms: int


def _memfd_create(name: str) -> int:
    import ctypes

    machine = platform.machine()
    if machine not in _SYS_MEMFD_CREATE:
        raise AssistantError(f"平台 {machine} 不支持 memfd_create")
    libc = ctypes.CDLL(None, use_errno=True)
    fd = libc.syscall(
        _SYS_MEMFD_CREATE[machine],
        ctypes.c_char_p(name.encode("utf-8") + b"\x00"),
        MFD_CLOEXEC | MFD_ALLOW_SEALING,
    )
    if fd < 0:
        raise AssistantError(
            f"memfd_create 失败: errno={ctypes.get_errno()} {errno.errorcode.get(ctypes.get_errno(), '')}"
        )
    return fd


def _open_source(path: str) -> tuple[int, os.stat_result]:
    """O_NOFOLLOW 打开源文件并做常规文件/特权位检查，返回 (fd, 初始 stat)。"""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError as exc:
        raise AssistantError(f"助手源文件不存在: {path}") from exc
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise AssistantError(f"助手路径是符号链接，拒绝执行: {path}") from exc
        raise AssistantError(f"无法打开助手源文件 {path}: {exc}") from exc

    try:
        st = os.fstat(fd)
    except OSError as exc:
        os.close(fd)
        raise AssistantError(f"无法 stat 助手源文件: {exc}") from exc

    import stat as stat_mod

    if not stat_mod.S_ISREG(st.st_mode):
        os.close(fd)
        raise AssistantError("仅支持常规文件，拒绝非常规文件类型")
    if st.st_mode & (stat_mod.S_ISUID | stat_mod.S_ISGID | stat_mod.S_ISVTX):
        os.close(fd)
        raise AssistantError("拒绝带 SUID/SGID/粘滞位的文件")
    return fd, st


def _assert_same_inode(st: os.stat_result, initial: os.stat_result, where: str) -> None:
    """确认两次 stat 指向同一 inode 身份，且内容/元数据未被改动。

    比对项：
    * ``st_dev`` / ``st_ino`` —— 路径是否被 rename 换成另一个文件；
    * ``st_size`` —— 截断或追加；
    * ``st_ctime_ns`` —— inode 任何内容/元数据变更都会更新 ctime，
      原地 write 也不例外，粒度比 mtime 更可靠，无法由普通进程回拨。
    """
    if (st.st_dev, st.st_ino) != (initial.st_dev, initial.st_ino):
        raise AssistantError(f"源文件在{where}被替换（inode 身份变化），拒绝执行")
    if st.st_size != initial.st_size:
        raise AssistantError(f"源文件在{where}被截断或追加（尺寸变化），拒绝执行")
    if st.st_ctime_ns != initial.st_ctime_ns:
        raise AssistantError(f"源文件在{where}被原地改写（ctime 变化），拒绝执行")


def _read_limited(fd: int, limit: int, initial: os.stat_result) -> bytes:
    """从 fd 分块读取至多 limit 字节；超过上限立即拒绝。

    每轮读取后对同一打开描述符 ``fstat``：即使源路径被同 inode 原地改写，
    尺寸/mtime 变化也能在读取窗口内被发现。
    """
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        total += len(chunk)
        if total > limit:
            raise AssistantError(
                f"助手超过 {limit} 字节上限（已读 {total} 字节），拒绝执行"
            )
        chunks.append(chunk)
        cur = os.fstat(fd)
        _assert_same_inode(cur, initial, "读取过程中")
    if total != initial.st_size:
        raise AssistantError("读取字节数与文件尺寸不一致（文件可能在读取期间变化）")
    return b"".join(chunks)


def _reopen_and_verify_identity(
    path: str, initial: os.stat_result, expected_size: int
) -> os.stat_result:
    """重新 O_NOFOLLOW 打开源路径，核对身份与尺寸。

    这一步关闭「读取完成后、启动前」的替换/截断/原地改写窗口：
    路径若被换成别的 inode、或同 inode 被改动，都会与打开时记录的身份不符。
    返回重新 stat 的结果，供调用方做后续内容比对。
    """
    fd, st = _open_source(path)
    try:
        _assert_same_inode(st, initial, "核验期间")
        if st.st_size != expected_size:
            raise AssistantError("源文件尺寸与已核验字节不一致，拒绝执行")
        return st
    finally:
        os.close(fd)


def _reopen_and_compare_bytes(path: str, expected: bytes, initial: os.stat_result) -> None:
    """哈希通过后最后一次重新打开源路径，全量比对当前字节与封印字节。

    即使存在 stat 时间戳粒度无法区分的极端同 inode 改写，只要当前路径下
    的字节与已封印、已核验的字节有任何差异即拒绝；内容一致才允许启动。
    """
    fd, st = _open_source(path)
    try:
        _assert_same_inode(st, initial, "启动前")
        if st.st_size != len(expected):
            raise AssistantError("启动前源文件尺寸与已核验字节不一致，拒绝执行")
        actual = _read_limited(fd, len(expected), st)
        if actual != expected:
            raise AssistantError(
                "启动前源文件字节与已封印核验字节不一致（疑似原地改写），拒绝执行"
            )
    finally:
        os.close(fd)


def _sealed_memfd_from_bytes(data: bytes, name: str) -> int:
    """把字节写入 memfd 并施加不可变封印，返回 memfd 描述符。"""
    memfd = _memfd_create(name)
    try:
        view = memoryview(data)
        written = 0
        while written < len(view):
            n = os.write(memfd, view[written:])
            if n <= 0:  # pragma: no cover - memfd 写入不应失败
                raise AssistantError("写入 memfd 失败")
            written += n
        # 封印后任何修改/截断/追加都会被内核拒绝（EPERM）
        fcntl.fcntl(memfd, fcntl.F_ADD_SEALS, _ALL_SEALS)
        seals = fcntl.fcntl(memfd, fcntl.F_GET_SEALS)
        if seals != _ALL_SEALS:
            raise AssistantError(f"memfd 封印不完整: {seals:#x}")
    except BaseException:
        os.close(memfd)
        raise
    return memfd


def _reread_and_hash(fd: int) -> bytes:
    """重新完整读取已封印 memfd，返回其字节（哈希与 ELF 校验均针对它）。"""
    os.lseek(fd, 0, os.SEEK_SET)
    h = hashlib.sha256()
    chunks: list[bytes] = []
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        h.update(chunk)
        chunks.append(chunk)
    os.lseek(fd, 0, os.SEEK_SET)
    data = b"".join(chunks)
    return data, h.hexdigest()


def _child_preexec() -> None:
    """子进程在 exec 前执行：独立进程组、资源上限、seccomp、清空环境。"""
    # 独立进程组，方便父进程一次性回收整组
    os.setpgid(0, 0)
    # 父进程若先死亡，内核自动回收，避免孤儿助手
    import ctypes

    libc = ctypes.CDLL(None, use_errno=True)
    PR_SET_PDEATHSIG = 1
    if libc.prctl(PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0) != 0:
        # 极端环境下不支持时不阻断执行，进程组仍由父进程 SIGKILL 兜底
        pass

    # 资源上限：双保险限制失控助手
    resource.setrlimit(resource.RLIMIT_AS, (_RLIMIT_AS_BYTES, _RLIMIT_AS_BYTES))
    resource.setrlimit(resource.RLIMIT_CORE, (_RLIMIT_CORE, _RLIMIT_CORE))
    resource.setrlimit(resource.RLIMIT_NOFILE, (_RLIMIT_NOFILE, _RLIMIT_NOFILE))
    try:
        resource.setrlimit(resource.RLIMIT_NPROC, (_RLIMIT_NPROC, _RLIMIT_NPROC))
    except (ValueError, OSError):
        # 某些容器环境/uid 下不允许调整 nproc，忽略，seccomp 仍会拦截
        pass

    # 安装禁派生/禁执行过滤器（安装失败则直接退出，绝不无过滤运行）
    install_no_process_filter()


def _kill_group(proc: subprocess.Popen) -> None:
    """对整个进程组发 SIGKILL 并回收。

    子进程可能已经自行退出（如被 seccomp 以 SIGSYS 终止成为僵尸），
    对僵尸描述符发信号会得到 EPERM；这些情况都以 ``wait`` 回收为准。

    必须先关闭父进程持有的 stdout/stderr 管道再 ``wait``：否则当管道缓冲
    被未读输出占满时，子进程即使收到 SIGKILL 也会停在管道写端的关闭流程
    上，而父进程又在 ``wait`` 中死等，形成长达数秒的回收停顿。
    """
    if proc.poll() is None:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except PermissionError:
            # 目标已是僵尸或正在退出：直接 wait 回收
            pass
        except OSError:
            try:
                proc.kill()
            except (ProcessLookupError, PermissionError):
                pass
    for pipe in (proc.stdout, proc.stderr):
        if pipe is not None and not pipe.closed:
            try:
                pipe.close()
            except OSError:
                pass
    try:
        proc.wait(timeout=_REAP_TIMEOUT)
    except subprocess.TimeoutExpired:  # pragma: no cover - 极端情况
        pass


def run_assistant(
    spec: AssistantSpec,
    config: TrustedConfig,
    *,
    cancel_event: threading.Event | None = None,
) -> RunResult:
    """核验并运行一个已批准助手，返回退出码与 Base64 输出。

    任何越限（超时、输出超限、客户端取消）都会先杀掉并回收整个进程组，
    再抛出异常，绝不返回部分结果。
    """
    started = time.monotonic()
    source_fd = -1
    memfd = -1
    proc: subprocess.Popen | None = None

    try:
        # ---- 1. 打开并读取源文件（O_NOFOLLOW，常规文件，8 MiB 上限）----
        source_fd, initial_st = _open_source(spec.path)
        try:
            if initial_st.st_size > config.max_assistant_bytes:
                raise AssistantError(
                    f"助手尺寸 {initial_st.st_size} 超过 {config.max_assistant_bytes} 字节上限"
                )
            data = _read_limited(source_fd, config.max_assistant_bytes, initial_st)
        finally:
            os.close(source_fd)
            source_fd = -1

        # ---- 2. 写入 memfd 并施加不可变封印 -----------------------------
        memfd = _sealed_memfd_from_bytes(data, f"diag-{spec.id}")
        del data  # 后续只信任封印后的同一份字节

        # ---- 3. 重新打开源路径核对身份：关闭读取后到启动前的替换窗口 ----
        # 封印已经完成，此刻若源 inode/尺寸/mtime 与打开时不同，说明字节
        # 是在读取窗口外被换掉的，memfd 中的内容不再代表当前批准路径，拒绝。
        _reopen_and_verify_identity(spec.path, initial_st, initial_st.st_size)

        # ---- 4. 重新完整读取封印字节并核验 SHA-256 / ELF ----------------
        sealed_data, digest = _reread_and_hash(memfd)
        if not _constant_time_equal(digest, spec.sha256):
            raise AssistantError(
                "SHA-256 核验失败：源文件内容与可信配置不一致（可能被替换、截断或改写）"
            )
        try:
            elf_check.validate_elf(sealed_data)
        except elf_check.ElfError as exc:
            raise AssistantError(f"ELF 核验失败: {exc}") from exc

        # ---- 5. 启动前最后一次全量比对：当前源字节必须就是封印字节 ------
        # 与第 3 步的身份核对形成双保险：stat 时间戳 + 实际字节内容，
        # 任何替换、截断、原地改写都无法通过。
        _reopen_and_compare_bytes(spec.path, sealed_data, initial_st)
        del sealed_data

        # ---- 6. 以 /proc/self/fd/<memfd> 启动，内核直接加载封印字节 ----
        proc_path = f"/proc/self/fd/{memfd}"
        argv = [proc_path, *spec.args]
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={},  # 最小环境：不继承任何调用侧变量
            cwd="/",
            close_fds=True,
            pass_fds=(memfd,),  # 保持 memfd 可继承，供 /proc/self/fd 打开
            preexec_fn=_child_preexec,
        )
        # 父进程关闭自己的副本：子进程持有独立引用，封印保证内容不可变
        os.close(memfd)
        memfd = -1

        # ---- 7. 监督运行：超时 / 输出上限 / 客户端取消 ------------------
        return _supervise(proc, spec, digest, started, cancel_event)

    except BaseException:
        if proc is not None and proc.poll() is None:
            _kill_group(proc)
        if memfd >= 0:
            try:
                os.close(memfd)
            except OSError:
                pass
        if source_fd >= 0:
            try:
                os.close(source_fd)
            except OSError:
                pass
        raise


def _supervise(
    proc: subprocess.Popen,
    spec: AssistantSpec,
    digest: str,
    started: float,
    cancel_event: threading.Event | None,
) -> RunResult:
    out_buf = bytearray()
    err_buf = bytearray()
    pipes = {
        proc.stdout.fileno(): (proc.stdout, out_buf),
        proc.stderr.fileno(): (proc.stderr, err_buf),
    }
    deadline = started + spec.timeout_seconds

    while True:
        if cancel_event is not None and cancel_event.is_set():
            _kill_group(proc)
            raise ClientDisconnected("客户端已断连，进程已终止回收，不返回部分结果")

        # 先收集管道上已就绪的数据，再判定进程是否退出，
        # 避免「子进程已退出但管道里还有残余输出」时漏读
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _kill_group(proc)
            raise TimeoutExceeded(
                f"运行超过 {spec.timeout_seconds} 秒，进程组已终止回收"
            )

        ready, _, _ = select.select(list(pipes), [], [], min(_POLL_INTERVAL, remaining))
        for fd in ready:
            _, buf = pipes[fd]
            chunk = os.read(fd, 65536)
            if chunk:
                buf.extend(chunk)
                if len(out_buf) + len(err_buf) > spec.max_output_bytes:
                    _kill_group(proc)
                    raise OutputLimitExceeded(
                        f"输出合计超过 {spec.max_output_bytes} 字节上限，进程组已终止回收"
                    )

        if proc.poll() is not None:
            # 进程退出：排空管道里内核已缓冲的残余输出
            _drain_remaining(proc, out_buf, err_buf, spec.max_output_bytes)
            total = len(out_buf) + len(err_buf)
            if total > spec.max_output_bytes:
                # 退出瞬间超限同样不返回部分结果
                raise OutputLimitExceeded(
                    f"输出合计 {total} 字节超过 {spec.max_output_bytes} 字节上限"
                )
            break

    import base64

    return RunResult(
        returncode=proc.returncode,
        stdout_b64=base64.b64encode(bytes(out_buf)).decode("ascii"),
        stderr_b64=base64.b64encode(bytes(err_buf)).decode("ascii"),
        sha256=digest,
        elapsed_ms=int((time.monotonic() - started) * 1000),
    )


def _drain_remaining(
    proc: subprocess.Popen,
    out_buf: bytearray,
    err_buf: bytearray,
    max_bytes: int,
) -> None:
    for pipe, buf in ((proc.stdout, out_buf), (proc.stderr, err_buf)):
        os.set_blocking(pipe.fileno(), False)
        while True:
            try:
                chunk = os.read(pipe.fileno(), 65536)
            except BlockingIOError:
                break
            if not chunk:
                break
            buf.extend(chunk)
            if len(out_buf) + len(err_buf) > max_bytes:
                return


def _constant_time_equal(a: str, b: str) -> bool:
    """定长字符串的常量时间比较，避免哈希比对侧信道。"""
    import hmac

    return hmac.compare_digest(a, b)
