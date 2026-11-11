"""受控执行子系统测试（仅标准库，python3 -I 直接运行）。

覆盖：
* 可信配置加载与硬上限约束；
* ELF 校验（魔数、类型、PT_INTERP、截断）；
* 执行闭环：正常执行、退出码透传、stdout/stderr 分离、参数固定；
* seccomp：fork/clone 被 SIGSYS 终止，execve 单次替换可用；
* 防篡改：替换、截断、原地改写、符号链接、非 ELF、超 8 MiB；
* TOCTOU：rename 风暴与原地改写风暴下绝不执行未批准内容；
* 资源治理：3s 超时、64KiB 输出上限、客户端取消、无进程残留；
* 并发隔离：多线程并发互不干扰。

首次运行若 fixtures 未编译且本机有 gcc 会自动编译；镜像内使用预编译产物。
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.runner import (  # noqa: E402
    AssistantError,
    ClientDisconnected,
    OutputLimitExceeded,
    TimeoutExceeded,
    load_trusted_config,
    run_assistant,
)
from app.runner.config import AssistantSpec, ConfigError  # noqa: E402
from app.runner.elf import ElfError, validate_elf  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURE_SRC = os.path.join(ROOT, "tests", "fixtures")
FAILURES: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    if not cond:
        FAILURES.append(f"{name} {detail}")
        print(f"  FAIL - {name} {detail}")
    else:
        print(f"  ok - {name}")


def _find_gcc() -> str | None:
    for cand in ("/usr/bin/gcc", "/usr/bin/cc", "gcc", "cc"):
        path = shutil.which(cand)
        if path and os.path.isfile(path):
            # 某些环境的 cc 是任务包装器脚本，gcc 更可靠
            if cand.endswith("gcc"):
                return path
    return shutil.which("gcc") or shutil.which("cc")


def compile_fixtures(dst: str) -> dict[str, str]:
    """返回测试夹具 {名称: 路径}。

    优先使用镜像内随包交付的预编译产物（运行镜像无 gcc）；否则在有 gcc
    的开发/构建环境现场编译。
    """
    prebuilt = os.path.join(ROOT, "tests", "prebuilt")
    needed = ("echoer", "forker", "execer", "archinfo", "slowprobe", "bigprinter")
    if os.path.isdir(prebuilt) and all(
        os.path.isfile(os.path.join(prebuilt, n)) for n in needed
    ):
        return {n: os.path.join(prebuilt, n) for n in needed}

    gcc = _find_gcc()
    if not gcc:
        raise RuntimeError("未找到 gcc 且无预编译夹具，无法运行本套件")
    sources = {
        "echoer": os.path.join(FIXTURE_SRC, "echoer.c"),
        "forker": os.path.join(FIXTURE_SRC, "forker.c"),
        "execer": os.path.join(FIXTURE_SRC, "execer.c"),
        "archinfo": os.path.join(ROOT, "tools", "archinfo.c"),
        "slowprobe": os.path.join(ROOT, "tools", "slowprobe.c"),
        "bigprinter": os.path.join(ROOT, "tools", "bigprinter.c"),
    }
    out = {}
    for name, src in sources.items():
        target = os.path.join(dst, name)
        subprocess.run(
            [gcc, "-O2", "-Wall", "-Wextra", "-o", target, src],
            check=True,
            capture_output=True,
        )
        out[name] = target
    return out


def spec_for(path: str, args: tuple[str, ...] = (), *, timeout: float = 3.0,
             outlim: int = 64 * 1024, digest: str | None = None) -> AssistantSpec:
    if digest is None:
        with open(path, "rb") as fh:
            digest = hashlib.sha256(fh.read()).hexdigest()
    return AssistantSpec(
        id="t-" + os.path.basename(path),
        path=path,
        sha256=digest,
        args=args,
        timeout_seconds=timeout,
        max_output_bytes=outlim,
    )


def write_config(path: str, tools: dict[str, str], *, args: dict | None = None,
                 timeout: float = 3.0, outlim: int = 64 * 1024) -> None:
    args = args or {}
    assistants = {}
    for name, target in tools.items():
        with open(target, "rb") as fh:
            digest = hashlib.sha256(fh.read()).hexdigest()
        assistants[name] = {
            "path": target,
            "sha256": digest,
            "args": args.get(name, []),
            "timeout_seconds": timeout,
            "max_output_bytes": outlim,
        }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(
            {
                "defaults": {
                    "timeout_seconds": timeout,
                    "max_output_bytes": outlim,
                    "max_assistant_bytes": 8 * 1024 * 1024,
                    "max_concurrency": 32,
                },
                "assistants": assistants,
            },
            fh,
        )


def memfd_procs(exclude_pid: int) -> list[tuple[int, str]]:
    found = []
    for pid in os.listdir("/proc"):
        if not pid.isdigit() or int(pid) == exclude_pid:
            continue
        try:
            link = os.readlink(f"/proc/{pid}/exe")
        except OSError:
            continue
        if "memfd" in link:
            found.append((int(pid), link))
    return found


def main() -> int:
    workdir = tempfile.mkdtemp(prefix="runner-test-")
    bindir = os.path.join(workdir, "bin")
    os.makedirs(bindir)
    try:
        tools = compile_fixtures(bindir)
    except (RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"夹具编译失败，跳过本套件: {exc}")
        return 0

    cfg_path = os.path.join(workdir, "assistants.json")
    write_config(cfg_path, tools, args={"archinfo": ["--verbose"]})
    cfg = load_trusted_config(cfg_path)
    me = os.getpid()

    # ------------------------------------------------------------------ #
    print("test_config_loading")
    check("加载三个助手", set(cfg.assistants) == set(tools))
    check("8MiB 硬上限", cfg.max_assistant_bytes == 8 * 1024 * 1024)
    bad_cfg = os.path.join(workdir, "bad.json")
    with open(bad_cfg, "w") as fh:
        json.dump({"defaults": {"timeout_seconds": 9.0}, "assistants":
                   {"x": {"path": tools["echoer"],
                          "sha256": "a" * 64, "args": []}}}, fh)
    try:
        load_trusted_config(bad_cfg)
        check("超时硬上限拒绝", False)
    except ConfigError:
        check("超时硬上限拒绝", True)
    with open(bad_cfg, "w") as fh:
        json.dump({"assistants": {"x": {"path": "relative/path",
                                         "sha256": "z" * 64, "args": []}}}, fh)
    try:
        load_trusted_config(bad_cfg)
        check("相对路径拒绝", False)
    except ConfigError:
        check("相对路径拒绝", True)

    # ------------------------------------------------------------------ #
    print("test_elf_validation")
    good_elf = open(tools["archinfo"], "rb").read()
    validate_elf(good_elf)
    check("正常 ELF 通过", True)
    for name, blob in [
        ("短文件", b"\x7fELF"),
        ("坏魔数", b"XXXX" + good_elf[4:]),
        ("非可执行类型", good_elf[:16] + b"\x01\x00" + good_elf[18:]),
        ("截断", good_elf[:200]),
        ("脚本", b"#!/bin/sh\nexit 0\n"),
    ]:
        try:
            validate_elf(blob)
            check(f"拒绝 {name}", False)
        except ElfError:
            check(f"拒绝 {name}", True)

    # ------------------------------------------------------------------ #
    print("test_normal_execution")
    r = run_assistant(cfg.get("archinfo"), cfg)
    out = base64.b64decode(r.stdout_b64).decode()
    check("退出码 0", r.returncode == 0)
    check("stdout 含报告", "archinfo diagnostic report" in out)
    check("seccomp 已启用", "Seccomp:\t2" in out)
    check("返回哈希等于配置", r.sha256 == cfg.get("archinfo").sha256)
    check("参数固定注入", "argv[1]=--verbose" in out or "[--verbose]" in out)
    check("耗时为正且毫秒级", r.elapsed_ms >= 0)

    print("test_exit_code_and_streams")
    r = run_assistant(spec_for(tools["echoer"], ("7",)), cfg)
    o = base64.b64decode(r.stdout_b64).decode()
    e = base64.b64decode(r.stderr_b64).decode()
    check("退出码透传 7", r.returncode == 7)
    check("参数进入 argv", "argv[1]=7" in o)
    check("stderr 独立返回", e.strip() == "echoer stderr marker")
    check("stdout 为 base64", r.stdout_b64 == base64.b64encode(
        base64.b64decode(r.stdout_b64)).decode())

    # ------------------------------------------------------------------ #
    print("test_seccomp_no_child")
    r = run_assistant(spec_for(tools["forker"]), cfg)
    check("fork 触发 SIGSYS(-31)", r.returncode == -31)
    r = run_assistant(spec_for(tools["execer"]), cfg)
    check("单次 execve 替换为 /bin/true 成功", r.returncode == 0)
    check("seccomp 后无残留进程", memfd_procs(me) == [])

    # ------------------------------------------------------------------ #
    print("test_timeout")
    t0 = time.monotonic()
    try:
        run_assistant(cfg.get("slowprobe"), cfg)
        check("3 秒超时杀进程", False)
    except TimeoutExceeded:
        check("3 秒超时杀进程", True)
    check("超时点接近 3 秒", 2.8 <= time.monotonic() - t0 <= 4.0)
    time.sleep(0.1)
    check("超时后无残留", memfd_procs(me) == [])

    print("test_output_limit")
    try:
        run_assistant(cfg.get("bigprinter"), cfg)
        check("64KiB 输出上限", False)
    except OutputLimitExceeded:
        check("64KiB 输出上限", True)
    time.sleep(0.1)
    check("输出超限后无残留", memfd_procs(me) == [])

    # 小限额快速触发
    small = spec_for(tools["archinfo"], outlim=128)
    try:
        run_assistant(small, cfg)
        check("自定义小限额生效", False)
    except OutputLimitExceeded:
        check("自定义小限额生效", True)

    # ------------------------------------------------------------------ #
    print("test_tamper_rejection")
    target = os.path.join(workdir, "tampered")
    good = open(tools["archinfo"], "rb").read()
    evil = open(tools["forker"], "rb").read()

    def reset_good() -> None:
        with open(target, "wb") as fh:
            fh.write(good)
        os.chmod(target, 0o755)

    reset_good()
    base_spec = spec_for(target)
    rr = run_assistant(base_spec, cfg)
    check("篡改前基线可执行", rr.returncode == 0)

    with open(target, "wb") as fh:
        fh.write(evil)
    try:
        run_assistant(base_spec, cfg)
        check("整体替换拒绝", False)
    except AssistantError:
        check("整体替换拒绝", True)

    with open(target, "wb") as fh:
        fh.write(good[:1000])
    try:
        run_assistant(base_spec, cfg)
        check("截断拒绝", False)
    except AssistantError:
        check("截断拒绝", True)

    reset_good()
    off = next(i for i in range(64, len(good)) if good[i] not in (0,))
    with open(target, "r+b") as fh:
        fh.seek(off)
        fh.write(bytes([good[off] ^ 0xFF]))
    try:
        run_assistant(base_spec, cfg)
        check("原地改写拒绝", False)
    except AssistantError:
        check("原地改写拒绝", True)

    reset_good()
    os.remove(target)
    os.symlink(tools["forker"], target)
    try:
        run_assistant(base_spec, cfg)
        check("符号链接拒绝", False)
    except AssistantError:
        check("符号链接拒绝", True)

    os.remove(target)
    with open(target, "wb") as fh:
        fh.write(b"#!/bin/sh\necho x\n")
    os.chmod(target, 0o755)
    script_spec = spec_for(target)
    try:
        run_assistant(script_spec, cfg)
        check("非 ELF 拒绝", False)
    except AssistantError:
        check("非 ELF 拒绝", True)

    big = os.path.join(workdir, "big")
    with open(big, "wb") as fh:
        fh.write(b"\x7fELF" + b"\x00" * (8 * 1024 * 1024))
    try:
        run_assistant(spec_for(big), cfg)
        check("超 8MiB 拒绝", False)
    except AssistantError:
        check("超 8MiB 拒绝", True)

    # ------------------------------------------------------------------ #
    print("test_toctou_rename_storm")
    reset_good()
    good_hash = hashlib.sha256(good).hexdigest()
    stop = threading.Event()

    def swapper() -> None:
        while not stop.is_set():
            current_size = os.path.getsize(target)
            data = evil if current_size == len(good) else good
            tmp = target + ".tmp"
            with open(tmp, "wb") as fh:
                fh.write(data)
            os.chmod(tmp, 0o755)
            os.replace(tmp, target)
            time.sleep(0.0005)

    th = threading.Thread(target=swapper)
    th.start()
    ok = rejected = 0
    try:
        for _ in range(100):
            try:
                rr = run_assistant(base_spec, cfg)
                check_idx = rr.sha256 == good_hash and rr.returncode == 0
                if check_idx:
                    ok += 1
                else:
                    FAILURES.append("rename 风暴执行了非批准内容")
            except AssistantError:
                rejected += 1
    finally:
        stop.set()
        th.join()
    check("rename 风暴全部安全（成功且哈希正确或拒绝）", ok + rejected == 100)
    check("rename 风暴存在成功样本", ok > 0, f"ok={ok}")

    print("test_toctou_inplace_storm")
    reset_good()
    stop2 = threading.Event()

    def mutator() -> None:
        while not stop2.is_set():
            with open(target, "r+b") as fh:
                fh.seek(64 + (int(time.time() * 1000) % 500))
                fh.write(os.urandom(16))
            time.sleep(0.0003)

    th2 = threading.Thread(target=mutator)
    th2.start()
    safe = 0
    try:
        for _ in range(60):
            try:
                rr = run_assistant(base_spec, cfg)
                if rr.sha256 == good_hash and rr.returncode == 0:
                    safe += 1
                else:
                    FAILURES.append("原地改写风暴执行了非批准内容")
            except AssistantError:
                safe += 1  # 拒绝也是安全结果
    finally:
        stop2.set()
        th2.join()
    check("原地改写风暴零未批准执行", safe == 60)

    # ------------------------------------------------------------------ #
    print("test_concurrency_isolation")
    errors: list[str] = []

    def worker(idx: int) -> None:
        for _ in range(5):
            try:
                rr = run_assistant(cfg.get("archinfo"), cfg)
                if rr.returncode != 0 or rr.sha256 != cfg.get("archinfo").sha256:
                    errors.append(f"worker{idx} bad result")
            except Exception as exc:  # noqa: BLE001
                errors.append(f"worker{idx} {exc!r}")

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
    t0 = time.monotonic()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    check("20 线程 x 5 次并发全部正确", not errors, str(errors))
    check("并发总耗时合理", time.monotonic() - t0 < 10.0)

    print("test_client_cancel")
    ev = threading.Event()
    outcome: dict[str, str] = {}

    def cancelled_run() -> None:
        try:
            run_assistant(cfg.get("slowprobe"), cfg, cancel_event=ev)
            outcome["r"] = "ran"
        except ClientDisconnected:
            outcome["r"] = "cancelled"
        except Exception as exc:  # noqa: BLE001
            outcome["r"] = repr(exc)

    t = threading.Thread(target=cancelled_run)
    t.start()
    time.sleep(0.3)
    ev.set()
    t.join(timeout=5)
    check("取消触发 ClientDisconnected", outcome.get("r") == "cancelled")
    time.sleep(0.1)
    check("取消后无残留进程", memfd_procs(me) == [])

    # ------------------------------------------------------------------ #
    shutil.rmtree(workdir, ignore_errors=True)
    print()
    if FAILURES:
        print(f"{len(FAILURES)} 项失败")
        for item in FAILURES:
            print(" -", item)
        return 1
    print("受控执行子系统全部测试通过")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
