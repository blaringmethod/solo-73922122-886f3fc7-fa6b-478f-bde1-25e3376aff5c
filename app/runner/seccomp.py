"""seccomp BPF 过滤器：禁止助手派生进程或执行其他程序。

不依赖 libseccomp，直接通过 ``prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER)``
安装经典 BPF 程序。过滤器在 :func:`subprocess.Popen` 的 ``preexec_fn`` 阶段、
``execve`` 之前装入，因此对助手进程整个生命周期生效。

拦截策略（命中即 ``SECCOMP_RET_KILL_PROCESS``，整个进程立即被杀，无信号
处理器可绕过）：

* 进程/线程/容器创建：``fork`` ``vfork`` ``clone`` ``clone3`` —— 不派生
  子进程这一硬约束的强制点（线程也是 clone 出来的，同样禁止）；
* 命名空间逃逸：``unshare`` ``setns``。

注意 **不拦截** ``execve``/``execveat``：本进程的首次 execve 由受控启动
流程在过滤器安装之后发起，用于让系统加载器加载已封印的 memfd 映像；
而“不能换入其他程序”由可信配置 + memfd 不可变封印在启动前保证，进程
起来后既无法 clone 出子进程、也没有任何外部输入可触发新的 exec。
系统加载器与动态库的正常加载由内核在同一次 execve 中完成。
"""

from __future__ import annotations

import ctypes
import platform
import struct

# prctl
PR_SET_NO_NEW_PRIVS = 38
PR_SET_SECCOMP = 22
SECCOMP_MODE_FILTER = 2

# BPF 指令字段
BPF_LD = 0x00
BPF_JMP = 0x05
BPF_RET = 0x06
BPF_W = 0x00
BPF_ABS = 0x20
BPF_JEQ = 0x10
BPF_K = 0x00

# seccomp data 偏移
OFF_NR = 0
OFF_ARCH = 4

SECCOMP_RET_KILL_PROCESS = 0x80000000
SECCOMP_RET_ALLOW = 0x7FFF0000

# 架构审计号
_AUDIT_ARCH = {
    "x86_64": 0xC000003E,
    "aarch64": 0xC00000B7,
}

# x86_64 系统调用号
_X86_64_BLOCKED = {
    57: "fork",
    58: "vfork",
    56: "clone",
    435: "clone3",
    272: "unshare",
    308: "setns",
}

# aarch64 系统调用号（无独立 fork/vfork，glibc 统一走 clone）
_AARCH64_BLOCKED = {
    220: "clone",
    435: "clone3",
    97: "unshare",
    268: "setns",
}


class SeccompError(RuntimeError):
    """当前平台不支持或内核拒绝安装 seccomp 过滤器。"""


def _insn(code: int, jt: int = 0, jf: int = 0, k: int = 0) -> bytes:
    return struct.pack("HBBI", code, jt, jf, k)


def _build_filter(audit_arch: int, blocked: dict[int, str]) -> bytes:
    """生成 BPF 字节码。

    1. 先校验 seccomp data 的架构号，非本机架构直接 KILL（防混淆攻击）；
    2. 逐条比较系统调用号，命中黑名单即 KILL；
    3. 其余 ALLOW。
    """
    program: list[bytes] = []

    # 加载架构号并比较
    program.append(_insn(BPF_LD | BPF_W | BPF_ABS, k=OFF_ARCH))
    program.append(_insn(BPF_JMP | BPF_JEQ | BPF_K, jt=1, k=audit_arch))
    program.append(_insn(BPF_RET | BPF_K, k=SECCOMP_RET_KILL_PROCESS))

    # 加载系统调用号
    program.append(_insn(BPF_LD | BPF_W | BPF_ABS, k=OFF_NR))

    blocked_sorted = sorted(blocked)
    for nr in blocked_sorted:
        # 相等则落入下一条 KILL；不相等则跳过 KILL 继续比较
        program.append(_insn(BPF_JMP | BPF_JEQ | BPF_K, jf=1, k=nr))
        program.append(_insn(BPF_RET | BPF_K, k=SECCOMP_RET_KILL_PROCESS))

    program.append(_insn(BPF_RET | BPF_K, k=SECCOMP_RET_ALLOW))
    return b"".join(program)


class _SockProg(ctypes.Structure):
    _fields_ = [
        ("len", ctypes.c_ushort),
        ("filter", ctypes.c_void_p),
    ]


def install_no_process_filter() -> None:
    """在当前进程（即将 exec 的子进程）中安装禁派生/禁执行过滤器。"""
    machine = platform.machine()
    if machine not in _AUDIT_ARCH:
        raise SeccompError(f"平台 {machine} 未提供 seccomp 规则")
    audit_arch = _AUDIT_ARCH[machine]
    blocked = _X86_64_BLOCKED if machine == "x86_64" else _AARCH64_BLOCKED

    bytecode = _build_filter(audit_arch, blocked)

    libc = ctypes.CDLL(None, use_errno=True)

    # NO_NEW_PRIVS 是非特权容器内安装过滤器的前提，同时阻断提权
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        err = ctypes.get_errno()
        raise SeccompError(f"prctl(PR_SET_NO_NEW_PRIVS) 失败: errno={err}")

    buf = ctypes.c_char_p(bytecode)
    prog = _SockProg(
        len=len(bytecode) // 8,
        filter=ctypes.cast(buf, ctypes.c_void_p),
    )
    if libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.byref(prog), 0, 0) != 0:
        err = ctypes.get_errno()
        raise SeccompError(f"prctl(PR_SET_SECCOMP) 失败: errno={err}")
