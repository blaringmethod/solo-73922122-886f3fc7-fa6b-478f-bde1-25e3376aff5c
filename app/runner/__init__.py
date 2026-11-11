"""受控诊断助手执行子系统。

设计要点（详见 README「安全模型」）：

* :mod:`config`   —— 可信启动配置（固定 ID、路径、SHA-256、参数），仅由镜像内
  只读文件提供，调用方只能传助手 ID。
* :mod:`elf`      —— 普通 ELF 校验（64 位小端、可执行类型、含 PT_INTERP、
  无特权位等），系统加载器与动态库视为可信。
* :mod:`seccomp`  —— 禁止派生/执行类系统调用的 BPF 过滤器。
* :mod:`executor` —— O_NOFOLLOW 打开源文件 -> 限额读取 -> 写入 memfd 并
  施加 SEAL_WRITE/SEAL_SHRINK/SEAL_GROW/SEAL_SEAL 封印 -> 对封印后的同一份
  不可变字节做 SHA-256 全量核验与 ELF 校验 -> 以 /proc/self/fd/<memfd>
  执行，确保「执行的必须是核验过的同一份不可变字节」，源文件在读取、核验
  或启动时被替换、截断、原地改写都不可能执行未批准内容。
"""

from .config import AssistantSpec, TrustedConfig, load_trusted_config
from .executor import (
    AssistantError,
    ClientDisconnected,
    OutputLimitExceeded,
    TimeoutExceeded,
    UnknownAssistant,
    run_assistant,
)

__all__ = [
    "AssistantSpec",
    "TrustedConfig",
    "load_trusted_config",
    "AssistantError",
    "UnknownAssistant",
    "ClientDisconnected",
    "TimeoutExceeded",
    "OutputLimitExceeded",
    "run_assistant",
]
