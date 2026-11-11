"""可信启动配置。

配置文件随镜像以只读方式分发，固定每个已批准助手的 **ID、绝对路径、
SHA-256 与参数模板**。HTTP 调用方只能提供助手 ID，不能影响路径、哈希或
参数，从入口上杜绝「把可写工具目录换入其他程序」。

配置 JSON 结构::

    {
      "defaults": {
        "timeout_seconds": 3.0,
        "max_output_bytes": 65536,
        "max_assistant_bytes": 8388608,
        "max_concurrency": 64
      },
      "assistants": {
        "archinfo": {
          "path": "/var/lib/diag-tools/archinfo",
          "sha256": "<64 hex>",
          "args": ["--verbose"],
          "timeout_seconds": 3.0,
          "max_output_bytes": 65536
        }
      }
    }
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass

# 硬性上限：即使配置写错也不允许超过题面约束
HARD_TIMEOUT_SECONDS = 3.0
HARD_MAX_OUTPUT_BYTES = 64 * 1024          # stdout/stderr 合计
HARD_MAX_ASSISTANT_BYTES = 8 * 1024 * 1024  # 单个 ELF 最大 8 MiB
HARD_MAX_CONCURRENCY = 256

DEFAULT_TIMEOUT_SECONDS = 3.0
DEFAULT_MAX_OUTPUT_BYTES = 64 * 1024
DEFAULT_MAX_ASSISTANT_BYTES = 8 * 1024 * 1024
DEFAULT_MAX_CONCURRENCY = 64


class ConfigError(ValueError):
    """可信配置文件内容不合法（部署期错误）。"""


@dataclass(frozen=True)
class AssistantSpec:
    """单个助手的可信启动配置（不可变）。"""

    id: str
    path: str
    sha256: str
    args: tuple[str, ...]
    timeout_seconds: float
    max_output_bytes: int

    @property
    def argv(self) -> list[str]:
        # argv[0] 固定为助手路径，调用方无法注入额外参数
        return [self.path, *self.args]


@dataclass(frozen=True)
class TrustedConfig:
    """整份可信配置（不可变）。"""

    source: str
    max_assistant_bytes: int
    max_concurrency: int
    assistants: dict[str, AssistantSpec]

    def get(self, assistant_id: str) -> AssistantSpec | None:
        return self.assistants.get(assistant_id)


def _is_safe_id(value: str) -> bool:
    return bool(value) and all(ch.isalnum() or ch in "._-" for ch in value)


def _coerce_int(value: object, name: str, hard_max: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"{name} 必须是整数")
    if not 1 <= value <= hard_max:
        raise ConfigError(f"{name} 必须在 1..{hard_max} 之间，收到 {value}")
    return value


def _coerce_float(value: object, name: str, hard_max: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError(f"{name} 必须是数字")
    value = float(value)
    if not 0.0 < value <= hard_max:
        raise ConfigError(f"{name} 必须在 (0, {hard_max}] 之间，收到 {value}")
    return value


def _coerce_sha256(value: object) -> str:
    if not isinstance(value, str):
        raise ConfigError("sha256 必须是十六进制字符串")
    digest = value.strip().lower()
    if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
        raise ConfigError("sha256 必须是 64 位小写十六进制字符")
    return digest


def load_trusted_config(path: str) -> TrustedConfig:
    """加载并严格校验可信配置。

    配置本身来自镜像内只读路径；加载失败属于部署错误，应在服务启动期暴露。
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError(f"无法加载可信配置 {path}: {exc}") from exc

    if not isinstance(raw, dict):
        raise ConfigError("可信配置根节点必须是 JSON 对象")

    defaults = raw.get("defaults", {})
    if defaults is None:
        defaults = {}
    if not isinstance(defaults, dict):
        raise ConfigError("defaults 必须是 JSON 对象")

    timeout = _coerce_float(
        defaults.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS),
        "defaults.timeout_seconds",
        HARD_TIMEOUT_SECONDS,
    )
    max_output = _coerce_int(
        defaults.get("max_output_bytes", DEFAULT_MAX_OUTPUT_BYTES),
        "defaults.max_output_bytes",
        HARD_MAX_OUTPUT_BYTES,
    )
    max_assistant = _coerce_int(
        defaults.get("max_assistant_bytes", DEFAULT_MAX_ASSISTANT_BYTES),
        "defaults.max_assistant_bytes",
        HARD_MAX_ASSISTANT_BYTES,
    )
    max_concurrency = _coerce_int(
        defaults.get("max_concurrency", DEFAULT_MAX_CONCURRENCY),
        "defaults.max_concurrency",
        HARD_MAX_CONCURRENCY,
    )

    raw_assistants = raw.get("assistants")
    if not isinstance(raw_assistants, dict) or not raw_assistants:
        raise ConfigError("assistants 必须是非空 JSON 对象")

    assistants: dict[str, AssistantSpec] = {}
    for assistant_id, item in raw_assistants.items():
        if not isinstance(assistant_id, str) or not _is_safe_id(assistant_id):
            raise ConfigError(f"非法助手 ID: {assistant_id!r}")
        if not isinstance(item, dict):
            raise ConfigError(f"助手 {assistant_id} 的配置必须是 JSON 对象")

        target = item.get("path")
        if not isinstance(target, str) or not target or not os.path.isabs(target):
            raise ConfigError(f"助手 {assistant_id} 的 path 必须是非空绝对路径")
        if os.path.islink(target):
            raise ConfigError(f"助手 {assistant_id} 的 path 不允许是符号链接: {target}")

        digest = _coerce_sha256(item.get("sha256"))

        raw_args = item.get("args", [])
        if not isinstance(raw_args, list) or not all(isinstance(a, str) for a in raw_args):
            raise ConfigError(f"助手 {assistant_id} 的 args 必须是字符串数组")

        spec_timeout = _coerce_float(
            item.get("timeout_seconds", timeout),
            f"助手 {assistant_id}.timeout_seconds",
            HARD_TIMEOUT_SECONDS,
        )
        spec_output = _coerce_int(
            item.get("max_output_bytes", max_output),
            f"助手 {assistant_id}.max_output_bytes",
            HARD_MAX_OUTPUT_BYTES,
        )

        if assistant_id in assistants:  # pragma: no cover - dict 天然去重，防御性
            raise ConfigError(f"助手 ID 重复: {assistant_id}")
        assistants[assistant_id] = AssistantSpec(
            id=assistant_id,
            path=target,
            sha256=digest,
            args=tuple(raw_args),
            timeout_seconds=spec_timeout,
            max_output_bytes=spec_output,
        )

    return TrustedConfig(
        source=os.path.abspath(path),
        max_assistant_bytes=max_assistant,
        max_concurrency=max_concurrency,
        assistants=assistants,
    )


def sha256_file(path: str) -> str:
    """构建期工具：计算文件 SHA-256（小写十六进制）。"""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()
