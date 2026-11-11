"""受控执行 API 的请求/响应模型（pydantic v2）。

调用方只能提交助手 ID；路径、SHA-256、参数全部由服务端可信配置固定，
请求模型刻意不接受任何路径/参数/环境变量字段。
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


class RunAssistantRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    assistant_id: str = Field(
        description="已批准助手的 ID；仅用于在可信配置中查找固定的路径、SHA-256 与参数",
        min_length=1,
        max_length=128,
    )

    @field_validator("assistant_id")
    @classmethod
    def _safe_id(cls, value: str) -> str:
        value = value.strip()
        if not value or any(not (ch.isalnum() or ch in "._-") for ch in value):
            raise ValueError("assistant_id 只允许字母、数字、点、下划线与连字符")
        return value


class AssistantInfo(BaseModel):
    assistant_id: str
    path: str = Field(description="可信配置固定的源文件绝对路径（可写工具目录）")
    sha256: str = Field(description="批准内容的 SHA-256（小写十六进制）")
    args: list[str] = Field(description="可信配置固定的启动参数")
    timeout_seconds: float
    max_output_bytes: int


class RunAssistantResponse(BaseModel):
    assistant_id: str
    returncode: int = Field(description="助手进程退出码；被信号终止时为负数信号号")
    stdout_b64: str = Field(description="stdout 的 Base64 编码（原始字节，不做拼接/截断）")
    stderr_b64: str = Field(description="stderr 的 Base64 编码（原始字节，不做拼接/截断）")
    sha256: str = Field(description="实际执行的封印字节 SHA-256，应与可信配置一致")
    elapsed_ms: int = Field(description="本次执行耗时（毫秒），始终不超过超时上限")


class ErrorResponse(BaseModel):
    detail: str
    error_code: Optional[str] = None
