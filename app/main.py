"""FastAPI 应用：systemd 沙箱策略离线核查 + 受控诊断助手执行。

所有计算均在本地完成，不发起任何外部网络请求，适合离线维护终端部署。
"""

from __future__ import annotations

import asyncio
import os
import threading
from concurrent.futures import ThreadPoolExecutor

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import RedirectResponse

from . import __version__
from .engine import PolicyError, evaluate
from .schemas import EvaluateRequest, EvaluateResponse
from .runner import (
    AssistantError,
    ClientDisconnected,
    OutputLimitExceeded,
    TimeoutExceeded,
    TrustedConfig,
    load_trusted_config,
    run_assistant,
)
from .runner.config import ConfigError
from .runner_schemas import (
    AssistantInfo,
    RunAssistantRequest,
    RunAssistantResponse,
)

# 可信配置路径：镜像内只读文件，部署方可通过环境变量覆盖
DEFAULT_CONFIG_PATH = "/etc/diag-runner/assistants.json"

app = FastAPI(
    title="systemd 沙箱策略核查与受控诊断执行 API",
    version=__version__,
    description=(
        "离线核对 systemd 沙箱指令（ProtectSystem / ProtectHome / ReadWritePaths / "
        "InaccessiblePaths / PrivateTmp）是否会阻断守护进程的真实文件操作；并提供"
        "受控诊断助手执行 API：调用方只传助手 ID，服务端按可信配置固定的路径、"
        "SHA-256 与参数，对 memfd 封印后的不可变字节核验后执行，超时/输出超限/"
        "客户端断连即终止回收。"
    ),
)

# 可信配置与并发闸门（惰性加载，容器内配置缺失属于部署错误）
_state: dict[str, object] = {}


def _get_config() -> TrustedConfig:
    cfg = _state.get("config")
    if cfg is None:
        path = os.environ.get("DIAG_CONFIG_PATH", DEFAULT_CONFIG_PATH)
        try:
            cfg = load_trusted_config(path)
        except ConfigError as exc:
            raise HTTPException(status_code=503, detail=f"可信配置不可用: {exc}") from exc
        _state["config"] = cfg
        _state["semaphore"] = threading.BoundedSemaphore(cfg.max_concurrency)
        # 专用线程池：同步执行器在此运行，阻塞不影响事件循环与 /docs
        _state["pool"] = ThreadPoolExecutor(
            max_workers=cfg.max_concurrency, thread_name_prefix="diag-run"
        )
    return cfg  # type: ignore[return-value]


def _get_semaphore(cfg: TrustedConfig) -> threading.BoundedSemaphore:
    sem = _state.get("semaphore")
    if sem is None:  # pragma: no cover - 与 _get_config 同时初始化
        sem = threading.BoundedSemaphore(cfg.max_concurrency)
        _state["semaphore"] = sem
    return sem  # type: ignore[return-value]


@app.get("/", include_in_schema=False)
def root() -> RedirectResponse:
    return RedirectResponse(url="/docs")


@app.get("/health", tags=["meta"], summary="健康检查")
def health() -> dict:
    return {"status": "ok", "service": "systemd-sandbox-checker", "version": __version__}


@app.post(
    "/api/v1/evaluate",
    response_model=EvaluateResponse,
    tags=["evaluate"],
    summary="回放审计事件并核对沙箱策略",
    responses={
        422: {"description": "策略或事件字段不合法（含相对路径出现在策略中等）"},
    },
)
def evaluate_events(req: EvaluateRequest) -> EvaluateResponse:
    """按进程继承与路径规范化逐步判定；拒绝路径优先于可写路径。"""
    try:
        result = evaluate(
            req.policy.model_dump(by_alias=False, exclude_none=False),
            [e.to_engine() for e in req.events],
        )
    except PolicyError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return EvaluateResponse(**result)


# --------------------------------------------------------------------------- #
# 受控诊断助手执行 API
# --------------------------------------------------------------------------- #
@app.get(
    "/api/v1/assistants",
    response_model=list[AssistantInfo],
    tags=["diagnostics"],
    summary="列出可信配置中已批准的诊断助手",
)
def list_assistants() -> list[AssistantInfo]:
    cfg = _get_config()
    return [
        AssistantInfo(
            assistant_id=spec.id,
            path=spec.path,
            sha256=spec.sha256,
            args=list(spec.args),
            timeout_seconds=spec.timeout_seconds,
            max_output_bytes=spec.max_output_bytes,
        )
        for spec in cfg.assistants.values()
    ]


@app.get(
    "/api/v1/assistants/{assistant_id}",
    response_model=AssistantInfo,
    tags=["diagnostics"],
    summary="查询单个已批准助手的可信启动配置",
    responses={404: {"description": "助手 ID 未在可信配置中登记"}},
)
def get_assistant(assistant_id: str) -> AssistantInfo:
    cfg = _get_config()
    spec = cfg.get(assistant_id)
    if spec is None:
        raise HTTPException(status_code=404, detail=f"未登记的助手 ID: {assistant_id}")
    return AssistantInfo(
        assistant_id=spec.id,
        path=spec.path,
        sha256=spec.sha256,
        args=list(spec.args),
        timeout_seconds=spec.timeout_seconds,
        max_output_bytes=spec.max_output_bytes,
    )


async def _wait_disconnect(request: Request) -> bool:
    while True:
        if await request.is_disconnected():
            return True
        await asyncio.sleep(0.05)


@app.post(
    "/api/v1/assistants/run",
    response_model=RunAssistantResponse,
    tags=["diagnostics"],
    summary="按助手 ID 受控执行已批准的诊断助手",
    responses={
        404: {"description": "助手 ID 未登记"},
        409: {"description": "核验失败（SHA-256/ELF/源文件异常），拒绝执行"},
        413: {"description": "stdout/stderr 合计超过 64 KiB，进程已回收，无部分结果"},
        422: {"description": "请求字段不合法"},
        499: {"description": "客户端断连，进程已回收，不返回部分结果"},
        503: {"description": "并发数达上限或可信配置不可用"},
        504: {"description": "运行超过 3 秒，进程已回收，无部分结果"},
    },
)
async def run_assistant_endpoint(
    req: RunAssistantRequest, request: Request
) -> RunAssistantResponse:
    cfg = _get_config()
    spec = cfg.get(req.assistant_id)
    if spec is None:
        raise HTTPException(status_code=404, detail=f"未登记的助手 ID: {req.assistant_id}")

    sem = _get_semaphore(cfg)
    if not sem.acquire(blocking=False):
        raise HTTPException(status_code=503, detail="并发执行数已达上限，请稍后重试")

    cancel_event = threading.Event()
    try:
        loop = asyncio.get_running_loop()
        pool: ThreadPoolExecutor = _state["pool"]  # type: ignore[assignment]
        runner_task = loop.run_in_executor(
            pool, lambda: run_assistant(spec, cfg, cancel_event=cancel_event)
        )
        disconnect_task = asyncio.ensure_future(_wait_disconnect(request))

        done, pending = await asyncio.wait(
            {runner_task, disconnect_task}, return_when=asyncio.FIRST_COMPLETED
        )

        if disconnect_task in done and runner_task not in done:
            # 客户端断连：通知执行器杀掉并回收进程组，不返回部分结果
            cancel_event.set()
            try:
                await asyncio.wait_for(runner_task, timeout=2.0)
            except (asyncio.TimeoutError, Exception):  # noqa: BLE001
                pass
            raise HTTPException(
                status_code=499,
                detail="客户端断连，本次进程及资源已终止回收，不返回部分结果",
            )

        disconnect_task.cancel()
        try:
            result = await runner_task
        except TimeoutExceeded as exc:
            raise HTTPException(status_code=504, detail=str(exc)) from exc
        except OutputLimitExceeded as exc:
            raise HTTPException(status_code=413, detail=str(exc)) from exc
        except ClientDisconnected as exc:  # pragma: no cover - 与上方分支等价的兜底
            raise HTTPException(status_code=499, detail=str(exc)) from exc
        except AssistantError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

        return RunAssistantResponse(
            assistant_id=spec.id,
            returncode=result.returncode,
            stdout_b64=result.stdout_b64,
            stderr_b64=result.stderr_b64,
            sha256=result.sha256,
            elapsed_ms=result.elapsed_ms,
        )
    finally:
        sem.release()
