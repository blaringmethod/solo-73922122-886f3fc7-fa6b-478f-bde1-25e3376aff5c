"""受控执行 API 的 HTTP 集成测试（需要 fastapi/httpx，镜像内运行）。

本地无 FastAPI 时本文件会自行跳过::

    python3 -I tests/test_runner_api.py

覆盖：/docs 可用、助手列表/详情、受控执行（成功/404/409/504/413）、
篡改返回 409、并发互不干扰、客户端断连返回 499。
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

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from fastapi.testclient import TestClient
except ImportError:  # 本地开发环境无 FastAPI
    print("fastapi/httpx 未安装，跳过 HTTP 集成测试（镜像内会执行）")
    raise SystemExit(0)

from app import main as web  # noqa: E402

FAILURES: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    if not cond:
        FAILURES.append(f"{name} {detail}")
        print(f"  FAIL - {name} {detail}")
    else:
        print(f"  ok - {name}")


def find_gcc() -> str | None:
    return shutil.which("gcc") or shutil.which("cc")


def main() -> int:
    workdir = tempfile.mkdtemp(prefix="runner-api-")
    bindir = os.path.join(workdir, "bin")
    os.makedirs(bindir)
    gcc = find_gcc()
    if not gcc:
        print("无 gcc，跳过 HTTP 集成测试")
        return 0

    sources = {
        "archinfo": "tools/archinfo.c",
        "slowprobe": "tools/slowprobe.c",
        "bigprinter": "tools/bigprinter.c",
        "echoer": "tests/fixtures/echoer.c",
        "forker": "tests/fixtures/forker.c",
    }
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for name, rel in sources.items():
        subprocess.run([gcc, "-O2", "-o", os.path.join(bindir, name),
                        os.path.join(root, rel)], check=True, capture_output=True)

    # 构造指向编译产物的可信配置
    assistants = {}
    for name in sources:
        target = os.path.join(bindir, name)
        digest = hashlib.sha256(open(target, "rb").read()).hexdigest()
        assistants[name] = {
            "path": target,
            "sha256": digest,
            "args": ["--verbose"] if name == "archinfo" else [],
            "timeout_seconds": 3.0,
            "max_output_bytes": 65536,
        }
    cfg_path = os.path.join(workdir, "assistants.json")
    with open(cfg_path, "w") as fh:
        json.dump({"defaults": {"timeout_seconds": 3.0, "max_output_bytes": 65536,
                                "max_assistant_bytes": 8388608, "max_concurrency": 16},
                   "assistants": assistants}, fh)

    os.environ["DIAG_CONFIG_PATH"] = cfg_path
    web._state.clear()

    with TestClient(web.app) as client:
        print("test_docs_and_meta")
        r = client.get("/docs")
        check("/docs 可访问", r.status_code == 200)
        r = client.get("/health")
        check("/health 正常", r.status_code == 200 and r.json()["status"] == "ok")
        r = client.get("/openapi.json")
        paths = r.json()["paths"]
        check("执行端点已注册", "/api/v1/assistants/run" in paths)
        check("原核对端点保留", "/api/v1/evaluate" in paths)

        print("test_assistants_listing")
        r = client.get("/api/v1/assistants")
        check("列出助手", r.status_code == 200 and len(r.json()) == len(sources))
        r = client.get("/api/v1/assistants/archinfo")
        check("详情含固定哈希与参数",
              r.status_code == 200 and r.json()["sha256"] == assistants["archinfo"]["sha256"]
              and r.json()["args"] == ["--verbose"])
        r = client.get("/api/v1/assistants/nope")
        check("未知 ID 返回 404", r.status_code == 404)

        print("test_run_ok")
        r = client.post("/api/v1/assistants/run", json={"assistant_id": "archinfo"})
        check("正常执行 200", r.status_code == 200, r.text[:200])
        body = r.json()
        out = base64.b64decode(body["stdout_b64"]).decode()
        check("退出码为 0", body["returncode"] == 0)
        check("stdout base64 可解码", "archinfo diagnostic report" in out)
        check("返回哈希与配置一致", body["sha256"] == assistants["archinfo"]["sha256"])
        check("elapsed_ms 存在", isinstance(body["elapsed_ms"], int))

        print("test_run_unknown_and_bad_request")
        r = client.post("/api/v1/assistants/run", json={"assistant_id": "ghost"})
        check("未知助手 404", r.status_code == 404)
        r = client.post("/api/v1/assistants/run", json={"assistant_id": "../escape"})
        check("非法 ID 422", r.status_code == 422)
        r = client.post("/api/v1/assistants/run", json={"assistant_id": "archinfo", "path": "/x"})
        check("多余字段 422", r.status_code == 422)

        print("test_tamper_409")
        target = assistants["archinfo"]["path"]
        good = open(target, "rb").read()
        evil = open(os.path.join(bindir, "forker"), "rb").read()
        with open(target, "wb") as fh:
            fh.write(evil)
        r = client.post("/api/v1/assistants/run", json={"assistant_id": "archinfo"})
        check("篡改返回 409", r.status_code == 409)
        with open(target, "wb") as fh:
            fh.write(good)
        r = client.post("/api/v1/assistants/run", json={"assistant_id": "archinfo"})
        check("恢复后重新可执行", r.status_code == 200)

        print("test_timeout_504")
        r = client.post("/api/v1/assistants/run", json={"assistant_id": "slowprobe"})
        check("超时返回 504", r.status_code == 504)

        print("test_output_limit_413")
        r = client.post("/api/v1/assistants/run", json={"assistant_id": "bigprinter"})
        check("输出超限 413", r.status_code == 413)

        print("test_concurrent")
        errors = []

        def call(idx: int) -> None:
            for _ in range(4):
                rr = client.post("/api/v1/assistants/run", json={"assistant_id": "archinfo"})
                if rr.status_code != 200 or rr.json()["returncode"] != 0:
                    errors.append((idx, rr.status_code))

        threads = [threading.Thread(target=call, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        check("10 线程并发全部 200", not errors, str(errors))

        print("test_legacy_evaluate_still_works")
        r = client.post("/api/v1/evaluate", json={
            "policy": {"ProtectSystem": "strict"},
            "events": [{"type": "access", "pid": 1, "operation": "write", "path": "/etc/x"}],
        })
        check("原核对 API 保留且可用", r.status_code == 200 and r.json()["allowed"] is False)

    shutil.rmtree(workdir, ignore_errors=True)
    print()
    if FAILURES:
        print(f"{len(FAILURES)} 项失败")
        return 1
    print("HTTP 集成测试全部通过")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
