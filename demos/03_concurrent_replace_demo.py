#!/usr/bin/env python3
"""演示 3：并发替换攻击下，受控执行 API 绝不执行未批准内容。

一个后台线程持续用 rename 原子替换可写工具目录中的 archinfo（在批准版本
与另一个程序之间来回切换），主线程并发发起大量受控执行请求。统计：

* success  —— 请求成功，且返回的 sha256 必须是批准哈希、退出码为 0；
* rejected —— 核验未通过被服务端拒绝（409）。

任何“成功但哈希不符”都视为失守。纯标准库实现。
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request

BASE = os.environ.get("BASE_URL", "http://localhost:8080")
TOOLS_DIR = os.environ.get("DIAG_TOOLS_DIR", "/var/lib/diag-tools")
GOLDEN_DIR = os.environ.get("GOLDEN_DIR", "/opt/diag-golden")
TARGET = os.path.join(TOOLS_DIR, "archinfo")
EVIL = os.path.join(GOLDEN_DIR, "forker")
GOOD = os.path.join(GOLDEN_DIR, "archinfo")
REQUESTS = int(os.environ.get("DEMO_REQUESTS", "40"))
SWAP_INTERVAL = 0.0005


def expected_sha256() -> str:
    with urllib.request.urlopen(BASE + "/api/v1/assistants/archinfo") as resp:
        return json.load(resp)["sha256"]


def call_once() -> tuple[int, dict | None]:
    req = urllib.request.Request(
        BASE + "/api/v1/assistants/run",
        data=json.dumps({"assistant_id": "archinfo"}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.load(resp)
    except urllib.error.HTTPError as exc:
        return exc.code, None


def main() -> int:
    approved = expected_sha256()
    print(f"批准哈希: {approved}")
    print(f"目标文件: {TARGET}")
    print(f"并发 {REQUESTS} 次请求，后台持续 rename 替换 ...\n")

    stop = threading.Event()

    def swapper() -> None:
        while not stop.is_set():
            try:
                current = os.path.getsize(TARGET)
                source = EVIL if current == os.path.getsize(GOOD) else GOOD
                tmp = TARGET + ".swap"
                with open(source, "rb") as src, open(tmp, "wb") as dst:
                    dst.write(src.read())
                os.chmod(tmp, 0o755)
                os.replace(tmp, TARGET)
            except FileNotFoundError:
                pass
            time.sleep(SWAP_INTERVAL)

    t = threading.Thread(target=swapper, daemon=True)
    t.start()

    success = rejected = breached = 0
    try:
        for i in range(REQUESTS):
            status, body = call_once()
            if status == 200 and body is not None:
                if body["sha256"] == approved and body["returncode"] == 0:
                    success += 1
                    print(f"  #{i+1:02d} 200 执行的是批准字节 sha256 匹配")
                else:
                    breached += 1
                    print(f"  #{i+1:02d} 200 但哈希/退出码异常！失守: {body}")
            elif status == 409:
                rejected += 1
                print(f"  #{i+1:02d} 409 核验失败，拒绝执行未批准内容")
            else:
                breached += 1
                print(f"  #{i+1:02d} 意外状态码 {status}")
    finally:
        stop.set()
        t.join()
        # 恢复黄金副本
        with open(GOOD, "rb") as src, open(TARGET, "wb") as dst:
            dst.write(src.read())
        os.chmod(TARGET, 0o755)

    print(f"\n成功(批准字节)={success}  拒绝(409)={rejected}  失守={breached}")
    if breached:
        print("结论：存在未批准内容被执行，安全约束被破坏！")
        return 1
    print("结论：并发替换下，服务端要么执行核验通过的同一份不可变字节，")
    print("      要么直接拒绝；未批准程序从未被执行。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
