#!/bin/sh
# 演示 4：资源治理 —— 3 秒超时（504）与 64 KiB 输出上限（413）。
# 两种越限都终止并回收整个进程组，不返回任何部分结果。
set -eu

BASE="${BASE_URL:-http://localhost:8080}"

call() {
    python3 - "$BASE" "$1" <<'PY'
import json, sys, urllib.request, urllib.error, time
base, assistant = sys.argv[1], sys.argv[2]
req = urllib.request.Request(
    base + "/api/v1/assistants/run",
    data=json.dumps({"assistant_id": assistant}).encode(),
    headers={"Content-Type": "application/json"},
    method="POST",
)
t0 = time.monotonic()
try:
    with urllib.request.urlopen(req, timeout=10) as resp:
        print(f"  HTTP {resp.status}: 放行执行")
except urllib.error.HTTPError as e:
    elapsed = time.monotonic() - t0
    detail = json.loads(e.read().decode()).get("detail", "")
    print(f"  HTTP {e.code} 用时 {elapsed:.2f}s -> {detail}")
PY
}

echo "== slowprobe：运行 5 秒，应在 3 秒时被终止并回收（504，无部分结果） =="
call slowprobe

echo
echo "== bigprinter：输出 128 KiB，超过 64 KiB 合计上限即终止回收（413，无部分结果） =="
call bigprinter

echo
echo "== 正常助手 archinfo 不受影响 =="
call archinfo
