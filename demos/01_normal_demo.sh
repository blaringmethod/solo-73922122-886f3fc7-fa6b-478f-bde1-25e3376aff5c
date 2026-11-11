#!/bin/sh
# 演示 1：正常调用已批准的诊断助手 archinfo。
# 调用方只传助手 ID；路径、SHA-256、参数全部来自服务端可信配置。
set -eu

BASE="${BASE_URL:-http://localhost:8080}"

echo "== 已登记的助手（可信配置固定 ID/路径/SHA-256/参数） =="
python3 - "$BASE" <<'PY'
import json, sys, urllib.request
base = sys.argv[1]
with urllib.request.urlopen(base + "/api/v1/assistants") as resp:
    for item in json.load(resp):
        print(f"  - {item['assistant_id']:<10} {item['path']}  sha256={item['sha256'][:16]}...  args={item['args']}")
PY

echo
echo "== POST /api/v1/assistants/run {\"assistant_id\": \"archinfo\"} =="
python3 - "$BASE" <<'PY'
import base64, json, sys, urllib.request
base = sys.argv[1]
req = urllib.request.Request(
    base + "/api/v1/assistants/run",
    data=json.dumps({"assistant_id": "archinfo"}).encode(),
    headers={"Content-Type": "application/json"},
    method="POST",
)
with urllib.request.urlopen(req, timeout=10) as resp:
    body = json.load(resp)
print(f"returncode : {body['returncode']}")
print(f"sha256     : {body['sha256']}")
print(f"elapsed_ms : {body['elapsed_ms']}")
print("--- stdout (Base64 解码后) ---")
sys.stdout.write(base64.b64decode(body["stdout_b64"]).decode(errors="replace"))
if body["stderr_b64"]:
    print("--- stderr (Base64 解码后) ---")
    sys.stdout.write(base64.b64decode(body["stderr_b64"]).decode(errors="replace"))
PY
