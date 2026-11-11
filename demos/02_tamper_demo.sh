#!/bin/sh
# 演示 2：篡改可写工具目录后，受控执行 API 一律拒绝（HTTP 409/404）。
#
# 覆盖三种攻击：整体替换为其他程序、截断文件、原地改写单字节。
# 演示结束自动从只读黄金副本 /opt/diag-golden 恢复。
set -eu

TOOLS_DIR="${DIAG_TOOLS_DIR:-/var/lib/diag-tools}"
GOLDEN_DIR="${GOLDEN_DIR:-/opt/diag-golden}"
BASE="${BASE_URL:-http://localhost:8080}"
TARGET="$TOOLS_DIR/archinfo"

run() {
    python3 - "$BASE" <<'PY'
import json, sys, urllib.request, urllib.error
base = sys.argv[1]
req = urllib.request.Request(
    base + "/api/v1/assistants/run",
    data=json.dumps({"assistant_id": "archinfo"}).encode(),
    headers={"Content-Type": "application/json"},
    method="POST",
)
try:
    with urllib.request.urlopen(req, timeout=10) as resp:
        print(f"  HTTP {resp.status}: 放行执行（仅当文件与批准字节一致时才应出现）")
except urllib.error.HTTPError as e:
    detail = json.loads(e.read().decode()).get("detail", "")
    print(f"  HTTP {e.code}: 已拒绝 -> {detail}")
PY
}

restore() {
    cp -f "$GOLDEN_DIR/archinfo" "$TARGET"
    chmod 0755 "$TARGET"
}

trap restore EXIT

echo "== 基线：未篡改时正常执行 =="
run

echo
echo "== 攻击 A：整体替换为另一个程序（forker） =="
if [ -f "$GOLDEN_DIR/forker" ]; then
    cp -f "$GOLDEN_DIR/forker" "$TARGET"
else
    # 同卷的 tamper-demo 容器没有黄金 forker 时，用任意不同 ELF 代替
    cp -f "$GOLDEN_DIR/bigprinter" "$TARGET"
fi
run

echo
echo "== 攻击 B：截断文件（仅保留前 256 字节） =="
restore
head -c 256 "$TARGET" > "$TARGET.tmp" && mv "$TARGET.tmp" "$TARGET"
run

echo
echo "== 攻击 C：原地改写一个非零字节 =="
restore
python3 - "$TARGET" <<'PY'
import sys
path = sys.argv[1]
data = bytearray(open(path, "rb").read())
off = next(i for i in range(64, len(data)) if data[i] not in (0,))
data[off] ^= 0xFF
open(path, "wb").write(data)
print(f"  已改写偏移 {off} 的字节")
PY
run

echo
echo "== 恢复黄金副本后再次执行 =="
restore
run
echo
echo "结论：源文件在读取/核验/启动任一时点被替换、截断或原地改写，"
echo "      都无法通过 memfd 封印字节的 SHA-256 与身份核验，未批准内容不会被执行。"
