#!/bin/sh
# 容器入口：把只读黄金副本初始化到可写工具目录，并确保权限允许维护侧写入。
#
# 可写目录是演示“换入其他程序”攻击面所必需的：服务从不信任该目录的内容
# 本身，只信任 /etc/diag-runner/assistants.json 中固定的 SHA-256，执行前
# 还会把字节封印进 memfd 并全量核验。
set -eu

TOOLS_DIR="${DIAG_TOOLS_DIR:-/var/lib/diag-tools}"
GOLDEN_DIR="${GOLDEN_DIR:-/opt/diag-golden}"

mkdir -p "$TOOLS_DIR"

if [ ! -d "$GOLDEN_DIR" ]; then
    echo "entrypoint: 黄金副本目录 $GOLDEN_DIR 不存在，拒绝启动" >&2
    exit 1
fi

for golden in "$GOLDEN_DIR"/*; do
    [ -f "$golden" ] || continue
    name="$(basename "$golden")"
    target="$TOOLS_DIR/$name"
    # 仅在目标缺失或与黄金副本不一致时初始化，避免覆盖演示中的篡改现场
    if [ ! -f "$target" ] || ! cmp -s "$golden" "$target"; then
        cp -f "$golden" "$target"
    fi
    chmod 0755 "$target"
done

# 让非 root 服务用户与同卷的演示容器都能写入该目录（演示攻击面）
chmod 0777 "$TOOLS_DIR" 2>/dev/null || true

exec uvicorn app.main:app --host 0.0.0.0 --port 8080
