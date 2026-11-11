#!/bin/sh
# 一键运行全部演示：正常调用 -> 篡改拒绝 -> 并发替换 -> 资源上限。
# 用法（项目根目录）：docker compose up --build -d 后执行本脚本。
set -eu

BASE="${BASE_URL:-http://localhost:8080}"
export BASE_URL="$BASE"

dir="$(dirname "$0")"

echo "############ 演示 1/4：正常助手调用 ############"
sh "$dir/01_normal_demo.sh"
echo
echo "############ 演示 2/4：篡改与原地改写拒绝 ############"
sh "$dir/02_tamper_demo.sh"
echo
echo "############ 演示 3/4：并发替换攻击 ############"
python3 -I "$dir/03_concurrent_replace_demo.py"
echo
echo "############ 演示 4/4：超时与输出上限 ############"
sh "$dir/04_limits_demo.sh"
