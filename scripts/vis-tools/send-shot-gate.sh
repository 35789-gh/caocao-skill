#!/bin/bash
# send-shot-gate.sh — 单发→等→窗口截屏→vision_gate 一体（㊳㊴㊵ 配套）
# 用法: ./send-shot-gate.sh <命令txt> <输出png> <claim> [kind]
# 环境变量:
#   WAIT=<秒>      等命令执行完的时长（默认 4）
#   TITLE=<窗口名>  cmd 窗口 title（默认 CMDPHOTO；B 批用 CMDPHOTO-B）
#   OWNER=<批名>   给了就自动拿锁/释放（snapwin 拍前最大化，两会话必互盖→必须锁）；不给则跳锁
set -o pipefail  # 批六十一⑨（r38 B-6）：snapwin 失败被 `| tail -1` 管道吞成 exit 0——错误照传
command -v py >/dev/null 2>&1 && PY_CMD="py -3" || PY_CMD="python3"
CMD="$1"; PNG="$2"; CLAIM="$3"; KIND="${4:-cmd}"
TITLE="${TITLE:-CMDPHOTO}"
DIR="$(cd "$(dirname "$0")" && pwd)"
VG="$DIR/../vision_gate.py"
OWNER_ARGS=()
[ -n "$OWNER" ] && OWNER_ARGS=(-Owner "$OWNER")
cd "$DIR"

if [ -n "$OWNER" ]; then
  $PY_CMD -X utf8 shotlock.py acquire --owner "$OWNER" --wait 900 >/dev/null || { echo "LOCK-TIMEOUT"; exit 3; }
fi
cleanup() { [ -n "$OWNER" ] && $PY_CMD -X utf8 shotlock.py release --owner "$OWNER" >/dev/null; }
trap cleanup EXIT

powershell -NoProfile -ExecutionPolicy Bypass ./cmdsend-any.ps1 "$(cygpath -w "$DIR/ccls.txt")" -Title "$TITLE" "${OWNER_ARGS[@]}" >/dev/null 2>&1 || { echo "CMDSEND-FAIL ccls"; exit 4; }
sleep 1
# 批六十一⑪（r38 G-08，RF-CMD-01 cwd 锚定）：发业务命令前先发 `cd` 让当前目录回显入画
# ——提示符+工作目录同框，下游（vision_gate cmd 判据/人工）可核命令跑在对的目录
printf 'cd\r\n' > "$DIR/.cwd-probe.txt"
powershell -NoProfile -ExecutionPolicy Bypass ./cmdsend-any.ps1 "$(cygpath -w "$DIR/.cwd-probe.txt")" -Title "$TITLE" "${OWNER_ARGS[@]}" >/dev/null 2>&1 || { echo "CMDSEND-FAIL cwd-probe"; exit 4; }
sleep 1
powershell -NoProfile -ExecutionPolicy Bypass ./cmdsend-any.ps1 "$(cygpath -w "$CMD")" -Title "$TITLE" "${OWNER_ARGS[@]}" >/dev/null 2>&1 || { echo "CMDSEND-FAIL cmd"; exit 4; }
sleep "${WAIT:-4}"
# 批六十一⑨：snapwin 失败（exit≠0）不再被 tail 吞掉——截图失败直接 exit 5，不拿旧图过闸
powershell -NoProfile -ExecutionPolicy Bypass ./snapwin.ps1 "$(cygpath -w "$PNG")" -Title "$TITLE" | tail -1 || { echo "SNAPWIN-FAIL"; exit 5; }
[ -s "$PNG" ] || { echo "SNAPWIN-EMPTY-PNG"; exit 5; }
$PY_CMD -X utf8 "$VG" --image "$PNG" --kind "$KIND" --claim "$CLAIM" --out "${PNG%.png}.review.md"
