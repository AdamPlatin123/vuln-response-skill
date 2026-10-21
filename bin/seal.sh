#!/usr/bin/env bash
# 封版：生成 MANIFEST.sha256（不含自身），并打印树与摘要。
#   bash bin/seal.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

find . -type f ! -name MANIFEST.sha256 ! -path './.git/*' -print0 \
  | sort -z \
  | xargs -0 sha256sum > MANIFEST.sha256

echo "== 文件树 =="
find . -type f ! -path './.git/*' | sort | sed 's|^\./||'
echo
echo "== 计数 =="
FILE_N=$(wc -l < MANIFEST.sha256)
LINE_N=$(find . -type f ! -name MANIFEST.sha256 ! -path './.git/*' -print0 \
  | xargs -0 wc -l | tail -1 | awk '{print $1}')
printf '文件 %s 个，共 %s 行\n' "$FILE_N" "$LINE_N"
echo
echo "== MANIFEST =="
cat MANIFEST.sha256
echo
echo "MANIFEST 自身 sha256: $(sha256sum MANIFEST.sha256 | cut -d' ' -f1)"
