#!/usr/bin/env bash
# 从 00-TEMPLATE.md 起一份草稿。
#   bash bin/new-playbook.sh 01 node-security-release
#   → playbooks/_draft/01-node-security-release.md
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TPL="$ROOT/playbooks/00-TEMPLATE.md"

if [ "$#" -ne 2 ]; then
  echo "用法: $0 <NN> <ecosystem-slug>" >&2
  echo "例:   $0 01 node-security-release" >&2
  exit 2
fi

NN="$1"
SLUG="$2"

if ! [[ "$NN" =~ ^[0-9]{2}$ ]]; then
  echo "NN 必须是两位数字（01、02 …）" >&2
  exit 2
fi
if ! [[ "$SLUG" =~ ^[a-z0-9]+(-[a-z0-9]+)*$ ]]; then
  echo "slug 只能用小写字母/数字/连字符" >&2
  exit 2
fi
if [ ! -f "$TPL" ]; then
  echo "模板不存在: $TPL" >&2
  exit 1
fi

case "$SLUG" in
  node-*|nodejs-*)                          ECO=node ;;
  npm-*|mal-*)                              ECO=npm ;;
  go-*|govuln*)                             ECO=go ;;
  python-llm-*|litellm-*|vllm-*|ollama-*)   ECO=python-llm ;;
  python-*|pip-*|py-*)                      ECO=python ;;
  *)                                        ECO=generic ;;
esac

OUT="$ROOT/playbooks/_draft/${NN}-${SLUG}.md"
if [ -e "$OUT" ]; then
  echo "已存在: $OUT" >&2
  exit 1
fi
mkdir -p "$(dirname "$OUT")"

python3 - "$TPL" "$OUT" "$NN" "$SLUG" "$ECO" <<'PY'
import re, sys
from datetime import date
tpl, out, nn, slug, eco = sys.argv[1:6]
text = open(tpl, encoding="utf-8").read()
text = re.sub(r'^id: "NN"$', f'id: "{nn}"', text, count=1, flags=re.M)
text = re.sub(r'^title: .*$', f'title: {slug}', text, count=1, flags=re.M)
text = re.sub(r'^ecosystem: .*$', f'ecosystem: {eco}', text, count=1, flags=re.M)
text = re.sub(r'^updated: .*$', f'updated: {date.today().isoformat()}', text, count=1, flags=re.M)
open(out, "w", encoding="utf-8").write(text)
PY

echo "已创建: $OUT"
echo "下一步: 填 frontmatter → 写六段 → bash bin/lint-playbooks.sh --all"
