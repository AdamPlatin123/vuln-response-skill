#!/usr/bin/env bash
# playbook 结构校验。参数透传给 lint_playbooks.py。
#   bash bin/lint-playbooks.sh            # 只校验定稿
#   bash bin/lint-playbooks.sh --all      # 含 _draft/（交件前必跑）
#   bash bin/lint-playbooks.sh --strict   # 要求 status=verified
set -euo pipefail
exec python3 "$(cd "$(dirname "$0")" && pwd)/lint_playbooks.py" "$@"
