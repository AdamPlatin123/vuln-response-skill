#!/usr/bin/env bash
# 统一 lint 入口。
#
# playbook 结构校验（原判定语义未改，参数原样透传）:
#   bash bin/lint-playbooks.sh            # 只校验定稿
#   bash bin/lint-playbooks.sh --all      # 含 _draft/（交件前必跑）
#   bash bin/lint-playbooks.sh --strict   # 要求 status=verified
#
# W1 清单表校验（组规 §2/§4/§5 + §8 裁定 R1–R4）:
#   默认复用侦察落盘的 ../vuln-w1/check_inventory.py 作基线门（peer PASS），
#   再叠加他不做的规则：verified 必须挂件（R4）、REMOVE-ONLY 与 verified 共存需挂件（R1 修订）、
#   observe 混入三态（R3）、一手来源/双前缀/front-matter 对账（审计 WARN）。
#
#   bash bin/lint-playbooks.sh --inventory                    # 默认 ../vuln-w1/inventory.tsv
#   bash bin/lint-playbooks.sh --inventory path/to/inv.tsv
#   bash bin/lint-playbooks.sh --inventory --allow-uncovered  # R4 未挂件暂降 WARN（交件前用）
#   bash bin/lint-playbooks.sh --inventory --strict-sync      # front-matter 对账升 FAIL
#   bash bin/lint-playbooks.sh --inventory --no-peer          # 不跑 peer，用内部完整校验（dist 用）
#   bash bin/lint-playbooks.sh --inventory --json
set -euo pipefail
BIN="$(cd "$(dirname "$0")" && pwd)"

if [ "${1:-}" = "--inventory" ]; then
  shift
  exec python3 "$BIN/lint_inventory.py" --inventory "$@"
fi

exec python3 "$BIN/lint_playbooks.py" "$@"
