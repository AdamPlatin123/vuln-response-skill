#!/usr/bin/env python3
"""playbook 结构校验器。

用法:
  bash bin/lint-playbooks.sh            # 只校验定稿 playbooks/*.md
  bash bin/lint-playbooks.sh --all      # 连 playbooks/_draft/ 一起校验（交件前必跑）
  bash bin/lint-playbooks.sh --strict   # 额外要求 status=verified 才算过

exit 0 = 通过；exit 1 = 有错。
"""
from __future__ import annotations

import re
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PB = ROOT / "playbooks"
DRAFT = PB / "_draft"
SOURCES = ROOT / "sources.md"

REQ_FM = ["id", "title", "ecosystem", "affects", "fixed", "severity", "status", "sources", "updated"]
REQ_SEC = ["适用版本区间", "检测", "影响判定", "修复", "验证", "回退"]
CODE_SEC = ["检测", "修复", "验证"]
ECOS = {"node", "npm", "go", "python", "python-llm", "php", "pki", "generic"}
STATUS = {"draft", "verified"}
PLACEHOLDERS = ["TODO", "TBD", "XXX", "待填", "待补写"]
# updated 校验白名单：模板与文档不是「件」
UPDATED_WHITELIST = {"00-TEMPLATE.md", "README.md"}
NAME_RE = re.compile(r"^(\d{2})-[a-z0-9]+(?:-[a-z0-9]+)*\.md$")
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")
URL_RE = re.compile(r"https?://\S+")


def strip_comment(value: str) -> str:
    """去掉值尾部的行内注释（不在引号内的 #）。"""
    quote = ""
    out = []
    for i, ch in enumerate(value):
        if quote:
            if ch == quote:
                quote = ""
        elif ch in "\"'":
            quote = ch
        elif ch == "#" and (i == 0 or value[i - 1].isspace()):
            break
        out.append(ch)
    return "".join(out).strip()


def parse_frontmatter(text: str) -> dict[str, str] | None:
    if not text.startswith("---"):
        return None
    end = text.find("\n---", 3)
    if end < 0:
        return None
    fm: dict[str, str] = {}
    for line in text[3:end].splitlines():
        if not line.strip() or line.lstrip().startswith("#") or line.startswith((" ", "\t")):
            continue
        m = re.match(r"^([a-z_]+):\s*(.*)$", line)
        if m:
            fm[m.group(1)] = strip_comment(m.group(2)).strip('"').strip("'")
    return fm


def parse_sections(text: str) -> tuple[list[str], dict[str, str]]:
    order: list[str] = []
    body: dict[str, list[str]] = {}
    cur: str | None = None
    for line in text.splitlines():
        if line.startswith("## "):
            cur = line[3:].strip()
            order.append(cur)
            body[cur] = []
        elif cur is not None:
            body[cur].append(line)
    return order, {k: "\n".join(v) for k, v in body.items()}


def check_file(path: Path, strict: bool) -> tuple[list[str], set[str]]:
    errs: list[str] = []
    text = path.read_text(encoding="utf-8")
    m = NAME_RE.match(path.name)
    if not m:
        errs.append("文件名不合规，应为 NN-<ecosystem>-<slug>.md")
        nn = None
    else:
        nn = m.group(1)

    fm = parse_frontmatter(text)
    if fm is None:
        errs.append("缺 YAML frontmatter（文件必须以 --- 开头，且有收尾 ---）")
        fm = {}
    for k in REQ_FM:
        if not fm.get(k):
            errs.append(f"frontmatter 缺字段或为空: {k}")

    # updated: 必须 ≥ 本件最后实质修改日（mtime），且不得是未来日期
    if path.name not in UPDATED_WHITELIST:
        upd = fm.get("updated", "")
        if upd:
            try:
                upd_d = date.fromisoformat(upd)
            except ValueError:
                errs.append(f"updated={upd!r} 不是 YYYY-MM-DD")
                upd_d = None
            if upd_d:
                today = date.today()
                if upd_d > today:
                    errs.append(f"updated={upd} 是未来日期（今天 {today.isoformat()}）")
                mt = date.fromtimestamp(path.stat().st_mtime)
                if mt > upd_d:
                    errs.append(
                        f"updated={upd} 早于本件最后修改日 {mt.isoformat()}（改了件没更新 updated）"
                    )

    fid = fm.get("id", "")
    if nn and fid and fid != nn:
        errs.append(f"id={fid} 与文件名前缀 {nn} 不一致")
    eco = fm.get("ecosystem", "")
    if eco and eco not in ECOS:
        errs.append(f"ecosystem={eco} 不在 {sorted(ECOS)}")
    st = fm.get("status", "")
    if st and st not in STATUS:
        errs.append(f"status={st} 不在 {sorted(STATUS)}")
    if strict and st != "verified":
        errs.append("status 不是 verified，不能作为定稿")
    src = fm.get("sources", "")
    if src and not URL_RE.search(src):
        errs.append("frontmatter sources 里没有 http(s) URL（至少一条一手来源）")

    order, secs = parse_sections(text)
    for s in REQ_SEC:
        if s not in secs:
            errs.append(f"缺二级标题: ## {s}")
    present = [s for s in order if s in REQ_SEC]
    if present != [s for s in REQ_SEC if s in secs]:
        errs.append(f"六段顺序不对，应为 {' → '.join(REQ_SEC)}，实际 {' → '.join(present)}")

    for s in CODE_SEC:
        if s in secs and "```" not in secs[s]:
            errs.append(f"「{s}」段缺命令块（``` fenced code）")

    for ph in PLACEHOLDERS:
        if ph in text:
            errs.append(f"有未清占位符: {ph}")

    cves = set(CVE_RE.findall(text))
    return errs, cves


def main(argv: list[str]) -> int:
    include_drafts = "--all" in argv
    strict = "--strict" in argv
    unknown = [a for a in argv if a not in {"--all", "--strict"}]
    if unknown:
        print(f"未知参数: {unknown}", file=sys.stderr)
        return 2

    final = sorted(p for p in PB.glob("*.md") if NAME_RE.match(p.name))
    drafts = sorted(p for p in DRAFT.glob("*.md") if NAME_RE.match(p.name)) if DRAFT.exists() else []
    files = final + (drafts if include_drafts else [])

    src_cves = set(CVE_RE.findall(SOURCES.read_text(encoding="utf-8"))) if SOURCES.exists() else set()
    cve_owner: dict[str, list[str]] = {}
    failures = 0

    print("== playbook 校验 ==")
    if not files:
        print("  （还没有 playbook，只有模板；结构检查跳过）")
    for p in files:
        errs, cves = check_file(p, strict)
        rel = p.relative_to(ROOT)
        if errs:
            failures += 1
            print(f"FAIL  {rel}")
            for e in errs:
                print(f"      - {e}")
        else:
            print(f"ok    {rel}")
        for c in cves:
            cve_owner.setdefault(c, []).append(str(rel))
            if c not in src_cves:
                failures += 1
                print(f"      - {c} 未收录进 sources.md")

    for c, owners in sorted(cve_owner.items()):
        if len(owners) > 1:
            print(f"WARN  {c} 同时出现在多份 playbook: {owners}（归并规则见 index.md 第 4 节）")

    nn_owner: dict[str, str] = {}
    for p in final + drafts:
        nn = p.name[:2]
        if nn in nn_owner:
            failures += 1
            print(f"FAIL  编号 {nn} 重复: {nn_owner[nn]} / {p.name}")
        nn_owner[nn] = p.name

    print(f"== 汇总 ==  文件 {len(files)} 个，失败 {failures} 项；sources.md 收录 CVE {len(src_cves)} 条")
    if not include_drafts and drafts:
        print(f"（另有 {len(drafts)} 份草稿未校验，交件前用 --all）")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
