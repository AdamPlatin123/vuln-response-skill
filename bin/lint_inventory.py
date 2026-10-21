#!/usr/bin/env python3
"""W1 漏洞清单表 inventory.tsv 校验器（组规 §2/§4/§5 + §8 裁定 R1–R4）。

用法（从 vuln-response/ 目录）:
  bash bin/lint-playbooks.sh --inventory                    # 默认 ../vuln-w1/inventory.tsv
  bash bin/lint-playbooks.sh --inventory path/to/inv.tsv
  bash bin/lint-playbooks.sh --inventory --allow-uncovered  # R4 未挂件只报 WARN（修复策略交件前用）
  bash bin/lint-playbooks.sh --inventory --strict-sync      # front-matter 对账也升 FAIL
  bash bin/lint-playbooks.sh --inventory --json

判定口径（FAIL 阻断封版）:
  F1  文件/表头：UTF-8、LF、14 列表头顺序一致、字段数一致、必填非空
  F2  id：`W1-NNN`、唯一、严格递增（跳号 WARN）
  F3  枚举：direction / in_the_wild / status / playbook / checked_at；
      ecosystem 为「包管理器/平台」自由枚举（小写 slug，组规 §2）
  F4  重复建行：`(advisory_ids 归一化集合, ecosystem)` 不得重复
  F5  同一 advisory 多行：跨行时 `merge_key` 必须相同（一 CVE 一行 / 跨生态归并）
  F6  fixed：R1 允许 `REMOVE-ONLY`（可与 verified 共存，但 verified 必须挂件）；`UNKNOWN` 不得出现在 verified 行；
      `UNKNOWN` 只能出现在 affects/fixed 列
  F7  一手来源：每个 advisory 号必须在 sources.md 命中「一手」行；
      只有二手/未确认/公开 PoC/三方公告 → FAIL；primary_source URL 必须已在 sources.md 建行；
      RUMOR: 前缀只允许 status=observe
  F8  evidence_ref（R2 三形式）：真实路径（必须存在）/ `sources.md#S003,S004` /
      `kev.json#CVE-…`；**禁双前缀**（`VYPER-GHSA-GHSA-*` 当场 FAIL）
  F9  observe 混入（R3 收窄）：只有三种 FAIL —— 进 front-matter `cve:`、
      进结论表某行、给了修复版本；标了「观察项/未确认/不进结论」的观察区出现是合规的（WARN 可见）
  F10 verified 必须挂 playbook（R4）；`--allow-uncovered` 时降为 WARN
  F11 front-matter 对账（§3.1）：ecosystem / cve / fixed 与清单行一致性
      → 默认 WARN，`--strict-sync` 升 FAIL
exit 0 = 无 FAIL；1 = 有 FAIL；2 = 调用错误。
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PB = ROOT / "playbooks"
DRAFT = PB / "_draft"
SOURCES = ROOT / "sources.md"
INDEX = ROOT / "index.md"
KEV = ROOT.parent / "kev.json"
PEER = ROOT.parent / "vuln-w1" / "check_inventory.py"
PEER_TSV = ROOT.parent / "vuln-w1" / "inventory.tsv"
# 工作区内：清单表在 ../vuln-w1/inventory.tsv；打包后的 dist 里清单表随包放在包根
DEFAULT_INV = (ROOT / "inventory.tsv") if (ROOT / "inventory.tsv").exists() else (ROOT.parent / "vuln-w1" / "inventory.tsv")

HEADER = [
    "id", "direction", "component", "ecosystem", "advisory_ids", "affects",
    "fixed", "in_the_wild", "primary_source", "evidence_ref", "merge_key",
    "playbook", "status", "checked_at",
]
DIRECTIONS = {"node", "npm", "go", "python-llm", "php", "pki", "boundary", "generic"}
ECO_RE = re.compile(r"^[a-z][a-z0-9.+-]{0,31}$")
# 已知 ecosystem 取值（包管理器/平台）；不在此表内不阻断，只 WARN
KNOWN_ECOS = {"nodejs", "node", "npm", "go", "pypi", "python", "python-llm", "php", "packagist",
              "nuget", "rubygems", "gem", "cpan", "cargo", "crates.io", "docker", "nss", "gitlab",
              "generic", "plex", "pan-os", "fortimail", "siteguard", "siemens"}
IN_THE_WILD = {"KEV", "vendor-confirmed", "poc-only", "unknown"}
STATUSES = {"verified", "partial", "draft", "observe"}
PB_NUMS = {f"{i:02d}" for i in range(1, 12)}

ID_RE = re.compile(r"^W1-(\d{3})$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
URL_RE = re.compile(r"https?://\S+")
VER_RE = re.compile(r"\d+\.\d+(?:\.\d+)*")
SID_RE = re.compile(r"\bS(\d{3,})\b")
CVE_ANY = r"(?:CVE-\d{4}-\d{4,}|GHSA-(?:[0-9a-z]{4}-){2}[0-9a-z]{4}|MAL-\d{4}-\d{4,}|PYSEC-\d{4}-\d+|GO-\d{4}-\d{4,}|RUSTSEC-\d{4}-\d{4})"
ADV_ANY_RE = re.compile(CVE_ANY)
DOUBLE_PREFIX_RE = re.compile(r"(?:CVE|GHSA|MAL|PYSEC|GO|RUSTSEC)-(?:CVE|GHSA|MAL|PYSEC|GO|RUSTSEC)-")
EXEMPT_H = re.compile(r"观察项|未入结论|不入结论|不进处置结论|仅线索|线索|传闻|未确认|不作结论|只登记")
EXEMPT_L = re.compile(r"观察项|未入结论|不入结论|不进处置结论|不写进处置|仅线索|待核|待补|待侦察|未确认|二手定位|不采信|降级")
FIXED_MARK_RE = re.compile(r"修复|fixed|升级到|升级至|patched|REMOVE-ONLY", re.I)
OK_SRC_TYPES = ("一手",)
SEP_ROW_RE = re.compile(r"^\|[\s:|-]+\|$")


class Report:
    def __init__(self) -> None:
        self.fails: list[str] = []
        self.warns: list[str] = []
        self.oks: list[str] = []
        self.by_code: dict[str, int] = {}

    def _count(self, msg: str) -> None:
        m = re.match(r"\[([A-Z]\d+)\]", msg)
        if m:
            self.by_code[m.group(1)] = self.by_code.get(m.group(1), 0) + 1

    def fail(self, code: str, msg: str) -> None:
        m = f"[{code}] {msg}"
        self.fails.append(m)
        self._count(m)

    def warn(self, code: str, msg: str) -> None:
        m = f"[{code}] {msg}"
        self.warns.append(m)
        self._count(m)

    def ok(self, msg: str) -> None:
        self.oks.append(msg)


def split_ids(raw: str) -> list[str]:
    return [t.strip() for t in re.split(r"[;；]", raw) if t.strip()]


def parse_sources() -> dict:
    text = SOURCES.read_text(encoding="utf-8") if SOURCES.exists() else ""
    by_adv: dict[str, list[tuple[str, str]]] = {}
    sids: set[str] = set()
    for line in text.splitlines():
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 4 or not re.match(r"^S\d{3,}$", cells[0]):
            continue
        sids.add(cells[0])
        typ = cells[2]
        for tok in ADV_ANY_RE.findall(line):
            by_adv.setdefault(tok.upper(), []).append((typ, line))
    return {"text": text, "by_adv": by_adv, "sids": sids}


def parse_headings(path: Path) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    if not path.exists():
        return out
    head = ""
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("#"):
            head = line.lstrip("#").strip()
        out.append((head, line))
    return out


def parse_playbook_meta(path: Path) -> dict[str, str]:
    text = path.read_text(encoding="utf-8")
    fm: dict[str, str] = {}
    if text.startswith("---"):
        end = text.find("\n---", 3)
        if end > 0:
            for line in text[3:end].splitlines():
                m = re.match(r"^([a-z_]+):\s*(.*)$", line)
                if m:
                    fm[m.group(1)] = m.group(2).strip().strip('"').strip("'")
    return fm


def playbook_files() -> list[Path]:
    files = [p for p in sorted(PB.glob("*.md")) if re.match(r"^\d{2}-", p.name)]
    if DRAFT.exists():
        files += [p for p in sorted(DRAFT.glob("*.md")) if re.match(r"^\d{2}-", p.name)]
    return files


def kev_index() -> tuple[set[str], str]:
    if not KEV.exists():
        return set(), ""
    try:
        data = json.loads(KEV.read_text(encoding="utf-8"))
    except Exception:
        return set(), ""
    ids = {str(v.get("cveID", "")).upper() for v in data.get("vulnerabilities", []) if v.get("cveID")}
    return ids, str(data.get("catalogVersion", ""))


def load_tsv(path: Path, rep: Report, lenient: bool = False) -> list[dict[str, str]]:
    raw = path.read_bytes()
    if raw.startswith(b"\xef\xbb\xbf"):
        (rep.warn if lenient else rep.fail)("F1", "inventory.tsv 带 UTF-8 BOM，去掉（下游脚本会读到 \\ufeff）")
        raw = raw[3:]
    if b"\r\n" in raw:
        (rep.warn if lenient else rep.fail)("F1", "inventory.tsv 是 CRLF 换行，统一成 LF（shell/awk 工具链会吃到 \\r）")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as e:
        rep.fail("F1", f"inventory.tsv 不是合法 UTF-8: {e}")
        return []
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if not lines:
        rep.fail("F1", "inventory.tsv 为空")
        return []
    header = [h.strip() for h in lines[0].split("\t")]
    if header != HEADER:
        rep.fail("F1", f"表头不合规：期望 14 列 {HEADER}；实际 {header}")
        return []
    rep.ok("F1 表头 14 列顺序正确")

    rows: list[dict[str, str]] = []
    for i, line in enumerate(lines[1:], start=2):
        cells = line.split("\t")
        if len(cells) != len(HEADER):
            rep.fail("F1", f"第 {i} 行字段数 {len(cells)} ≠ 14（多半是某列里混了制表符/漏列）")
            continue
        row = {k: v.strip() for k, v in zip(HEADER, cells)}
        row["_line"] = str(i)
        for k in HEADER:
            if row[k] == "":
                rep.fail("F1", f"第 {i} 行（{row['id'] or '?'}）必填列为空: {k}")
        rows.append(row)
    rep.ok(f"F1 行结构：{len(rows)} 条清单行")
    return rows


def check_ids(rows: list[dict[str, str]], rep: Report) -> None:
    seen: dict[str, str] = {}
    nums: list[tuple[int, str]] = []
    for r in rows:
        m = ID_RE.match(r["id"])
        if not m:
            rep.fail("F2", f"第 {r['_line']} 行 id={r['id']!r} 不合规，应为 W1-NNN")
            continue
        n = int(m.group(1))
        if r["id"] in seen:
            rep.fail("F2", f"id 重复: {r['id']}（第 {seen[r['id']]} 行与第 {r['_line']} 行）")
        seen[r["id"]] = r["_line"]
        nums.append((n, r["id"]))
    nums.sort()
    for a, b in zip(nums, nums[1:]):
        if b[0] <= a[0]:
            rep.fail("F2", f"id 未严格递增: {a[1]} → {b[1]}")
        elif b[0] - a[0] > 1:
            rep.warn("F2", f"id 跳号: {a[1]} → {b[1]}（允许，但封版前确认不是漏行）")
    if nums and nums[0][0] != 1:
        rep.warn("F2", f"id 从 {nums[0][1]} 起，不是 W1-001")
    rep.ok(f"F2 id 唯一递增：{len(seen)} 个")


def check_enums(rows: list[dict[str, str]], rep: Report) -> None:
    on_disk = {p.name[:2] for p in playbook_files()}
    bad = 0
    unknown_eco: set[str] = set()
    for r in rows:
        tag = f"第 {r['_line']} 行（{r['id']}）"
        if r["direction"] not in DIRECTIONS:
            rep.fail("F3", f"{tag} direction={r['direction']!r} 不在 {sorted(DIRECTIONS)}")
            bad += 1
        if not ECO_RE.match(r["ecosystem"]):
            rep.fail("F3", f"{tag} ecosystem={r['ecosystem']!r} 不是小写包管理器/平台 slug")
            bad += 1
        elif r["ecosystem"] not in KNOWN_ECOS:
            unknown_eco.add(r["ecosystem"])
        if r["in_the_wild"] not in IN_THE_WILD:
            rep.fail("F3", f"{tag} in_the_wild={r['in_the_wild']!r} 不在 {sorted(IN_THE_WILD)}")
            bad += 1
        if r["status"] not in STATUSES:
            rep.fail("F3", f"{tag} status={r['status']!r} 不在 {sorted(STATUSES)}")
            bad += 1
        if r["checked_at"] and not DATE_RE.match(r["checked_at"]):
            rep.fail("F3", f"{tag} checked_at={r['checked_at']!r} 不是 YYYY-MM-DD")
            bad += 1
        pb = r["playbook"]
        if pb != "NONE":
            if pb not in PB_NUMS:
                rep.fail("F3", f"{tag} playbook={pb!r} 应为 NONE 或 01–11")
                bad += 1
            elif pb not in on_disk:
                rep.fail("F3", f"{tag} playbook={pb} 指向的文件不存在（playbooks/ 或 _draft/ 下都没有 {pb}-*.md）")
                bad += 1
    for e in sorted(unknown_eco):
        rep.warn("F3", f"ecosystem={e!r} 不在已知清单里（新平台先确认再收，别让拼写变体混进来）")
    if bad == 0:
        rep.ok("F3 枚举/日期/playbook 引用全部命中")


def check_dups(rows: list[dict[str, str]], rep: Report) -> None:
    seen: dict[tuple[str, str], str] = {}
    adv_rows: dict[str, list[dict[str, str]]] = {}
    for r in rows:
        ids = split_ids(r["advisory_ids"])
        if not ids or ids == ["NONE"]:
            continue
        norm = ";".join(sorted(t.upper() for t in ids))
        key = (norm, r["ecosystem"])
        if key in seen:
            rep.fail("F4", f"重复建行：({r['advisory_ids']}, {r['ecosystem']}) 已在第 {seen[key]} 行；一行一 advisory")
        else:
            seen[key] = r["_line"]
        for t in ids:
            adv_rows.setdefault(t.upper(), []).append(r)
    rep.ok(f"F4 (advisory_ids, ecosystem) 去重：{len(seen)} 组")

    for tok, rs in sorted(adv_rows.items()):
        if len(rs) < 2:
            continue
        mks = {x["merge_key"] for x in rs}
        lines = ", ".join(f"第 {x['_line']} 行({x['ecosystem']})" for x in rs)
        if len(mks) > 1:
            rep.fail("F5", f"{tok} 出现在 {len(rs)} 行但 merge_key 不一致（{sorted(mks)}）：{lines}；跨生态同根因必须同 merge_key")
        else:
            rep.ok(f"F5 {tok} 跨 {len(rs)} 行，merge_key={sorted(mks)[0]} 一致")


def check_fixed(rows: list[dict[str, str]], rep: Report) -> None:
    for r in rows:
        tag = f"第 {r['_line']} 行（{r['id']}）"
        for k in HEADER:
            if k in {"affects", "fixed"}:
                continue
            if "UNKNOWN" in r[k]:
                rep.fail("F6", f"{tag} {k} 列出现 UNKNOWN；只允许出现在 affects/fixed")
        has_unknown = "UNKNOWN" in r["affects"] or "UNKNOWN" in r["fixed"]
        if has_unknown and r["status"] == "verified":
            rep.fail("F6", f"{tag} status=verified 但 affects/fixed 含 UNKNOWN（verified 要求区间与修复版本已核实）")
        elif has_unknown:
            rep.warn("F6", f"{tag} affects/fixed 含 UNKNOWN → status 只能是 partial/draft")
        if r["fixed"] == "REMOVE-ONLY":
            # R1 修订（组长 2026-10-22）：REMOVE-ONLY 可与 verified 共存，前提是挂了 playbook
            if r["status"] == "observe":
                rep.fail("E2", f"{tag} fixed=REMOVE-ONLY 却是 observe：移除+轮换已是结论，不该降成线索")
            elif r["status"] == "verified" and r["playbook"] == "NONE":
                rep.fail("E2", f"{tag} REMOVE-ONLY + verified 但 playbook=NONE（R1 修订：verified 必须挂件）")
            else:
                rep.ok(f"E2 {r['id']} REMOVE-ONLY + {r['status']} 合规（playbook={r['playbook']}）")
    rep.ok("F6 fixed/UNKNOWN 规则检查完成（R1 允许 REMOVE-ONLY）")


def check_sources(rows: list[dict[str, str]], rep: Report, src: dict, warn_only: bool = False) -> None:
    text = src["text"]
    emit = rep.warn if warn_only else rep.fail
    code = "E4" if warn_only else "F7"
    for r in rows:
        if warn_only and r["status"] == "observe":
            continue  # observe 是线索，来源不要求一手（E4 审计口径）
        tag = f"第 {r['_line']} 行（{r['id']}）"
        ids = [t for t in split_ids(r["advisory_ids"]) if t.upper() != "NONE"]
        psrc = r["primary_source"]
        rumor = psrc.upper().startswith("RUMOR:")
        if rumor and r["status"] != "observe":
            emit(code, f"{tag} primary_source 是 RUMOR:（二手），status={r['status']}；只有 observe 允许二手")
        if not rumor:
            m = URL_RE.search(psrc)
            if not m:
                emit(code, f"{tag} primary_source 里没有 http(s) URL")
            else:
                u = m.group(0).rstrip("/")
                if u not in text and m.group(0) not in text:
                    emit(code, f"{tag} primary_source 未在 sources.md 建行：{m.group(0)}（组规 §3.3：先补 sources.md 再引用）")
        for tok in ids:
            hits = src["by_adv"].get(tok.upper(), [])
            if not hits:
                emit(code, f"{tag} {tok} 在 sources.md 找不到任何来源行")
                continue
            if not any(h[0].startswith(p) for h in hits for p in OK_SRC_TYPES):
                types = sorted({h[0] for h in hits})
                if any("三方公告" in t for t in types):
                    emit(code, f"{tag} {tok} 只有三方公告来源；修复版本必须厂商一手复核")
                else:
                    emit(code, f"{tag} {tok} 只有非一手来源 {types}（二手/未确认/公开 PoC 不能支撑结论）")
    rep.ok(("E4 一手来源审计完成" if warn_only else "F7 一手来源对账完成"))


def check_double_prefix(rows: list[dict[str, str]], rep: Report, warn_only: bool = False) -> None:
    emit = rep.warn if warn_only else rep.fail
    code = "E4" if warn_only else "F8"
    n = 0
    for r in rows:
        ev = r["evidence_ref"]
        if DOUBLE_PREFIX_RE.search(ev):
            n += 1
            emit(code, f"第 {r['_line']} 行（{r['id']}）evidence_ref 出现双前缀（如 VYPER-GHSA-GHSA-*）：{ev}")
    if n == 0:
        rep.ok("E4/F8 evidence_ref 无双前缀（R2）")


def check_evidence(rows: list[dict[str, str]], rep: Report, src: dict, kev: tuple[set[str], str]) -> None:
    kev_ids, kev_ver = kev
    for r in rows:
        tag = f"第 {r['_line']} 行（{r['id']}）"
        ev = r["evidence_ref"]
        if DOUBLE_PREFIX_RE.search(ev):
            rep.fail("F8", f"{tag} evidence_ref 出现双前缀（如 VYPER-GHSA-GHSA-*）：{ev}")
        parts = [p.strip() for p in ev.split(";") if p.strip()]
        if not parts:
            rep.fail("F8", f"{tag} evidence_ref 为空")
            continue
        for part in parts:
            low = part.lower()
            if "sources.md" in low:
                sids = SID_RE.findall(part)
                if not sids:
                    rep.fail("F8", f"{tag} sources.md 引用缺 S 号（应为 sources.md#S003,S004）：{part}")
                    continue
                for sid in sids:
                    if f"S{sid}" not in src["sids"]:
                        rep.fail("F8", f"{tag} evidence_ref 引用的 S{sid} 在 sources.md 不存在：{part}")
            elif "kev.json" in low:
                cves = re.findall(r"CVE-\d{4}-\d{4,}", part, re.I)
                if not cves:
                    rep.fail("F8", f"{tag} kev.json 引用缺 CVE 号（应为 kev.json#CVE-…）：{part}")
                    continue
                for cve in cves:
                    if kev_ids and cve.upper() not in kev_ids:
                        rep.fail("F8", f"{tag} kev.json 里没有 {cve}（catalogVersion {kev_ver}）")
                    elif not kev_ids:
                        rep.warn("F8", f"{tag} 本地 kev.json 缺失/不可解析，无法核 {cve}")
                mv = re.search(r"catalogVersion[=@]([\d.]+)", part)
                if mv and kev_ver and mv.group(1) != kev_ver:
                    rep.fail("F8", f"{tag} kev.json catalogVersion 写 {mv.group(1)}，本地实际 {kev_ver}")
            else:
                # 第三种形式：真实路径
                if not re.search(r"[/.]", part):
                    rep.fail("F8", f"{tag} evidence_ref 不符合三形式（路径 / sources.md#Sxxx / kev.json#CVE-…）：{part}")
                    continue
                cand = Path(part) if part.startswith("/") else (ROOT.parent / part)
                if not cand.exists():
                    rep.fail("F8", f"{tag} evidence_ref 路径不存在: {part}")
    rep.ok("F8 evidence_ref 三形式/双前缀检查完成（R2）")


def check_observe(rows: list[dict[str, str]], rep: Report) -> None:
    obs = [r for r in rows if r["status"] == "observe"]
    if not obs:
        rep.ok("F9 无 observe 行")
        return
    books = [(str(p.relative_to(ROOT)), parse_playbook_meta(p), parse_headings(p)) for p in playbook_files()]
    idx = parse_headings(INDEX)
    for r in obs:
        ids = [t for t in split_ids(r["advisory_ids"]) if t.upper() != "NONE"]
        tag = f"第 {r['_line']} 行（{r['id']}）"
        if not ids:
            rep.warn("F9", f"{tag} observe 行无 advisory_ids，无法自动查混入，人工核 component={r['component']}")
            continue
        for tok in ids:
            # R3-1：进 front-matter cve:
            for name, fm, _lines in books:
                if tok in fm.get("cve", ""):
                    rep.fail("F9", f"{tok} 是 observe（{tag}）却进了 {name} 的 front-matter cve:（R3 禁止）")
            # R3-2/3：结论表行 / 给了修复版本；观察区出现只 WARN
            seen_fail: set[str] = set()
            seen_warn: set[str] = set()
            streams = [(n, lines) for n, _fm, lines in books] + [("index.md", idx)]
            for name, lines in streams:
                for head, line in lines:
                    if tok not in line:
                        continue
                    label = head or "文首"
                    exempt = bool(EXEMPT_H.search(head) or EXEMPT_L.search(line))
                    is_row = line.lstrip().startswith("|") and not SEP_ROW_RE.match(line.strip())
                    gives_fixed = bool(FIXED_MARK_RE.search(line) and VER_RE.search(line))
                    if exempt:
                        if name not in seen_warn:
                            rep.warn("F9", f"{tok}（observe）出现在 {name}「{label}」观察区/已标注，合规")
                            seen_warn.add(name)
                    elif is_row:
                        rep.fail("F9", f"{tok} 是 observe（{tag}）却进了 {name}「{label}」的结论表行（R3 禁止）")
                        seen_fail.add(name)
                    elif gives_fixed:
                        rep.fail("F9", f"{tok} 是 observe（{tag}）却在 {name}「{label}」给了修复版本（R3 禁止）")
                        seen_fail.add(name)
                    elif name not in seen_fail and name not in seen_warn:
                        rep.warn("F9", f"{tok}（observe）出现在 {name}「{label}」正文（非观察区），人工确认不是结论")
                        seen_warn.add(name)
    rep.ok(f"F9 observe 混入检查：{len(obs)} 条 observe 行（R3 收窄版）")


def check_verified_playbook(rows: list[dict[str, str]], rep: Report, allow_uncovered: bool) -> None:
    bad = 0
    for r in rows:
        if r["status"] != "verified" or r["playbook"] != "NONE":
            continue
        bad += 1
        msg = f"第 {r['_line']} 行（{r['id']}）status=verified 但 playbook=NONE（R4：verified 必须挂件；{r['component']}）"
        if allow_uncovered:
            rep.warn("F10", msg + " [--allow-uncovered 暂放行]")
        else:
            rep.fail("F10", msg)
    if bad == 0:
        rep.ok("F10 verified 全部挂件")


def check_frontmatter_sync(rows: list[dict[str, str]], rep: Report, strict: bool) -> None:
    by_nn: dict[str, list[dict[str, str]]] = {}
    for r in rows:
        if r["playbook"] in PB_NUMS:
            by_nn.setdefault(r["playbook"], []).append(r)

    def emit(msg: str) -> None:
        (rep.fail if strict else rep.warn)("F11", msg)

    files = playbook_files()
    for p in files:
        nn = p.name[:2]
        fm = parse_playbook_meta(p)
        rel = p.relative_to(ROOT)
        rows_nn = by_nn.get(nn, [])
        if not rows_nn:
            rep.warn("F11", f"{rel} 没有任何清单行挂到 playbook={nn}（清单/playbook 未对齐）")
            continue
        fm_text = " ".join(fm.get(k, "") for k in ("cve", "affects", "fixed"))
        for r in rows_nn:
            tag = f"第 {r['_line']} 行（{r['id']}）→ {rel}"
            for tok in split_ids(r["advisory_ids"]):
                if tok.upper() == "NONE":
                    continue
                if tok not in fm_text:
                    emit(f"{tag} 清单有 {tok}，playbook front-matter 的 cve/affects/fixed 里没有")
            for tok in sorted(set(VER_RE.findall(r["fixed"]))):
                if tok not in fm_text:
                    emit(f"{tag} 清单 fixed 含 {tok}，playbook front-matter 未出现该修复版本")
            if r["status"] == "verified" and fm.get("status") != "verified":
                emit(f"{tag} 清单 status=verified，playbook front-matter status={fm.get('status')!r}")
    rep.ok(f"F11 front-matter 对账：{len(files)} 份 playbook × {len(by_nn)} 个编号")


def run_peer(inv_path: Path, explicit: str | None) -> tuple[bool | None, str]:
    """跑侦察落盘的 check_inventory.py。返回 (通过?, 输出)；None = 不可用。"""
    peer = Path(explicit) if explicit else PEER
    if not peer.exists():
        return None, ""
    if explicit is None and inv_path.resolve() != PEER_TSV.resolve():
        return None, ""  # peer 硬编码读自家 inventory.tsv，自定义路径时不用它
    proc = subprocess.run([sys.executable, str(peer)], capture_output=True, text=True)
    out = (proc.stdout + proc.stderr).rstrip()
    return proc.returncode == 0, out


def main(argv: list[str]) -> int:
    inv: str | None = None
    strict_sync = False
    allow_uncovered = False
    as_json = False
    no_peer = False
    peer_path: str | None = None
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--inventory":
            i += 1
            continue
        if a in {"--strict-sync", "--strict"}:
            strict_sync = True
        elif a == "--allow-uncovered":
            allow_uncovered = True
        elif a == "--json":
            as_json = True
        elif a == "--no-peer":
            no_peer = True
        elif a == "--peer":
            i += 1
            if i >= len(argv):
                print("--peer 需要参数", file=sys.stderr)
                return 2
            peer_path = argv[i]
        elif a.startswith("-"):
            print(f"未知参数: {a}", file=sys.stderr)
            return 2
        elif inv is None:
            inv = a
        else:
            print(f"多余参数: {a}", file=sys.stderr)
            return 2
        i += 1

    path = Path(inv) if inv else DEFAULT_INV
    if not path.is_absolute():
        path = (Path.cwd() / path).resolve()
    rep = Report()
    if not path.exists():
        print(f"FAIL  清单表不存在: {path}", file=sys.stderr)
        print("（侦察交件前属预期；交件后此条即阻断封版）", file=sys.stderr)
        return 1

    peer_ok: bool | None = None
    peer_out = ""
    if not no_peer:
        peer_ok, peer_out = run_peer(path, peer_path)

    rows = load_tsv(path, rep, lenient=peer_ok is not None)
    if rows:
        if peer_ok is None:
            # 内部完整检查（dist / 无 peer 时用）
            check_ids(rows, rep)
            check_enums(rows, rep)
            check_dups(rows, rep)
            check_fixed(rows, rep)
            src = parse_sources()
            check_sources(rows, rep, src)
            check_evidence(rows, rep, src, kev_index())
            check_observe(rows, rep)
            check_verified_playbook(rows, rep, allow_uncovered)
            check_frontmatter_sync(rows, rep, strict_sync)
        else:
            # peer 模式：侦察校验器为准，只加他没做的规则 + 只读审计
            check_fixed(rows, rep)                      # E2 REMOVE-ONLY + F6 UNKNOWN 交叉核对
            src = parse_sources()
            check_sources(rows, rep, src, warn_only=True)   # E4 一手来源审计（WARN）
            check_double_prefix(rows, rep, warn_only=True)  # E4 双前缀（WARN）
            check_observe(rows, rep)                    # F9 observe 混入（R3，FAIL）
            check_verified_playbook(rows, rep, allow_uncovered)  # F10 verified 必须挂件（R4）
            check_frontmatter_sync(rows, rep, strict_sync)       # F11 对账（WARN）
    else:
        rep.fail("F0", "没有可校验的数据行")

    base_fail = (peer_ok is False)
    total_fail = len(rep.fails) + (1 if base_fail else 0)

    if as_json:
        print(json.dumps({
            "file": str(path), "rows": len(rows),
            "peer": {"used": peer_ok is not None, "pass": peer_ok},
            "base_fail": base_fail,
            "fail": total_fail, "extras_fail": len(rep.fails), "warn": len(rep.warns),
            "by_code": dict(sorted(rep.by_code.items())),
            "allow_uncovered": allow_uncovered,
            "fails": ([] if not base_fail else ["[PEER] 侦察 check_inventory.py FAIL"]) + rep.fails,
            "warns": rep.warns,
        }, ensure_ascii=False, indent=2))
    else:
        print(f"== inventory 校验 ==  {path}")
        if peer_ok is None:
            print("== 模式 ==  内部校验（未找到 ../vuln-w1/check_inventory.py 或用了自定义路径）")
        else:
            print(f"== 模式 ==  peer 校验器（侦察 check_inventory.py）+ 补充规则")
            print(f"== peer ==  {'PASS' if peer_ok else 'FAIL'}")
            for ln in peer_out.splitlines():
                print(f"   {ln}")
            print("== 补充规则 ==")
        for m in rep.oks:
            print(f"ok    {m}")
        for m in rep.warns:
            print(f"WARN  {m}")
        for m in rep.fails:
            print(f"FAIL  {m}")
        codes = "，".join(f"{k}×{v}" for k, v in sorted(rep.by_code.items()))
        print(f"== 汇总 ==  行 {len(rows)}，FAIL {total_fail}"
              f"（peer {1 if base_fail else 0} + 补充 {len(rep.fails)}），WARN {len(rep.warns)}"
              + (f"（{codes}）" if codes else ""))
        print(f"== 开关 ==  {'strict-sync' if strict_sync else '默认 F11=WARN'} / "
              f"{'allow-uncovered（F10 降级）' if allow_uncovered else 'uncovered=FAIL'}")
    return 0 if total_fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
