---
id: "12"
title: Vyper 源码闸门（6 条 GHSA · 无已发布修复版本，只能改源码 + 阻断发布）
ecosystem: python
cve: []
aliases: ["GHSA-2489-32vh-8rrc", "GHSA-6j9c-gvcw-74fj", "GHSA-cw3h-xwxq-8cx2", "GHSA-fxg7-4wqg-c8gh", "GHSA-r3c7-7xwm-6vfw", "GHSA-wvx7-39qj-2g9v"]
affects: "vyper 全系受影响面按 GHSA 逐条给：导入常量/默认参数解析 `>=0.4.0b1`；`msg.value | K` 折叠 `>=0.3.8`；三元嵌套数组 `>=0.3.8 <=0.5.0b1`；`create_from_blueprint` 偏移 `>=0.3.4`；多字节标识符 `>=0.1.0b1 <0.1.0b12` / `=0.1.0b14` / `>=0.4.1`；行分隔符 `>=0.1.0b1 <0.1.0b17` / `>=0.4.1`"
fixed: ["无已发布修复版本（截至 2026-10-22，6 条 GHSA 的 first_patched_version 均为空）→ 本件是源码闸门，不给升级命令"]
severity: "中危为主（6 条 GHSA：medium×3 / low×3；后果是静默错值、错误部署、字面量被改，不是直接 RCE）"
status: verified
sources: ["https://github.com/vyperlang/vyper/security/advisories/GHSA-2489-32vh-8rrc", "https://github.com/vyperlang/vyper/security/advisories/GHSA-6j9c-gvcw-74fj", "https://github.com/vyperlang/vyper/security/advisories/GHSA-cw3h-xwxq-8cx2", "https://github.com/vyperlang/vyper/security/advisories/GHSA-fxg7-4wqg-c8gh", "https://github.com/vyperlang/vyper/security/advisories/GHSA-r3c7-7xwm-6vfw", "https://github.com/vyperlang/vyper/security/advisories/GHSA-wvx7-39qj-2g9v"]
updated: 2026-10-22
---

# Vyper 源码闸门（6 条 GHSA）

**一句话**：这 6 条**没有可升级的修复版本**（GHSA 的 `first_patched_version` 全空，`>=0.4.1` / `0.5.0b1` 仍在受影响面）——所以它们**不能靠「升版本」关单**，只能做**源码闸门**：发布前扫源码，命中即阻断。

> **三条硬规则**
> 1. **不许拿「升到最新版」当修复**：`0.4.1`+ 和 `0.5.0b1` 仍在多条受影响面内，写「升级已修复」就是错账。
> 2. **闸门必须在 CI 上阻断**（exit≠0 即不许合并/发布），不是「人工检查」。
> 3. **命中不等于有漏洞**：闸门是近似扫描，命中后人工复核 → 改源码或走**限时白名单**（带到期日），不许长期放行。

## 适用版本区间

| # | GHSA | 缺陷 | 受影响（GHSA 原文） | 修复版本 |
|---|---|---|---|---|
| R1 | GHSA-2489-32vh-8rrc | 函数形参/局部/循环变量**覆盖导入常量与默认参数**的解析 | `>=0.4.0b1` | **无** |
| R2 | GHSA-6j9c-gvcw-74fj | 优化器把三元分支里的 `(msg.value OR K)` / `(len(msg.data) OR K)` 折成 `1`（`-O gas`/`-O codesize`，默认开） | `>=0.3.8` | **无** |
| R3 | GHSA-cw3h-xwxq-8cx2 | 三元在**内层边界不同的嵌套数组**间选择 → 按更宽布局读错偏移 | `>=0.3.8 <=0.5.0b1` | **无** |
| R4 | GHSA-fxg7-4wqg-c8gh | `create_from_blueprint` 的 `code_offset` 无符号回绕 → 部署**空 runtime** 而不 revert | `>=0.3.4` | **无** |
| R5 | GHSA-r3c7-7xwm-6vfw | 多字节字符（非 ASCII 标识符 / BOM）位移源码切片 → **字面量被静默改值/改类型** | `>=0.1.0b1 <0.1.0b12`、`=0.1.0b14`、`>=0.4.1` | **无** |
| R6 | GHSA-wvx7-39qj-2g9v | 8 种额外行分隔符（`U+000B/000C/001C/001D/001E/0085/2028/2029`）位移切片 → 同样静默改值 | `>=0.1.0b1 <0.1.0b17`、`>=0.4.1` | **无** |

**判断命令（版本只作背景，不构成「已修」依据）**

```bash
python3 -c 'import importlib.metadata as m;print("vyper",m.version("vyper"))' 2>/dev/null
vyper --version 2>/dev/null || true
```

> 版本判断在这里**没有处置意义**：命中版本区间也不代表有可利用实例（要看源码模式），不在区间也别以为安全（R5/R6 的区间是分段枚举）。

## 检测

### 1) 落盘闸门脚本（一次性）

```bash
cat > /tmp/vyper_gate.py <<'PY'
#!/usr/bin/env python3
"""Vyper 源码闸门：6 条 GHSA 模式。用法: python3 vyper_gate.py <dir> | --selftest
口径：字节/正则级近似扫描，不是编译器级证明；命中即阻断发布，人工复核后改源码。"""
import re, sys, pathlib

LINE_SEPS = {0x0B, 0x0C, 0x1C, 0x1D, 0x1E, 0x85, 0x2028, 0x2029}

def scan_text(path, raw):
    f = []
    bad = sorted({b for b in raw if b > 0x7F})          # R5 非 ASCII
    if bad:
        f.append((path, "R5", "非 ASCII 字节 " + ",".join(hex(b) for b in bad[:8])))
    if raw.startswith(b"\xef\xbb\xbf"):                  # R5 BOM
        f.append((path, "R5", "文件以 UTF-8 BOM 开头"))
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        f.append((path, "R5", "非法 UTF-8")); return f
    for cp in sorted({ord(c) for c in text if ord(c) in LINE_SEPS}):   # R6
        f.append((path, "R6", "含行分隔符 U+%04X" % cp))
    lines = text.splitlines()
    for i, l in enumerate(lines, 1):
        if re.search(r"\(\s*(?:msg\.value|len\(\s*msg\.data\s*\))\s*\|\s*\w+\s*\)", l):
            f.append((path, "R2", "L%d 表达式里用 `|`：%s" % (i, l.strip()[:80])))
        if re.search(r"\[[^\]]*\]\s+if\s+.+?\s+else\s+\[", l):
            f.append((path, "R3", "L%d 三元直接选数组字面量：%s" % (i, l.strip()[:80])))
        if "create_from_blueprint" in l:
            f.append((path, "R4", "L%d 需复核 code_offset 来源：%s" % (i, l.strip()[:90])))
    imported = set()
    for l in lines:
        m = re.match(r"\s*from\s+\S+\s+import\s+(.+)", l)
        if m:
            for part in m.group(1).split(","):
                nm = part.split(" as ")[-1].strip()
                if re.fullmatch(r"[A-Za-z_]\w*", nm):
                    imported.add(nm)
    if imported:
        for i, l in enumerate(lines, 1):
            m = re.match(r"\s*def\s+\w+\s*\((.*)\)", l)
            if m:
                for p in m.group(1).split(","):
                    nm = p.split(":")[0].strip()
                    if nm in imported:
                        f.append((path, "R1", "L%d 形参 %r 与导入名同名" % (i, nm)))
            m2 = re.match(r"\s*([A-Za-z_]\w*)\s*:\s*[^=]+=", l)
            if m2 and m2.group(1) in imported:
                f.append((path, "R1", "L%d 局部变量 %r 与导入名同名" % (i, m2.group(1))))
    return f

def main(argv):
    if argv and argv[0] == "--selftest":
        bad = {"R1": b"from src.consts import LIMIT\ndef f(LIMIT: uint256):\n    pass\n",
               "R2": b"x: uint256 = 1 if (msg.value | 1) else 0\n",
               "R3": b"y: uint256[2] = [1,2] if c else [1,2,3]\n",
               "R4": b"create_from_blueprint(bp, code_offset=off)\n",
               "R5": "x: uint256 = 1  # \u00e9\n".encode(),
               "R6": "x: uint256 = 1\u2028y: uint256 = 2\n".encode()}
        ok = True
        for rule, blob in bad.items():
            hits = [h for h in scan_text("<fixture>", blob) if h[1] == rule]
            print(("ok   " if hits else "FAIL ") + rule + " 命中=%d" % len(hits)); ok &= bool(hits)
        clean = b"from src.consts import LIMIT\n\ndef f(amount: uint256):\n    return amount\n"
        cheat = scan_text("<clean>", clean)
        print(("ok   " if not cheat else "FAIL ") + "clean 无误报 %s" % (cheat or ""))
        return 0 if ok and not cheat else 1
    if len(argv) != 1:
        print("用法: python3 vyper_gate.py <contracts-dir> | --selftest", file=sys.stderr); return 2
    files = sorted(pathlib.Path(argv[0]).rglob("*.vy"))
    if not files:
        print("FAIL 目录内没有 .vy 文件：%s" % argv[0]); return 1
    findings = []
    for p in files:
        findings += scan_text(p, p.read_bytes())
    for path, rule, msg in findings:
        print("FAIL [%s] %s: %s" % (rule, path, msg))
    print("== %d 个 .vy 文件，命中 %d 条 ==" % (len(files), len(findings)))
    print("结果:", "PASS" if not findings else "FAIL")
    return 0 if not findings else 1

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
PY
```

### 2) 先自测闸门本身（不通过就别信它的结果）

```bash
python3 /tmp/vyper_gate.py --selftest    # 期望 6 行 ok + clean 无误报，exit 0
```

### 3) 扫仓库

```bash
CONTRACTS="${CONTRACTS:?export CONTRACTS=合约目录}"
python3 /tmp/vyper_gate.py "$CONTRACTS"   # 期望「结果: PASS」，exit 0
```

### 4) 快速分诊（不进 CI，只看一眼）

```bash
# R5/R6：非 ASCII / BOM / 八种行分隔符
grep -rPn '[^\x00-\x7F]' --include='*.vy' "$CONTRACTS" | head
grep -rlP '\x{000B}|\x{000C}|\x{001C}|\x{001D}|\x{001E}|\x{0085}|\x{2028}|\x{2029}' --include='*.vy' "$CONTRACTS"
# R2/R3/R4：模式命中
grep -rnP '\(\s*(msg\.value|len\(\s*msg\.data\s*\))\s*\|\s*\w+\s*\)' --include='*.vy' "$CONTRACTS"
grep -rnP '\[[^\]]*\]\s+if\s+.+?\s+else\s+\[' --include='*.vy' "$CONTRACTS"
grep -rn 'create_from_blueprint' --include='*.vy' "$CONTRACTS"
```

**命中判据**：闸门 exit ≠ 0，或上面任一 `grep` 有输出 → **阻断发布**，进入人工复核。

## 影响判定

| 规则 | 命中意味着 | 判级 | 误报排除 |
|---|---|---|---|
| R1 | 导入常量/默认参数可能被同名变量替换，值可越出声明类型 | **P1**（静默错值，可能直接改业务逻辑） | 形参/局部与导入名同名但该导入名**从未在函数体使用** → 误报 |
| R2 | 开了优化后 `(msg.value OR K)` 恒为 `1`，转账金额判断失效 | **P0**（涉及资金判断） | 表达式只用作 `if` 条件（真值位）且未参与比较/赋值 |
| R3 | 三元选嵌套数组读错偏移，结果静默错 | **P1** | 两边数组**内层边界相同**（宽窄一致）→ 不触发 |
| R4 | 部署出空 runtime，且不 revert；攻击者可控制 `code_offset` 时最危险 | **P1**（若 `code_offset` 外部可控则 **P0**） | `code_offset` 是字面量/常量 → 误报 |
| R5 | 非 ASCII 字符/BOM 让**字面量序号与类型被改**，无告警 | **P1** | 非 ASCII 只出现在注释/字符串字面量内且不参与数字字面量解析 → 需人工确认，仍建议清掉 |
| R6 | 行分隔符同理位移，多个字符时位移累积 | **P1** | 同上 |

**总体定级**：命中 R2 或「R4 + 外部可控 offset」→ **P0**，立即冻结发布并审合约；其余命中 → P1，修完再发。

## 修复

**总原则：改源码 + 禁模式，不是升级。** 修复动作按规则给：

```text
R1  → 导入常量/默认参数改用不易冲突的名字（前缀命名空间，如 CONST_LIMIT）；
      或在使用处显式限定（不留同名形参/局部变量）。
R2  → 三元里禁止 `|` 运算：先算 `v: uint256 = msg.value`，再用 `v`；
      涉及金额判断的分支改用 `if/else` 明确写；不要依赖优化器行为。
R3  → 嵌套数组的三元选择改成 `if/else` 赋值（等价语义，GHSA 原文也指出 if/else 正确）。
R4  → `create_from_blueprint` 的 `code_offset` 只允许字面量/常量；禁止来自 calldata/参数；
      调用后校验部署结果（runtime 非空 / extcodesize > 0）。
R5  → 源码**纯 ASCII 化**：删 BOM、非 ASCII 标识符改 ASCII；注释里的非 ASCII 也要清（闸门按字节判）。
R6  → 删掉 `U+000B/000C/001C/001D/001E/0085/2028/2029` 全部字符，只用 `\n` 换行。
```

**禁模式（进 CI / pre-commit，防复发）**

```yaml
# CI 片段：闸门不过就不许合并/发布
- run: python3 ci/vyper_gate.py --selftest
- run: python3 ci/vyper_gate.py contracts/
```

- 把 `vyper_gate.py` 放进仓库 `ci/`（本件脚本可直接用），**自测与扫描都要跑**；
- 新增合约必须过闸门；存量命中走「限时白名单」（见回退），不许静默放行。

## 验证

```bash
# 1) 闸门自身有效
python3 ci/vyper_gate.py --selftest                      # 期望 6 ok + clean 无误报，exit 0

# 2) 目标仓库 PASS
python3 ci/vyper_gate.py contracts/                      # 期望「结果: PASS」，exit 0

# 3) 编译回归（改过源码必须能编）
vyper -f bytecode contracts/YourContract.vy >/dev/null && echo compile-ok

# 4) 行为回归（R2 专属：金额判断）
#    在测试网用「转账金额 != 1」的用例跑一遍；修复前该用例应失败、修复后通过
```

**通过标准**

1. `--selftest` exit 0（6 条规则各自命中、clean 无误报）；
2. 目标仓库扫描 `结果: PASS`、exit 0；
3. 改过源码的合约编译通过、测试通过；
4. R2 命中过的合约：**金额判断用例**在测试网验证通过（不能只靠编译成功）；
5. CI 里闸门已生效（故意提交一个坏样本，能被 fail 掉）；
6. 若用白名单：每条都有责任人 + 到期日，且到期前必须改源码。

## 回退

```bash
# 场景：闸门误伤导致无法发布（白名单是唯一允许的「回退」，且限时）
# 1) 记录：规则号 / 文件 / 命中行 / 为什么是误报 / 责任人 / 到期日
: "${GATE_COMMIT:?export GATE_COMMIT=引入闸门的提交}"
git revert "$GATE_COMMIT"        # 只许回退闸门接入，不许回退源码修复
# 2) 临时白名单（示例形态）：在 ci/vyper_gate_allow.txt 写
#    R5 contracts/Old.vy 2026-11-05   # 到期日
python3 ci/vyper_gate.py contracts/   # 白名单生效后应 PASS
```

**回退后风险**：回退闸门 = 这 6 类静默错值重新无阻进入发布；回退源码修复 = 直接暴露 R2 资金判断缺陷。因此回退只允许「闸门误伤」，且必须：白名单限时（≤2 周）、登记责任人、到期强制改源码；**不允许关掉 CI 检查当解法**。

## 条目

| 编号 | 组件 | 受影响 | 修复 | 来源 |
|---|---|---|---|---|
| GHSA-2489-32vh-8rrc | vyper（导入常量/默认参数名解析） | `>=0.4.0b1` | **无**；源码改名/限定，闸门 R1 | https://github.com/vyperlang/vyper/security/advisories/GHSA-2489-32vh-8rrc |
| GHSA-6j9c-gvcw-74fj | vyper（优化器折叠 `msg.value OR K`） | `>=0.3.8` | **无**；禁位或模式，闸门 R2 | https://github.com/vyperlang/vyper/security/advisories/GHSA-6j9c-gvcw-74fj |
| GHSA-cw3h-xwxq-8cx2 | vyper（三元嵌套数组越界读） | `>=0.3.8 <=0.5.0b1` | **无**；改 if/else，闸门 R3 | https://github.com/vyperlang/vyper/security/advisories/GHSA-cw3h-xwxq-8cx2 |
| GHSA-fxg7-4wqg-c8gh | vyper（`create_from_blueprint` 偏移绕过） | `>=0.3.4` | **无**；`code_offset` 限字面量，闸门 R4 | https://github.com/vyperlang/vyper/security/advisories/GHSA-fxg7-4wqg-c8gh |
| GHSA-r3c7-7xwm-6vfw | vyper（多字节标识符改字面量） | `>=0.1.0b1 <0.1.0b12`、`=0.1.0b14`、`>=0.4.1` | **无**；源码纯 ASCII 化，闸门 R5 | https://github.com/vyperlang/vyper/security/advisories/GHSA-r3c7-7xwm-6vfw |
| GHSA-wvx7-39qj-2g9v | vyper（行分隔符改字面量/类型） | `>=0.1.0b1 <0.1.0b17`、`>=0.4.1` | **无**；只留 `\n`，闸门 R6 | https://github.com/vyperlang/vyper/security/advisories/GHSA-wvx7-39qj-2g9v |

> 与 `vuln-w1/inventory.tsv` 对应：W1-061 ~ W1-066（`merge_key=vyper-*`，`fixed=UNKNOWN`，`status=partial`）。**本件不给升级命令，故这 6 行不应因本件升 verified**——建议维持 `partial` 并在 `playbook=12` 注明「源码闸门，无修复版本」。

## 来源

| 类型 | URL |
|---|---|
| 一手（GHSA：导入常量/默认参数名解析） | https://github.com/vyperlang/vyper/security/advisories/GHSA-2489-32vh-8rrc |
| 一手（GHSA：优化器 `msg.value OR K` 折叠） | https://github.com/vyperlang/vyper/security/advisories/GHSA-6j9c-gvcw-74fj |
| 一手（GHSA：三元嵌套数组） | https://github.com/vyperlang/vyper/security/advisories/GHSA-cw3h-xwxq-8cx2 |
| 一手（GHSA：`create_from_blueprint` 偏移） | https://github.com/vyperlang/vyper/security/advisories/GHSA-fxg7-4wqg-c8gh |
| 一手（GHSA：多字节标识符） | https://github.com/vyperlang/vyper/security/advisories/GHSA-r3c7-7xwm-6vfw |
| 一手（GHSA：行分隔符） | https://github.com/vyperlang/vyper/security/advisories/GHSA-wvx7-39qj-2g9v |
