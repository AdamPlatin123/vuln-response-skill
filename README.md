# vuln-response-skill

把「收到一条 CVE / 公告 → 判断我受不受影响 → 修复 → 验证 → 留证」压成可执行流程的 Agent Skill。
不是漏洞库，是**处置流程**：每条结论带一手 URL，每个修复步骤带能直接跑的验证命令。

- 状态：`v0.4.2`（W7 最终版：vLLM 6 条 + 决策树并行件/条件标签 + 105752/升格残留清扫），情报快照 **2026-10-22**（滚动窗口 2026-09-23 ~ 2026-10-23）
- 许可：Apache-2.0（见 `LICENSE`、`NOTICE`）
- 语言：中文
- 覆盖：Node/npm、Go、Python/LLM 基建、PHP、PKI/CA、**.NET/ASP.NET Core**、边界设备、**Vyper 源码闸门**、通用生产修复与凭据轮换

## 它是怎么被加载的

`SKILL.md` 是入口，头部有 Agent 用的元数据：

```yaml
---
name: vuln-response
description: 互联网漏洞情报 → 检测 / 影响判定 / 修复 / 验证 的可执行流程。...触发：收到 CVE/GHSA/公告链接、问「版本 X 受影响吗」...
---
```

把整个目录放进你的 Skill / 工具目录即可；加载后 Agent 按 `SKILL.md` 的决策树走，
再按 `index.md` 找对应 playbook。**不需要联网也能读**，但结论要生效必须回一手来源复核。

## 目录

| 路径 | 作用 |
|---|---|
| `SKILL.md` | 入口：触发条件、决策树、铁律、紧急通道 |
| `index.md` | 按生态 + 按 CVE 两套索引，含归并规则与未闭环清单 |
| `sources.md` | 来源表：ID、级别（一手/三方/公开 PoC/二手）、URL、核实状态 |
| `playbooks/01-…12-` | **12 件全部 verified**，逐生态处置：检测 → 判定 → 修复 → 验证 → 回退 |
| `playbooks/07` | **入口件**：定档 P0–P3、六段四门、「先关服务」判断、动生产库姿势 |
| `playbooks/_draft/` | 本轮为空（W2 无草稿件；`10` 已转 verified 在根） |
| `evidence/` | 取证存档：OSV / cvelistV5 原始 JSON、SPKI 清单 |
| `inventory.tsv` | v0.4.0 机器可读清单表（14 列 / **106 行** / 一行一 advisory）：id、方向、区间、fixed、在野、一手 URL、证据、merge_key、playbook、status；status = verified 68 · partial 6 · draft 28 · observe 4 |
| `bin/lint-playbooks.sh` | 结构校验：段缺命令块、占位符残留、CVE 未收录进 `sources.md` |
| `bin/lint_inventory.py` | 清单表校验：复用 `check_inventory.py` 基线 + `verified` 必须挂件、`REMOVE-ONLY` 口径、`observe` 三态混入、一手来源审计 |
| `bin/seal.sh` | 生成 `MANIFEST.sha256` 并打印文件树/行数 |
| `bin/new-playbook.sh` | 按模板起新 playbook 草稿 |

## 用法（三条命令）

```bash
bash bin/lint-playbooks.sh --all        # playbook 结构校验，失败项要修到 0
bash bin/seal.sh                        # 生成 MANIFEST.sha256
sha256sum -c MANIFEST.sha256            # 校验没被人改过
```

> `inventory.tsv` 是 **W2 快照**：`evidence_ref` 保留工作区相对路径（`vuln-response/evidence/…`，包内对应 `evidence/…`），
> `kev.json#CVE-…` 指向工作区里的 KEV 快照。它由 `bin/lint_inventory.py` 在工作区版（含 `../vuln-w1/`、`kev.json`）里校验，
> **不在包内重跑**；包内只保证 playbook 结构校验可跑。

## 设计上的三条硬约束

1. **一手来源优先**：官方公告 / NVD / GHSA / 厂商博客。三方公告（CERT）可用作影响面依据，
   但修复版本必须厂商复核；二手只能标「传闻」。
2. **禁止编造**：查不到就写「未确认」，不给修复步骤、不写版本号。
3. **版本号不是结论**：查版本只是第一层证据。装包 ≠ 重启 ≠ 重建镜像 ≠ 重新部署；
   有些东西没有版本号（信任库要看 SPKI、mTLS 是配置、边界设备 KEV 不含 fixed），
   所以流程里强制要求行为验证（旧凭据 401、只读 PoC 被拒、进程启动时间）。

## 明确不做什么

- 不提供漏洞利用代码、不给攻击步骤；
- 不代替资产扫描；不读取你的生产环境；
- 不保证「按本文升完就安全」——修复证明必须来自你自己的验证证据。

## 已知短板（请当缺陷清单看）

- `playbooks/10` 已 verified，但 fixed 来自五家厂商 PSIRT **逐分支/逐 hotfix 线**（Plex `1.43.3.10861` 2026-08-04 起全量（#713））；KEV 本身不含 fixed，别拿 KEV 当版本依据；
- 无自动化测试：`lint` 只做结构校验，不执行 playbook 里的命令；
- 覆盖缺口：Java(GraalVM) 无厂商修复版本（处置见 09 W4 收口：优先 `-Djavax.net.ssl.trustStore=` 指向清洗副本，次选 `keytool -delete`，GraalVM 须重编译）；Vyper 有 12 号源码闸门但 6 条仍 `partial`（无已发布修复版本）；K8s/Docker 只给配置姿势；
- 情报有时效：全部结论基于 2026-10-22 快照，过期后必须重新对一手来源。

## 已知差异（W6 最终交付口径）

v0.3.4 doc-only 以 **0 FAIL + WARN 交付**，不把 WARN 改成「已核实」。分项如下（`lint_inventory` 实跑 **88** 条 WARN）：

| 类别 | 条数 | 含义 | 处置 |
|---|---|---|---|
| E4 一手来源审计 | 46 | 部分 advisory 号在 `sources.md` 只有二手/未确认行，或新采条目的 secondary 来源待补一手 | 不入结论；随 v0.4.0 起逐条补一手（不设单独里程碑） |
| F11 front-matter 对账 | 3 | 结构性提示：`00-TEMPLATE` / `06` / `07` 本就不挂清单行（流程型文件，非漏洞条） | 非缺陷，保留 |
| F6 UNKNOWN 提示 | 34 | `affects`/`fixed` 含 `UNKNOWN` 的行（均 `partial`/`draft`，无 `verified`） | 按状态定义合规，仅提示 |
| F9 观察区提示 | 5 | `observe` 条目出现在已标注「观察项/未确认/不进结论」的区域 | 合规（R3 收窄后允许） |

**W1 遗留的 G9 别名对账已清零**：09 补 `CVE-2026-113812` / `105221` / `85086`，11 补 6 个 GHSA（`ghsa:` 字段），02/03/04 补 `aliases:`。

`lint-playbooks.sh --all`：**12 文件** 0 失败；唯一 WARN 是 `CVE-2026-111943` 同现 04/09（跨生态双写，组长红线保留，不拆）。

**E4 46 条（secondary 来源待补一手）随 v0.4.0 起逐条补一手，不设单独里程碑；F11 3 条为结构性（00/06/07 流程型文件不挂清单行），非缺陷。**

## 贡献

提 PR 前请先跑 `bash bin/lint-playbooks.sh --all`，并保证：

- 每条新结论带一手 URL，`sources.md` 建行（无 CVE 的 GHSA 也要建行）；
- 修复步骤带可执行验证命令，且写明回退方案；
- 不把「未确认」写成「已核实」。
