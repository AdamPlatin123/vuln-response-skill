# vuln-response-skill

把「收到一条 CVE / 公告 → 判断我受不受影响 → 修复 → 验证 → 留证」压成可执行流程的 Agent Skill。
不是漏洞库，是**处置流程**：每条结论带一手 URL，每个修复步骤带能直接跑的验证命令。

- 状态：`v0.1.0`，情报快照 **2026-10-21**
- 许可：Apache-2.0（见 `LICENSE`、`NOTICE`）
- 语言：中文
- 覆盖：Node/npm、Go、Python/LLM 基建、PHP、PKI/CA、通用生产修复与凭据轮换

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
| `playbooks/01-…09-` | 逐生态处置：检测 → 判定 → 修复 → 验证 → 回退 |
| `playbooks/07` | **入口件**：定档 P0–P3、六段四门、「先关服务」判断、动生产库姿势 |
| `playbooks/_draft/` | 未定稿件（不保证结论完整） |
| `evidence/` | 取证存档：OSV / cvelistV5 原始 JSON、SPKI 清单 |
| `bin/lint-playbooks.sh` | 结构校验：段缺命令块、占位符残留、CVE 未收录进 `sources.md` |
| `bin/seal.sh` | 生成 `MANIFEST.sha256` 并打印文件树/行数 |
| `bin/new-playbook.sh` | 按模板起新 playbook 草稿 |

## 用法（三条命令）

```bash
bash bin/lint-playbooks.sh --all      # 结构校验，失败项要修到 0
bash bin/seal.sh                      # 生成 MANIFEST.sha256
sha256sum -c MANIFEST.sha256          # 校验没被人改过
```

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

- `playbooks/_draft/10-boundary-devices.md` 仍是草稿：KEV 不含修复版本，五家厂商版本未逐条核实；
- 无自动化测试：`lint` 只做结构校验，不执行 playbook 里的命令；
- 覆盖缺口：.NET / Java(GraalVM) / Vyper / Ruby / Perl / K8s·Traefik 只有线索，没有已核实条目；
- 情报有时效：全部结论基于 2026-10-21 快照，过期后必须重新对一手来源。

## 贡献

提 PR 前请先跑 `bash bin/lint-playbooks.sh --all`，并保证：

- 每条新结论带一手 URL，`sources.md` 建行（无 CVE 的 GHSA 也要建行）；
- 修复步骤带可执行验证命令，且写明回退方案；
- 不把「未确认」写成「已核实」。
