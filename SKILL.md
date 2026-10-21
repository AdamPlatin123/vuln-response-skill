---
name: vuln-response
description: 互联网漏洞情报 → 检测 / 影响判定 / 修复 / 验证 的可执行流程。覆盖 Node/npm、Go、Python-LLM 基建与通用供应链投毒。触发：收到 CVE/GHSA/公告链接、问「版本 X 受影响吗」「要不要升级」「包是否被投毒」、发版前基线核查。
---

# 漏洞响应 Skill

> 包版本：`v0.4.2`（W7 最终版 · 快照 2026-10-22）。升级只换 tar + 本版本行，loader 内容不动。

## 何时用（触发条件）

命中任一条即加载：

- 用户给出 **CVE / GHSA / 厂商公告 URL**，问怎么修；
- 问「**版本 X 受不受影响**」「要不要升级」「升到哪个版本」；
- 怀疑**依赖被投毒**（postinstall 异常、锁文件漂移、陌生包名）；
- **发版/上线前基线核查**（Node/Go/Python 运行时与 LLM 网关）；
- **要动生产**（发版 / 关停 / 改库 / 轮换凭据）→ 先按 `playbooks/07-production-remediation.md` 定档位；
- 安全公告批量跟进（一次几十条，需要归并成表）。

不适用：纯情报搜集（找新漏洞）→ 那是 `漏洞侦察` 的职责；写业务功能代码 → 普通编码。

## 输入与入口

| 输入 | 第一步 |
|---|---|
| 包名 + 版本 | 直接跳到本 playbook「检测」段 |
| CVE / GHSA 编号 | 先取一手来源 → 查 `index.md` 是否已有 playbook |
| 公告 URL | 抽取 `affects` / `fixed` 区间 → 命中已有 playbook 就复用，不新建 |
| 一堆告警/表格 | 按 `index.md` 生态分组，走「归并规则」 |

## 决策树

```
输入
 │
 ├─ 输入能定位到组件吗？（组件 + 版本 + 暴露面，至少给 2 项）
 │    · 暴露面三类：对外可达（公网 / 中继）/ 仅内网 / 仅本机或 CI；未知即算缺项
 │    ├─ 不足 → 先追问缺的项（**必须列出缺哪几项**），或按 index 生态表定位；禁止直跳某个 playbook、禁止猜版本
 │    │    · 追问期间可给「若为 X 则走 NN」的条件标签；**不给修复步骤、不给版本号、不写成结论**（标签需带条件，结论需带证据）
 │    └─ 够 → 下一步
 │
 ├─ index.md 有对应 playbook？
 │    ├─ 有 → 执行 playbook（检测 → 判定 → 修复 → 验证）；若涉及生产变更（发版 / 关停 / 改库）或凭据动作 → 并行标注 07 / 06
 │    └─ 无 → 下一步
 │
 ├─ 能拿到一手来源？（NVD / GHSA / 官方公告 / 厂商博客）
 │    ├─ 能 → 按 00-TEMPLATE 新建 playbooks/NN-*.md（先 _draft/）
 │    └─ 不能 → 只输出「未确认风险」条目，禁止给修复步骤、禁止写版本号
 │
 ├─ 判定影响面：本机/仓库是否落在受影响区间？
 │    ├─ 不在 → 存证据（命令输出）→ 结束
 │    ├─ 在 + 已可利用（在野利用 / 公开 PoC）→ 紧急通道
 │    └─ 在 + 仅理论 → 常规通道（排期升级 + 验证）
 │
 ├─ 多件同时命中：排序 = P0 → 暴露面（对外可达 > 仅内网 > 仅本机/CI）→ KEV dueDate（逾期在前）→ 可利用性。
 ├─ 无对应件 / 缺版本：无件 → 归 07 定档，取到厂商版本后回 index 找件；有件但缺版本 → 有暴露面证据（公网可达 / 在野利用）按件先处置、不等版本，无暴露面证据 → 07 定档并补版本，再回件。
 │
 └─ 产出：绝对路径 + sha256 + 一句话结论
```

## 铁律

1. **一手来源优先**：官方公告 / NVD / GHSA / 厂商博客。二手报道只能标「传闻」，不得当依据。
2. **来源分四级**：一手（官方/NVD/GHSA/厂商）> 三方公告（CERT/CNVD 自撰，影响面可用、修复版本必须厂商复核）> 公开 PoC（只证明 PoC 存在）> 二手（只能标「传闻」）。
3. **禁止编造** CVE 号、版本号、链接。查不到就写「未确认」。
4. 每条结论带来源 URL；每个修复步骤带**能直接跑**的验证命令。
5. 修复必须写**回退方案**，以及「不修的话怎么缓解」。
6. 已可利用漏洞 → 先止血，再升级，再轮换密钥，最后回查日志。顺序不可颠倒。

## 紧急通道（有在野利用 / 公开 PoC）

```bash
# 1) 止血：先断暴露面，不急着改代码
#    网关/反代层拦截，示例（nginx）
#    location /chat/completions { deny all; }
# 2) 升级到 fixed 版本（见具体 playbook）
# 3) 轮换全部可能泄露的凭据：API key / DB 口令 / provider key
# 4) 回查访问日志，找攻击痕迹（时间窗 = 披露日往前 30 天）
grep -iE 'authorization:.*(\x00|%00|union|sleep\(|pg_sleep|information_schema)' access.log
```

## 通用侦测命令（不知道从哪查时先跑这三条）

```bash
# Node/npm
node -v; npm -v; npm ls --depth=0 2>/dev/null | head -40; npm audit --json | head -c 2000
# Go
go version; go list -m all 2>/dev/null | head -40; govulncheck ./...
# Python
python3 -V; pip list --format=json 2>/dev/null | head -c 2000; pip-audit 2>/dev/null | head -40
```

> `govulncheck` / `pip-audit` 不存在时先装：`go install golang.org/x/vuln/cmd/govulncheck@latest`、`pip install pip-audit`。

## 产出规范

| 项 | 规则 |
|---|---|
| 文件位置 | `playbooks/NN-<ecosystem>-<slug>.md`，NN 两位数字 |
| 先用 `_draft/` | 起草放 `playbooks/_draft/`，验收通过才移到 `playbooks/` |
| 交件必须报 | **绝对路径 + sha256**（`sha256sum <file>`） |
| 校验 | `bin/lint-playbooks.sh` 必须 exit 0 |
| 封版 | `bin/seal.sh` 生成 `MANIFEST.sha256` |

## 常用操作

```bash
cd /path/to/vuln-response-skill
bash bin/new-playbook.sh 03 go-cve-xxxx        # 从模板起稿
bash bin/lint-playbooks.sh                     # 结构校验（交件前必跑）
bash bin/seal.sh                               # 生成 sha256 清单
```

## 包怎么用（加载 / 选件 / 升级）

### 1. 加载入口

- 入口是 **`SKILL.md`**（本文件）头部 front-matter：`name: vuln-response` + `description`（触发条件）。
  客户端把整个目录当 Skill 加载后，命中触发词即进本文件；不需要联网。
- 进来先做两件事：① 按「决策树」判档；② 按 `index.md` 找件。**不要跳过 index 直接猜 playbook 编号**。

### 2. 12 份 playbook 的适用面

| 编号 | 文件 | 什么时候用 | 状态 |
|---|---|---|---|
| 01 | `playbooks/01-nodejs-security-release.md` | Node.js 运行时安全版本（Brotli/TLS/crypto 熵） | verified |
| 02 | `playbooks/02-litellm-emergency.md` | LiteLLM 网关（未认证 SQLi + 6 条认证类 + PyPI 投毒） | verified |
| 03 | `playbooks/03-npm-supply-chain.md` | npm 投毒 / 站外 tarball / 依赖混淆（`REMOVE-ONLY`） | verified |
| 04 | `playbooks/04-go-vulncheck.md` | Go stdlib、govulncheck、x/net、Coraza、Traefik K8s | verified |
| 05 | `playbooks/05-python-llm-infra.md` | vLLM / LMCache / Ollama / GitLab AI Gateway | verified |
| 06 | `playbooks/06-credential-rotation.md` | 任意凭据轮换（先加后减、双读窗口、回退） | verified |
| 07 | `playbooks/07-production-remediation.md` | **入口件**：定档 P0–P3、六段四门、动生产库姿势 | verified |
| 08 | `playbooks/08-php-runtime.md` | PHP 运行时未认证 RCE（8.5.12 / 8.4.27 / 8.3.36 / 8.2.35） | verified |
| 09 | `playbooks/09-pki-ca-rollover.md` | eMudhra 中间 CA 弱密钥 / 五套信任库（含 Ruby gist、Perl Thrift） | verified（**W4 收口**：Debian 三线全有版本——trixie `20250419+deb13u1`（DSA-6572-1）、bookworm-security `20250419~deb12u2`、unstable/testing `20260816+nmu1`；Java cacerts 分两条路——发行版 JDK 随 OS 包修（以 `keytool -list -cacerts` 实际路径为准），Oracle JDK 无厂商版本 → 优先 `-Djavax.net.ssl.trustStore=` 指向清洗副本，次选 `keytool -delete`；.NET 随 OS/基础镜像更新） |
| 10 | `playbooks/10-boundary-devices.md` | KEV 在野利用簇：边界/媒体设备 9 条（逐分支 fixed 已按厂商公告核） | verified |
| 11 | `playbooks/11-dotnet-runtime.md` | .NET / ASP.NET Core 6 条（Kestrel 走私 9.4 领衔） | verified |
| 12 | `playbooks/12-vyper-source-gate.md` | Vyper 6 条 GHSA：**无已发布修复版本** → 源码闸门（非 ASCII 标识符 / 8 种行分隔符 / `msg.value \|` 折叠 / 导入常量与默认参数名 / `create_from_blueprint` 偏移）；不给升级命令 | verified（闸门≠修复版本） |

> `10` 已转 `verified`（fixed 来自五家厂商 PSIRT，逐分支；Plex `1.43.3.10861` 2026-08-04 起全量（#713））。`playbooks/_draft/` 现为空，包内不再有草稿区。

### 3. 升级流程（换新快照）

1. **什么时候换**：情报过期（当前快照日见 `README.md` 首屏）、或新 CVE/KEV 命中你资产时。
2. **换之前先校验旧包**：`sha256sum -c MANIFEST.sha256`（全绿才说明包没被改过）。
3. **改内容**：`playbooks/_draft/` 起草 → `bash bin/lint-playbooks.sh --all` exit 0 → 移入 `playbooks/`。
4. **封版**：`bash bin/seal.sh` 一次 → `sha256sum -c MANIFEST.sha256` 全绿 → 报 `MANIFEST sha256 + 文件数 + 行数`。
5. **清单表**：`inventory.tsv` 是机器可读快照，改完要重跑 `bash bin/lint-playbooks.sh --inventory`
   （工作区版还需 `../vuln-w1/check_inventory.py` 作基线门；包内只跑 playbook 结构校验）。

### 4. evidence 怎么用

- `evidence/` 是**取证存档**，只证明「某天我从一手源抓到的原文」，不替代结论。
- 引用方式：`sources.md` 的 S 号 → 对应 evidence 文件；`inventory.tsv` 的 `evidence_ref` 指向具体文件或 `sources.md#Sxxx`。
- 复核时**重抓比对**：URL 在 `sources.md` 行内，命令块见 `evidence/README.md`。
- 证据会过期：同一 URL 内容可能被厂商改版，重抓后不一致就以新抓的为准并更新 S 行「核实状态」。

## 已知生态与 playbook 索引

见 [index.md](index.md)；一手来源清单见 [sources.md](sources.md)。
