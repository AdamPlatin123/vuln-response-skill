# 索引 · 漏洞响应 Skill

> 用法：先按**生态**找 playbook，再按 **CVE 编号**定位到具体条目。
> 状态：`定稿 verified` = 已通过 `bin/lint-playbooks.sh --all` 且在 `playbooks/`；`草稿` = 在 `playbooks/_draft/`。
> 来源行号统一编号 `Sxxx`，对应 [sources.md](sources.md)。
> **编号已定死**（2026-10-21 最终版，Chief 亲手落刀）：`07` 生产修复编排（**入口件，先读它**）、`08` PHP、`09` PKI/CA、`10` 边界设备（**定稿 verified**，五家厂商 fixed 逐分支）；`01–06` 为漏洞件，不复用、不重排。

## 1. 按生态

| 生态 | 说明 | playbook | 状态 |
|---|---|---|---|
| Node.js 运行时 | 官方安全版本升级；Brotli RCE / TLS 绕过 / crypto 熵缓存 | [`01-nodejs-security-release.md`](playbooks/01-nodejs-security-release.md) | **定稿 verified**（公告无 CVSS，结论写「官方未给」） |
| Python / LLM 基建 | LiteLLM 网关：未认证 SQLi（KEV）+ 6 条认证类 + PyPI 投毒事故 | [`02-litellm-emergency.md`](playbooks/02-litellm-emergency.md) | **定稿 verified** |
| npm 供应链 | postinstall 投毒、站外 tarball、依赖混淆 | [`03-npm-supply-chain.md`](playbooks/03-npm-supply-chain.md) | **定稿 verified**（无 CVE，用 MAL 编号） |
| Go | stdlib HTTP/2、`govulncheck`、x/net、Coraza WAF | [`04-go-vulncheck.md`](playbooks/04-go-vulncheck.md) | **定稿 verified** |
| Python / LLM 基建（通用） | vLLM / LMCache / Ollama / GitLab AI Gateway | [`05-python-llm-infra.md`](playbooks/05-python-llm-infra.md) | **定稿 verified** |
| 通用 · 生产修复编排（**入口件**） | 定档 P0–P3、三种处置模式、动生产库红线、时间轴 | [`07-production-remediation.md`](playbooks/07-production-remediation.md) | **定稿 verified** |
| 通用 · 密钥轮换 | 凭据轮换清单、先加后减、双读窗口、验证、回退 | [`06-credential-rotation.md`](playbooks/06-credential-rotation.md) | **定稿 verified** |
| PHP 运行时 | 2 条未认证 RCE，修复 `8.5.12` / `8.4.27` / `8.3.36` / `8.2.35` | [`08-php-runtime.md`](playbooks/08-php-runtime.md) | **定稿 verified** |
| PKI / CA | eMudhra 8 张中间 CA 私钥被攻破（跨生态，改 01/04 结论） | [`09-pki-ca-rollover.md`](playbooks/09-pki-ca-rollover.md) | **定稿 verified** |
| 边界 / 媒体设备 | KEV 在野利用簇：SiteGuard / Plex / Siemens / PAN-OS / FortiMail（9 条，逐分支 fixed 已按厂商公告核） | [`10-boundary-devices.md`](playbooks/10-boundary-devices.md) | **定稿 verified**（S416–S421 五家厂商一手） |
| .NET / ASP.NET Core | Kestrel HTTP/1 请求走私（CVSS 9.4）领衔 6 条；修 `8.0.32` / `9.0.21` / `10.0.13` / `11.0.0-rc.2` | [`11-dotnet-runtime.md`](playbooks/11-dotnet-runtime.md) | **定稿 verified**（MSRC + GHSA 一手，S404–S409） |
| Vyper 源码闸门 | 6 条 GHSA：**无已发布修复版本** → 只能改源码 + 阻断发布（非 ASCII 标识符 / 8 种行分隔符 / `msg.value \|` 三元折叠 / 导入常量与默认参数名 / `create_from_blueprint` 偏移） | [`12-vyper-source-gate.md`](playbooks/12-vyper-source-gate.md) | **定稿 verified**（闸门≠修复版本，不给升级命令） |

## 2. 按 CVE 定位

### 2.1 LiteLLM（playbook 02 · 定稿，7 条 + 1 起投毒事故）

| 编号 | 缺陷 | 认证前提 | 受影响 | 修复 | 来源 | 状态 |
|---|---|---|---|---|---|---|
| CVE-2026-42208 | 未认证 SQL 注入，CWE-89，**CVSS 9.8** | **无** | `>=1.81.16 <1.83.7` | `1.83.7` | S003 / S004 / S005（KEV） / S009（PoC） | 一手 |
| CVE-2026-35029 | `/config/update` 无角色校验 → RCE / 任意文件读 / 接管 admin | 有效 key | `<1.83.0` | `1.83.0` | S309 | 一手 |
| CVE-2026-35030 | OIDC userinfo 缓存键碰撞（`token[:20]`）→ 认证绕过 | 开 `enable_jwt_auth`（默认关） | `<1.83.0` | `1.83.0` | S310 | 一手 |
| GHSA-69x8-hrgq-fjj8 | 密码哈希泄露 + pass-the-hash（**无 CVE**） | 认证 | `<1.83.0` | `1.83.0` | S316 | 一手 |
| CVE-2026-59823 | `user_config` 嵌套 `api_base` → SSRF | 有效 virtual key | `<1.83.9` | `1.83.9` | S311 | 一手 |
| CVE-2026-84377 | 已认证 SSRF + **provider 凭据外泄** | 认证（`PR:L`） | `<1.88.6`；1.89–1.96 共 **9 条分支**（见下表，**不是双分支**） | 分支表 | S312 | 一手 |
| PyPI 投毒（非 CVE） | `litellm==1.82.7` / `1.82.8` 凭据窃取器 | — | 2026-03-24 **10:39–16:00 UTC** 窗口内安装 | 最低 `1.83.0`；两版已下架 | S313 | 一手 |
| Check Point 研究 | 网关攻击面综述 | — | 2026-10-13 | — | S314 | **正文未抓，暂不入结论** |

**CVE-2026-84377 分支修复表**（OSV 原文）：`<1.89`→`1.88.6`｜`1.89.x`→`1.89.7`｜`1.90.x`→`1.90.7`｜`1.91.x`→`1.91.5`｜`1.92.x`→`1.92.2`｜`1.93.x`→`1.93.2`｜`1.94.x`→`1.94.3`｜`1.95.x`→`1.95.1`｜`1.96.x`→`1.96.2`。

> **观察项（不入结论）**：`GHSA-7hp6-4w63-5g45`（salt key 伪造 admin → RCE）、`GHSA-g5ff…`（viewer LFI）——前者 OSV 实查 **404**、后者 ID 不完整，均待侦察补；Check Point 原文未抓（S314）。**别把它们写成「已确认」**。

> **三个禁止**：① `1.83.9` 只覆盖 42208/35xxx/59823 这条线，**不是总修复线**；② 禁止全局 semver 比较（分支回移，PyPI 最新 1.106.2）；③ 带 `.pth` 的 1.82.7/1.82.8 环境**不能用它自己的 python/pip 自查**——可信环境只读盘点 + 重建 + 吊销。

### 2.2 Node.js（playbook 01 · 定稿）

公告日 2026-10-21，修复 `22.23.4` / `24.22.1` / `26.12.1`；**官方公告只给 HIGH/MEDIUM/LOW 标签，未给 CVSS**。

| CVE | 级别 | 影响线 | 缺陷 | 触发前提 | 来源 | 状态 |
|---|---|---|---|---|---|---|
| CVE-2026-111497 | 高 | 22/24/26 | Brotli 解码越界写 → 可 RCE | 对不可信数据解 br | S006 | 一手，无 CVSS |
| CVE-2026-105482 | 高 | 22/24/26 | `dns.resolve` NUL 截断 | 用户可控主机名 | S006 | 一手，无 CVSS |
| CVE-2026-105483 | 高 | **24/26 only** | 全角数字 IP 绕过 TLS 主机名校验 | 出站 TLS + 中间人 | S006 | 一手，无 CVSS |
| CVE-2026-106069 | 高 | 22/24/26 | 松散解析 IP 绕过校验 | 可控 DNS | S006 | 一手，无 CVSS |
| CVE-2026-105481 | 中 | 22/24/26 | keep-alive 乱序响应处理 | 内网乱序注入 | S006 | 一手，无 CVSS |
| CVE-2026-106072 | 中 | 22/24/26 | 非规范 IPv4 主机名校验 | IP 字面量 + 中间人 | S006 | 一手，无 CVSS |
| CVE-2026-106074 | 中 | 22/24/26 | `randomUUID/randomInt` 熵缓存写入 snapshot/SEA | **仅 SEA / `--build-snapshot`** | S006 | 一手，无 CVSS |
| CVE-2026-106073 | 低 | 22/24/26 | Permission Model 被 `fs.realpathSync` 绕过 | 已用 `--permission` | S006 | 一手，无 CVSS |
| CVE-2026-106070 | 低 | **26 only** | ZipFile 头校验失败返回可控前缀 | 解析不可信 ZIP | S006 | 一手，无 CVSS |
| CVE-2026-106071 | 低 | **26 only** | Permission Model 通配符越权 | `--permission` + 通配符 | S006 | 一手，无 CVSS |

> 两条容易抄错的：`CVE-2026-105483` **22.x 不中**；`CVE-2026-106074` **普通 `node app.js` 不中**。

### 2.3 Go（playbook 04 · 定稿）

`govulncheck` 是唯一可信的「我用没用」判定入口；OSV 四条均**未给 CVSS**，「高危」是定性表述。

**2026-10-08 批次共 15 项，统一修复线 `1.26.9` / `1.27.2` + `x/net 0.60.0`**：本表逐条收录 8 个 GO ID（`6599/6602/6608/6609/6610/6611/6668/6809`），其余同批不逐条建行——**判定交给 `govulncheck`，别背 CVE 列表**。

| CVE / OSV | 组件 | 影响区间 | 修复 | 来源 | 状态 |
|---|---|---|---|---|---|
| CVE-2026-78660 / GO-2026-6610 | net/http（HTTP/2 响应走私） | `<1.26.9`、`1.27.0–<1.27.2`、`x/net <0.60.0` | `1.26.9` / `1.27.2` / `x/net v0.60.0` | S100 | 一手已核实 |
| CVE-2026-78669 / GO-2026-6611 | net/http（HTTP/2 初始窗口洪泛 → CPU DoS） | 同上 | 同上 | S101 | 一手已核实 |
| CVE-2026-111943 / GO-2026-6809 | crypto/x509（停止信任 eMudhra 中间 CA） | `<1.26.10`、`1.27.0–<1.27.3` | `1.26.10` / `1.27.3` | S102 | 一手已核实 |
| CVE-2026-41510 / GO-2026-6668 | Coraza WAF（参数洪泛绕过规则） | `coraza/v3 v3.0.0–<3.8.1` | `v3.8.1` | S103 | 一手已核实 |

> 跨生态同一根因：`CVE-2026-111943`（Go）与 Node 的 ca-cert 更新是**同一个 eMudhra 中间 CA 被攻破事件**，两边都要查系统信任库，不是只升运行时。

### 2.4 npm 供应链（playbook 03 · 定稿）

恶意包**没有「安全版本」**，只有「移除 + 回滚锁文件 + 轮换凭据 + 查持久化」；用 OSV `MAL-*` 编号而非 CVE。

| 包 | 恶意版本 | 手法 | 处置 | 来源 | 状态 |
|---|---|---|---|---|---|
| `tensorlake` | `0.5.144` | preinstall 窃取 npm/GitHub/AWS/K8s/Vault/SSH/.env；写 `.claude`/`.vscode` 持久化 | 移除 + 全量轮换 | S205 | 一手已核实 |
| `@library-wide/library-shell` | `99.9.1` | 依赖指向站外 tarball，无哈希无锁版本 | 移除 + 锁 registry | S201 | 一手已核实 |
| `kmf-vendor-pack` | `99.0.0` / `100.100.x` | 依赖混淆，postinstall 外泄主机信息到裸 IP | 移除 + 查外联 | S202 | 一手已核实 |
| `sc-announcer` | `99.9.1` | 与恶意域通信 | 移除 + 查外联 | S203 | 一手已核实 |

> `tensorlake` 事件的时间线仍只有二手（S204，ThaiCERT 转述）；一手是 OSV `MAL-2026-17650`（含 GHSA-rqxj-g25x-4v9v）。 `tensorlake@0.5.144` **已下架**；`MAL-2026-17754` 别名 `GHSA-8j36-pr5c-f6vx`。 tensorlake 现在有**三重一手**：S205（OSV）、S206（Socket.dev）、S207（Sonatype）。

### 2.5 Python / LLM 基建（playbook 05 · 定稿）

| CVE | 组件 | 影响区间 | 修复 | 来源 | 状态 |
|---|---|---|---|---|---|
| CVE-2026-90553 | vLLM（LlavaOnevision2 loader，可绕过 `trust_remote_code=False`） | `<0.28.0` | `0.28.0` | S301 | 一手 |
| CVE-2026-105192 | LMCache（ZMQ 未认证 pickle RCE） | `0.3.9–0.5.5`（含 `0.5.6rc`） | `0.5.6` | S304 | 一手 |
| CVE-2026-105752 | vLLM（跨租户前缀缓存泄露，low） | `≤0.25.1` | `0.30.0` | S302 | 一手 |
| CVE-2026-103663 | Ollama（`/api/pull` 路径穿越 → root RCE） | `>=0.34.2 <0.35.0`（cvelistV5 原文） | `0.35.0` | S305 / S315 | **一手（CNA 记录）**；条件 CVSS：默认 root **9.4** / 无写权限 **6.9**；SSVC `Exploitation: none`（未在野利用）；Ollama release note 静默 |
| CVE-2026-90970 | GitLab **Self-Hosted** AI Gateway（模板沙箱逃逸 → 命令执行） | `18.1.6–<19.2.4` / `19.3.0–<19.3.2` / `19.4.0–<19.4.1` | `19.2.4` / `19.3.2` / `19.4.1` | S308 | **一手（GitLab 官方）**；**CVSS 9.9 但 `PR:L` 需认证**；GitLab.com/Dedicated 不受影响 |

**CVSS（有分的一手才写）**：vLLM `CVE-2026-90553` **7.8**（3.1）/ **8.5**（4.0）；LMCache `CVE-2026-105192` **9.8**；GitLab `CVE-2026-90970` **9.9**（一手，`PR:L`）；Ollama 条件分 9.4 / 6.9（CNA 记录）。

> **观察项（未进 05 的 cve 列表）**：`CVE-2026-105775` vLLM mamba_mixer2——issue #57266 是普通崩溃 bug（越界 slice 杀 EngineCore），无 GHSA、无修复 commit，不写升级命令。

> `CVE-2026-114053`（AutoProcessor RCE）、`CVE-2026-105754` 只有二手候选，**未核实到官方 GHSA，不进结论**。

> cert.pl：CERT Polska 是 `CVE-2026-103663` 的 **CNA（CVE 分配方）**，其公告属 CVE 官方记录，记「一手」。但 Ollama 自己的 release note 未提该 CVE——**「CNA 记录了修复版本」≠「厂商声明确认」**，两件事分开写。

### 2.6 PHP 运行时（playbook 08 · 定稿）

| 分支 | 受影响 | 修复 |
|---|---|---|
| 8.5.x | `<8.5.12` | `8.5.12` |
| 8.4.x | `<8.4.27` | `8.4.27` |
| 8.3.x | `<8.3.36` | `8.3.36` |
| 8.2.x | `<8.2.35` | `8.2.35` |
| 8.1 及更早 | 全部 | **无补丁**（已过安全维护）→ 升分支 |

| CVE | 缺陷 | 来源 | 状态 |
|---|---|---|---|
| CVE-2026-109618 | RCE via OOM corruption | S400 / S402 | 一手 |
| CVE-2026-109619 | RCE via stale state（UAF） | S400 / S403 | 一手 |

> 关键事实：`mod_php` **未认证、默认配置即可 RCE**，FPM 经应用层路径也能 RCE；**CVSS 实为 9.2**（网传 10.0 是错的）；发布时**未确认在野利用**；8.1 无补丁；Chainguard 提前破 embargo（07:41 UTC）。CLI 与 web SAPI 是不同二进制，检测要分别查。

### 2.7 PKI / CA（playbook 09 · 定稿）

**同一事件横跨五套信任库**：8 把 eMudhra 中间 CA 私钥被攻破（P384 私钥小于 256 的整数），可伪造 HTTPS 证书做中间人。**只升运行时修不掉系统信任库**。

| 编号 | 覆盖对象 | 修复 |
|---|---|---|
| CVE-2026-111943 | Go / Rust 生态与 Node 内置 CA | Go `1.26.10` / `1.27.3`；`webpki-roots 1.0.10`；`rustls-webpki 0.103.16` / `0.104.0-alpha.8`；`webpki-root-certs 1.0.10`；Node `22.23.4` / `24.22.1` / `26.12.1` |
| CVE-2026-113470 | Firefox / NSS OneCRL | Firefox `158.0.1`；ESR `115.43.1` / `153.5.1`；Android `158.0.2`；NSS `3.131.1` |

> 来源 S501–S507（Mozilla 博客、MFSA 2026-111、RUSTSEC-2026-0381/0382/0383、Bugzilla 2083449）。**W3 收口口径见下。**
>
> **三套信任库收口（W3）**：Debian ca-certificates **已确认**——stable/trixie `20250419+deb13u1`（DSA-6572-1，2026-10-20）、unstable/testing `20260816+nmu1`（NMU 2026-10-20，changelog 明写黑名单 `emSign ECC Root CA - G3` + `Comodo AAA Services root`），**bookworm 未确认**；Java cacerts **无厂商修复版本**（Oracle CPU 0 命中、OpenJDK master 仍含 3 张 emSign 根）→ 处置为手工 `keytool -delete` 或指向清洗后 trustStore；.NET **无独立处置版本**，随 OS/基础镜像 trust store 更新。
>
> **状态口径（组长裁定 2026-10-22，W3 更新）**：09 保持 `verified`。漏洞条目的 `fixed` 由 SPKI 移除信任确定；上列**Java cacerts / .NET 无厂商修复版本、Debian bookworm 未确认属执行侧子项缺口**，不因此降 `partial`——引用时必须带上这句限定。

- **SPKI 检测锚点**：3 根 + 8 张中间 CA 的 SPKI SHA-256 全表在 `evidence/spki-emudhra-2026-10-21.md`（源 = oss-security 一手）。Sectigo 交叉签名同 SPKI → **检测只认 SPKI，不看签发路径**。
- **归并口径**：同一 `CVE-2026-111943` 在 09 按**信任库分行承载**（生态级修复见 04，信任库级处置见 09）；`inventory.tsv` 的「一 CVE 一行」不套用到本表——各承载物不同、处置不同，合并会丢处置差异。**跨生态/跨信任库允许分行。**
- **RUSTSEC-2026-0381 / 0382 / 0383 与 `GO-2026-6809` 是同一个 `CVE-2026-111943`**（Go + Rust 同一根因），**09** 已按一行归档，**别拆三条**。
- 根因口径：是**弱密钥**（KGC 生成脚本缺陷，出现 1 字节私钥 / 连续整数 155、156 这类 P384），不是普通「私钥被窃」。**09 标题已改为「eMudhra 中间 CA 弱密钥（P384 私钥可秒级恢复）」——本条已闭环**（见 G16）。

### 2.8 边界 / 媒体设备（playbook 10 · 定稿）

KEV 收录 = **已被利用**，不是「有补丁待升级」。全部 9 条已用 KEV JSON 实抓核对（catalogVersion `2026.10.21`，count 1754）：

逐分支 fixed（厂商公告原文，Plex `1.43.3.10861` / FortiMail `8.0.2`·`7.6.7`·`7.4.9` / SiteGuard `8.00U5`·`7.00U6` / Siemens `V4.0.9.8` / PAN-OS 逐分支）见 playbook 10 §适用版本区间与 §修复。

| CVE | 产品 | KEV 原文要点 | added / due |
|---|---|---|---|
| CVE-2026-106931 | SiteGuard Server Edition | OS 命令注入（KEV 原文：可执行任意 OS 命令，**root 或 SYSTEM** 权限） | 10-20 / 10-23 |
| CVE-2026-96652 | Plex Media Server | SSRF（**任意 `X-Plex-Token` 值即可**） | 10-20 / 11-03 |
| CVE-2026-96654 | Plex Media Server | 编码 URI scheme 未中和 | 10-20 / 10-23 |
| CVE-2026-96655 | Plex Media Server | SSRF（已认证用户） | 10-20 / 11-03 |
| CVE-2026-96656 | Plex Media Server | 文件名/路径外部控制 → 写任意文件 | 10-20 / 10-23 |
| CVE-2026-110936 | Siemens Software Center | 不受控搜索路径（本地已认证 → ACE） | 10-20 / 11-03 |
| CVE-2026-0322 | PAN-OS | 代码注入（**已认证 + 网络访问**） | 10-14 / 10-17（已过） |
| CVE-2026-0257 | PAN-OS | **认证绕过**；**5 月批，不是 10 月批** | 05-29 / 06-01（已过） |
| CVE-2026-104286 | FortiMail | 路径穿越 + NULL 字节，**未认证** | 10-01 / 10-04（已过） |

> **两条纪律**：① KEV **不含 fixed 字段**——本节的 fixed 全部来自厂商 PSIRT 一手（Plex 论坛公告 / FortiGuard FG-IR-26-175 / JVN / Siemens SSA-580366 / PAN-OS security advisories，S416–S421），**不挂 KEV 名下**；Plex `1.43.3.10861` 目前只在 Plex Pass Beta 通道，稳定通道待核。② `CVE-2026-0257`（认证绕过）与 `CVE-2026-0322`（代码注入）是**两个不同 CVE、两个批次**，别合并。


> **watchlist（不进主表、不进 `inventory.tsv`）**：`CVE-2026-0300`（PAN-OS 越界写，出 W1 窗口，W2 再采）。
## 3. 按场景

| 你在干什么 | 从这里开始 |
|---|---|
| 收到一条 CVE，不知道怎么修 | `SKILL.md` 决策树 → 本索引第 2 节 |
| Node 服务要发版，先做基线 | 01 的「检测」段（版本线 + SEA 分流 + 系统 CA） |
| LLM 网关（LiteLLM）暴露过公网 | 02 的「修复」段：4.1 止血 → 4.2 升级 → 4.3 轮换 → 4.4 取证 |
| 担心依赖被投毒 | 03 的「检测」段：锁文件站外 tarball + postinstall 面 + `osv-scanner` |
| 凭据可能已泄露、要轮换 | 06 的「修复」段：先加后减、双读窗口、引用计数归零才算完 |
| 有 Go 服务要过 CI | 04 的「检测」段：`govulncheck` + 工具链/依赖/x-net/Coraza |
| 自建 LLM 推理/网关（vLLM/Ollama/LMCache） | 05 的「检测」段：端口暴露面 + 版本 + 是否 root |
| **要动生产**（发版 / 关停 / 改库 / 轮换） | **07 的「影响判定 + 修复」段**（入口件）：先定档位 P0–P3，再选隔离/断流/变更窗口模式；六段四门 P1–P6 + G1–G4 |

## 4. 归并规则（新增条目先读）

1. **同类归一份**：同类漏洞只维护一份通用 playbook；具体 CVE 作为条目表附在末尾 `## 条目` 段。
2. **单点单独立**：修复步骤与通用版差别大（如 LiteLLM 需全量密钥轮换）就单独立。
3. **上限**：同一生态超过 8 条 CVE 必须提炼通用段。
4. **去重键**：`ecosystem + 漏洞类型`；重复以一手来源为准，另一条标「重复，见 NN」。
5. 每条条目回填 `sources.md`，两处双向引用（lint 会查 CVE 是否在 sources.md）。

## 5. 交付看板

| 文件 | 负责人 | 状态 |
|---|---|---|
| `SKILL.md` / `index.md` / `sources.md` / `playbooks/00-TEMPLATE.md` / `playbooks/README.md` | Skill工坊 | 定稿 |
| `bin/lint-playbooks.sh` / `bin/new-playbook.sh` / `bin/seal.sh` | Skill工坊 | 定稿 |
| `playbooks/02-litellm-emergency.md` | 修复策略 | **verified**，已归并（编号 5.x→4.x） |
| `playbooks/01-nodejs-security-release.md` | 修复策略 | **verified**，已移出 `_draft/` |
| `playbooks/04-go-vulncheck.md` | 漏洞侦察 | **verified**，已补 S100–S103 并归并 |
| `playbooks/03-npm-supply-chain.md` | 漏洞侦察 | **verified**；tensorlake 一手已补 S205 |
| `playbooks/05-python-llm-infra.md` | 修复策略 | **verified**，已移出 `_draft/`（Ollama 区间改 `>=0.34.2 <0.35.0`） |
| `playbooks/07-production-remediation.md` | 修复策略 | **verified**，入口件（内存/连接取证、failover、双读窗口、四种修复状态已补） |
| `playbooks/08-php-runtime.md` | 修复策略 | **verified**，两条 CVE 一手齐（S400–S403） |
| `playbooks/09-pki-ca-rollover.md` | 修复策略 | **verified**（S501–S507 + SPKI 锚点） |
| `ingest/2026-10-21/`（4 件） | Chief → Skill工坊 | 原件已归档，**编号未入表**，等侦察回件 |
| `playbooks/06-credential-rotation.md` | 修复策略 | **verified**，凭据轮换流程（覆盖 02/03 的轮换清单） |

## 6. 未闭环清单（写报告时必须带上）

| # | 项 | 阻塞点 | 归属 |
|---|---|---|---|
| G1 | 01 的 NVD/GHSA 分数 | 已不阻塞：01 按「官方公告未给 CVSS」转 verified；若 NVD 后续出分，回填 `severity` 与条目表 | 漏洞侦察 |
| G2 | 02 容器修复 | ghcr tag 匿名拉取受限，未核实具体镜像 tag；升级必须以**容器内** `pip show litellm` 为准 | 修复策略 |
| G3 | 02 `LITELLM_SALT_KEY` 轮换 | 换 salt 后 provider key 需重录，官方迁移步骤未核实 | 修复策略 |
| G4 | 02 只用 SDK 是否命中 | 待验证「SDK 直连无同等拼接查询」 | 修复策略 |
| G5 | 01 SEA 验证闭环 | 需应用自建 `/health/random` 探针才能验证 snapshot/SEA 产物 | 修复策略 |
| G6 | ~~05 转 verified~~ | **已闭环**：05 已 verified；Ollama 走 CNA 记录 + 区间 `>=0.34.2 <0.35.0`，措辞保留「厂商静默」 | — |
| G7 | eMudhra CA 事件一手 | Node 与 Go 都只有各生态「停止信任」公告，CA 侧一手未收录；对外只能写「各生态公告表述」 | 漏洞侦察 |
| G8 | ~~vLLM `CVE-2026-105775` 归属~~ | **已闭环**：已从 05 的 cve 列表移出，转入「观察项」 | — |
| G9 | ~~06 密钥轮换 playbook~~ | **已闭环**：06 已 verified（先加后减 / 双读窗口 / 数字触发器） | — |
| G10 | Sysdig LiteLLM 披露博客 | 「披露日 2026-04-30」仍无链接；02 在补 URL 前不得写该日期 | 漏洞侦察 |
| G11 | ~~05 的 GitLab 判定降级~~ | **已闭环**：05 已改「Self-Hosted + PR:L 需认证 + GitLab.com 不受影响」 | — |
| G12 | ~~`S305` 的 CNA 证据要可点开~~ | **已闭环**：S315 = cvelistV5 原始 JSON（实抓存档，`assignerShortName` = CERT-PL） | — |
| G13 | GPT 情报集吸收（分批） | **D1 已吸收**：LiteLLM 6 条 + PyPI 事故 → S309–S316，02 扩成 7 条 + 分支表。**未吸收**：eMudhra CA 两份厂商公告、PHP 2 条、Go 15 项、在野利用簇 5 家 | 漏洞侦察 → Skill工坊 |
| G14 | Check Point 研究正文（S314） | 只登记了 URL，正文未抓；引用了也没法核 | 漏洞侦察 |
| G15 | 内核 `c6e50df8` 映射 | 8 位缩写**无法唯一映射**到 CVE（已查 10 月内核 CVE 与修复 commit 均不符）→ 标「未确认」，别拿 commit 猜 | 漏洞侦察 |
| G16 | ~~09 标题与根因措辞~~ | **已闭环**：09 标题已改为「eMudhra 中间 CA 弱密钥（P384 私钥可秒级恢复）」，正文结论未动 | — |

## 7. 传闻区（二手/未确认，**不作结论**，只登记跟进）

| 内容 | 类型 | 来源 | 处理 |
|---|---|---|---|
| PoeLLM 僵尸网络：声称感染 3,400+ 暴露 Ollama/vLLM，C2 藏 GitHub 诗 | 二手 | S900（SystemTwo） | 不入结论；先核实感染面 |
| TOPHIT：单操作者 npm 抢注洪泛 + GPU 挖矿 C2 | 二手 | S902（CloudSEK） | 不入结论；可作 03 的风险背景 |
| vLLM 0.31.0 批量「RCE」修复 | 二手 | S901（LinuxSecurity） | 候选 CVE-2026-114053 / 105754 未核实到官方 GHSA，压后处理 |

## 8. 按架构自查（多栈生产环境 · 本次场景）

> 来源：`vuln-ingest/2026-10-21-arch-scenario-map.md`（73 行）。状态两档：**已核实** = 本队一手复核过；**待核实** = 在侦察队列，**只给查法不给命令级结论**。

| 层 | 命中 | 动作 | 状态 |
|---|---|---|---|
| nginx 反代 | 无自身 CVE | 入口层，同时是**断流工具**：拒 `Content-Encoding: br`、拒受影响路径 | — |
| **HTTPS 证书（eMudhra/emSign）** | INC-EMUDHRA-202610 | 根因是**弱密钥**（KGC 生成脚本缺陷）；① 换 CA 重签全部对外证书 ② 各 trust store 移除 ③ SPKI 自查 | 已核实（S501–S507） |
| Node 24.x Brotli 网关 | CVE-2026-111497 | 公网 + 不可信压缩体 = 最急；先 nginx 拦 br 再升 `24.22.1` | 已核实（S006） |
| Go 微服务 | CVE-2026-111943 + 10-08 批次 | **信任库随二进制走，升 `go` 命令没用**：用 `1.26.10`/`1.27.3` 工具链重编译；x/net `0.60.0` | 已核实（S100–S103） |
| Java GraalVM | 无本队条目 | `cacerts` 独立于系统；**native image 把 trust store 烤进二进制**，必须重建 | 待核实（缺口） |
| Rust TLS 校验层 | RUSTSEC-2026-0381/0382/0383 | 根证书**编译进二进制**，升级后重编译 | 已核实（S502–S504） |
| Python + LiteLLM 1.107.0 | 5 条 CVE，修复线上限 `1.96.2` | `1.107.0` 高于全部修复线，版本大概率没事；**但 venv 的 `certifi` 要单独换**；逐条对 02 §0 矩阵 | 已核实（S309–S313） |
| CI（昨晚拉新包） | PyPI 1.82.7/1.82.8 投毒（历史） | 冻结 CI → 锁文件 diff → `.pth` 扫描 → 可疑环境**别用它自己的 python/pip 自查** | 已核实（S313） |
| Vyper + Docker/K8s/Traefik（mTLS **fail-open**） | **Traefik 已并入 04**（CVE-2026-112778，修 `2.11.46` / `3.6.17` / `3.7.1`）；**Vyper 6 条挂 12（源码闸门，状态维持 `partial`——闸门≠修复版本）**；**fail-open 本身是配置缺陷** | 改 `requireAndVerifyClientCert`（fail-closed），不依赖任何 CVE；Vyper 按 12 的闸门跑 CI | 已核实（S108 / S422–S431）；Vyper 无修复版本 |
| PHP 8.1 主站 | 7 号件（`CVE-2026-109618/109619`） | 8.1 **无补丁** → 升在维护分支（8.2/8.3）；查 FPM/Apache SAPI 而非 CLI | 已核实（S400–S403，见 07） |
| Linux 内核（`c6e50df8` 之前） | KEV 三条 + 研究性 CVE-2026-99999 | `c6e50df8` 是占位，**必须先映射到 CVE**；容器共享宿主内核，重启才生效 | 待核实 |
| Ruby / Perl | gist（CVE-2026-105221，修 `6.1.0`）、Thrift perl（CVE-2026-85086，修 `0.25.0`）已并入 **09** | 走 OpenSSL 系统 trust store；Perl 查 `IO::Socket::SSL` 是否关 `verify` | 已核实（S410 / S411） |
| ASP.NET Core / .NET（宿主） | **11 号件** 6 条（Kestrel 走私 9.4 等） | 先对版本：`8.0.32` / `9.0.21` / `10.0.13` / `11.0.0-rc.2`；宿主面板不暴露公网、最小权限 | 已核实（S404–S409） |

**P0 顺序（小时级）**：eMudhra 证书链 → Node Brotli → CI 供应链 → Traefik fail-closed。
**P1（天级）**：Go/Rust 重编译、Java cacerts + native image 重建、PHP 升分支、LiteLLM 逐条对、镜像 digest 固定（按 07）。
**P2（周级）**：内核映射后重启窗口、Perl/Ruby/ASP.NET 收容。

```bash
# 证书链每一跳都要看
openssl s_client -connect host:443 -servername host </dev/null 2>/dev/null \
  | openssl crl2pkcs7 -nocrl | openssl pkcs7 -print_certs -noout | grep -iE 'emSign|eMudhra'
# SPKI SHA-256，对 oss-security 清单
openssl s_client -connect host:443 </dev/null 2>/dev/null \
  | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256
# 五套 trust store 普查，别只查浏览器
grep -c 'BEGIN CERT' /etc/ssl/certs/ca-certificates.crt
python -c "import certifi;print(certifi.where())"
"$JAVA_HOME"/bin/keytool -list -cacerts -storepass changeit | grep -iE 'emSign|eMudhra'
node -e "console.log(require('tls').rootCertificates.length)"
# Traefik 是否 fail-open
kubectl get tlsoptions.traefik.io -o yaml | grep -n 'clientAuth\|requireAndVerifyClientCert'
# CI 侧
find .venv/lib -name '*.pth' -newermt '-3 days'; grep -R 'models.litellm.cloud' -n .venv || true
```

**仍覆盖不到（缺口，别假装有）**：Java/GraalVM（Oracle CPU 原文 0 命中，处置见 09 W3 收口）；Docker/K8s 只给配置姿势（mTLS fail-open、最小权限），无 CVE 条目。**已收口**：.NET → `11`（S404–S409）、Traefik → `04`（S108）、Ruby/Perl → `09`（S410/S411）、Vyper → `12`（源码闸门，6 条仍 `partial`）。下一版：SPKI 清单进 08、Java/.NET trust store 检测进 09 附录。