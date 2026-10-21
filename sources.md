# 一手来源清单

> 规则：每条 CVE / 版本 / 区间结论都必须能追到本表的一行。
> `index.md` 第 2 节与各 playbook 的「来源」段都与本表双向引用。

## 类型定义

| 类型 | 定义 | 能否作为修复依据 |
|---|---|---|
| **一手** | 官方公告 / NVD / GHSA / **CNA（CVE 分配方）记录** / 厂商博客 / 官方 commit | 可以 |
| **三方公告** | CERT / CNVD 等公告机构**自撰**的漏洞公告（转述媒体的仍算二手） | 可作影响面依据；**修复版本必须厂商公告复核** |
| **公开 PoC** | 第三方公开的 PoC / 利用模板 / 扫描模板 | 只证明「公开 PoC 存在」，不作影响面或修复依据 |
| **二手** | 媒体报道、CERT 转述媒体、论坛、博客转述 | 不可以，只能标「传闻」并用于找一手线索 |
| **未确认** | 查不到一手来源 | 不可以，结论写「未确认」 |

## 已收录

| ID | 来源 | 类型 | URL | 涉及 | 核实状态 |
|---|---|---|---|---|---|
| S001 | Node.js 官方安全公告（日文镜像，2026-10 安全版本） | 一手 | https://nodejs.org/ja/blog/vulnerability/october-2026-security-releases | 同 S006（英文原文为主引用） | 一手；**已被 S006 替代为主引用**；公告未给 CVSS |
| S002 | ThaiCERT 转述 BleepingComputer：LiteLLM SQL 注入 | 二手 | https://www.thaicert.or.th/en/2026/04/30/sql-injection-vulnerability-found-in-litellm-exposes-risk-of-secret-and-key-disclosure/ | CVE-2026-42208 | 二手；**已降级为时间线线索**，不得作为结论依据（一手见 S003/S004/S005；「36 小时在野利用」仍无一手） |
| S003 | LiteLLM 官方安全博客：CVE-2026-42208 | 一手 | https://docs.litellm.ai/blog/cve-2026-42208-litellm-proxy-sql-injection | CVE-2026-42208；影响 1.81.16–1.83.6；修复 1.83.7+；推荐 1.83.10-stable | 已核实（2026-10-21 抓原文） |
| S004 | GitHub Advisory GHSA-r75f-5x8p-qvmc | 一手 | https://github.com/advisories/GHSA-r75f-5x8p-qvmc | CVE-2026-42208；CVSS 3.1 **9.8**（AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H）；CWE-89；workaround `disable_error_logs: true` | 已核实（GitHub Advisory API） |
| S005 | CISA KEV 目录 | 一手 | https://www.cisa.gov/known-exploited-vulnerabilities-catalog | CVE-2026-42208 于 2026-05-08 收录，dueDate 2026-05-11 | 已核实（catalogVersion 2026.10.21，count 1754） |
| S006 | Node.js 官方安全公告（英文原文） | 一手 | https://nodejs.org/en/blog/vulnerability/october-2026-security-releases | CVE-2026-111497 / CVE-2026-105482 / CVE-2026-105483 / CVE-2026-106069 / CVE-2026-105481 / CVE-2026-106072 / CVE-2026-106074 / CVE-2026-106073 / CVE-2026-106070 / CVE-2026-106071；修复 22.23.4 / 24.22.1 / 26.12.1 | 已核实（逐条比对：**CVE-2026-105483 仅 24/26.x，非三线全中；公告未给 CVSS**） |
| S007 | Node.js 发布页 v22.23.4 / v24.22.1 / v26.12.1 | 一手 | https://nodejs.org/en/blog/release/v24.22.1 | 三线修复版本 tag 存在 | 已核实（Docker Hub 同名 tag 均 HTTP 200） |
| S008 | PyPI litellm 版本索引 | 一手 | https://pypi.org/pypi/litellm/json | `1.83.7` / `1.83.10` 存在；2026-10-21 latest = `1.106.2` | 已核实 |
| S009 | nuclei 模板 CVE-2026-42208 | 公开 PoC | https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-42208.yaml | CVE-2026-42208 的公开检测模板 | 侦察给出链接；**只证明公开 PoC 存在**，不作影响面/修复依据 |
| S100 | OSV `GO-2026-6610`（CVE-2026-78660） | 一手 | https://osv.dev/vulnerability/GO-2026-6610 | stdlib `net/http` HTTP/2 接受畸形 framing 头；fixed `1.26.9` / `1.27.2` / `x/net 0.60.0` | 2026-10-21 经 OSV API 复核（aliases + 区间与 playbook 04 一致）；原始 JSON 见 `evidence/osv-2026-10-21/`；**OSV 未给 CVSS** |
| S101 | OSV `GO-2026-6611`（CVE-2026-78669） | 一手 | https://osv.dev/vulnerability/GO-2026-6611 | HTTP/2 初始窗口洪泛 → CPU DoS；fixed 同 S100 | 同上 |
| S102 | OSV `GO-2026-6809`（CVE-2026-111943） | 一手 | https://osv.dev/vulnerability/GO-2026-6809 | `crypto/x509` 停止信任被攻破的 eMudhra 中间 CA；fixed `1.26.10` / `1.27.3` | 同上；**与 Node.js ca-cert 同一 CA 事件**（跨生态） |
| S103 | OSV `GO-2026-6668`（CVE-2026-41510） | 一手 | https://osv.dev/vulnerability/GO-2026-6668 | Coraza：超 `ArgumentLimit` 静默丢参 → WAF 规则绕过；fixed `coraza/v3 3.8.1` | 同上 |
| S104 | OSV `GO-2026-6599`（CVE-2026-94448） | 一手 | https://osv.dev/vulnerability/GO-2026-6599 | `html/template` JS 字面量上下文未重置（XSS）；修复 `1.26.9` / `1.27.2` | 2026-10-08 批次；侦察交件 |
| S105 | OSV `GO-2026-6602`（CVE-2026-94447） | 一手 | https://osv.dev/vulnerability/GO-2026-6602 | `cmd/go` toolchain 校验和绕过（恶意 GOMODPROXY）；修复同上 | 同上 |
| S106 | OSV `GO-2026-6608`（CVE-2026-94440） | 一手 | https://osv.dev/vulnerability/GO-2026-6608 | `net/textproto` / `mime/multipart` MIME 头内存限制绕过；修复同上 | 同上 |
| S107 | OSV `GO-2026-6609`（CVE-2026-78667） | 一手 | https://osv.dev/vulnerability/GO-2026-6609 | `net/http` Range 头无上限 → CPU DoS；修复同上 | 同上 |
| S201 | OSV 恶意包库 MAL-2026-17754 | 一手 | https://osv.dev/vulnerability/MAL-2026-17754 | `@library-wide/library-shell@99.9.1`；站外 tarball + 任意生命周期脚本 | 已核实（侦察交件） |
| S202 | OSV 恶意包库 MAL-2026-17744 | 一手 | https://osv.dev/vulnerability/MAL-2026-17744 | `kmf-vendor-pack@99.0.0/100.100.x`；依赖混淆 + postinstall 外泄 | 已核实（侦察交件） |
| S203 | OSV 恶意包库 MAL-2026-18064 | 一手 | https://osv.dev/vulnerability/MAL-2026-18064 | `sc-announcer@99.9.1`；恶意域通信 | 已核实（侦察交件） |
| S204 | ThaiCERT 转述 tensorlake npm 投毒 | 二手 | https://www.thaicert.or.th/en/2026/10/09/supply-chain-attack-through-tensorlake-npm-package-steals-credentials-and-spreads-malware/ | `tensorlake@0.5.144`；preinstall 窃密 + 持久化 | 二手（时间线线索）；**一手已补：见 S205（OSV `MAL-2026-17650`）** |
| S205 | OSV 恶意包库 `MAL-2026-17650`（含 GHSA-rqxj-g25x-4v9v） | 一手 | https://osv.dev/vulnerability/MAL-2026-17650 | `tensorlake@0.5.144`：`lib/setup.mjs` 混淆加载器，窃取 npm/GitHub/AWS/K8s/Vault/SSH/.env 凭据；无安全版本 | 2026-10-21 经 OSV API 复核（原始 JSON 见 `evidence/osv-2026-10-21/`） |
| S206 | Socket.dev 研究团队博客：tensorlake 投毒 | 一手（研究方） | https://badge.socket.dev/blog/tensorlake-compromise | `tensorlake@0.5.144` 被投毒（ChainDrop / Shai-Hulud 窃密蠕虫）；2026-10-08 | 一手研究方原文（侦察交件） |
| S207 | Sonatype 博客：tensorlake npm 被劫持 | 一手（研究方） | https://www.sonatype.com/blog/hijacked-tensorlake-npm-turned-install-into-credential-risk | 安装流程变成凭据风险；与 S206 互相印证 | 一手（侦察交件） |
| S301 | vLLM GHSA-3c86-2m5g-59q7 | 一手 | https://github.com/vllm-project/vllm/security/advisories/GHSA-3c86-2m5g-59q7 | CVE-2026-90553；LlavaOnevision2 loader 无视 `trust_remote_code` → RCE；修 `0.28.0` | 已核实（侦察交件） |
| S302 | vLLM GHSA-935w-9g4m-p28p | 一手 | https://github.com/vllm-project/vllm/security/advisories/GHSA-935w-9g4m-p28p | CVE-2026-105752；跨租户前缀缓存泄露（low）；修 `0.30.0` | 已核实（侦察交件） |
| S303 | GitHub Advisory GHSA-QX62-JWPF-RCPJ | 未确认 | https://github.com/advisories/GHSA-QX62-JWPF-RCPJ | CVE-2026-105775；vLLM mamba_mixer2 越界读，PoC 公开；修复版本未确认 | 未确认（VulDB 源，项目未确认） |
| S304 | LMCache GHSA-w5f2-9q9c-ff4h | 一手 | https://github.com/LMCache/LMCache/security/advisories/GHSA-w5f2-9q9c-ff4h | CVE-2026-105192；ZMQ 未认证 pickle RCE，CVSS 9.8；修 `0.5.6` | 已核实（侦察交件） |
| S305 | CERT Polska 公告 CVE-2026-103663 | 一手 | https://cert.pl/en/posts/2026/10/CVE-2026-103663/ | Ollama **`>=0.34.2 <0.35.0`**（cvelistV5 semver，见 S315）；`/api/pull` 路径穿越 → **重启后**执行写入文件（`UI:P`，非即时）；条件 CVSS 4.0：无 `/usr/lib/ollama` 写权限 **6.9**、有写权限（多数 Docker 默认 root）**9.4**；CISA-ADP SSVC `Exploitation: none`；修复 `0.35.0`；披露 2026-10-08 | **CNA 记录**：`assignerShortName` = CERT-PL（原始 JSON 见 **S315**）；受区间按 semver `>=0.34.2 <0.35.0`；条件 CVSS 6.9 / 9.4；SSVC `Exploitation: none`；⚠️ Ollama release note 静默 |
| S306 | ThaiCERT 转述 GitLab AI Gateway | 二手 | https://www.thaicert.or.th/en/2026/10/05/gitlab-patches-critical-ai-gateway-vulnerability-that-could-allow-command-execution-on-self-hosted-gateways/ | CVE-2026-90970；模板沙箱逃逸，CVSS 9.9；修 `19.2.4` / `19.3.2` / `19.4.1` | 二手；**已被 S308（GitLab 官方）替代**，仅留时间线 |
| S307 | VulDB 候选（传闻，CVE-2026-114053） | 未确认 | —（无一手 URL；GHSA-QX62 只对应 S303 的 105775） | CVE-2026-114053（AutoProcessor RCE）；`CVE-2026-105754` 已升 verified → 见 S437（一手 GHSA-ph72-cqr5-qpp7） | 未确认；未核实到官方 GHSA，不入结论 |
| S308 | GitLab 官方补丁发布页：AI Gateway 19.4.1 | 一手 | https://docs.gitlab.com/releases/patches/other-patches/patch-release-gitlab-ai-gateway-19-4-1-released/ | CVE-2026-90970；CVSS 3.1 **9.9**（`AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H`，**PR:L = 需 Duo Agent Platform 认证**）；受影响 18.1.6–<19.2.4 / 19.3.0–<19.3.2 / 19.4.0–<19.4.1；修复 `19.2.4` / `19.3.2` / `19.4.1` | 厂商一手（侦察交件） |
| S309 | GitHub Advisory GHSA-53mr-6c8q-9789（CVE-2026-35029） | 一手 | https://github.com/advisories/GHSA-53mr-6c8q-9789 | LiteLLM `/config/update` 未校验 admin 角色 → 权限提升 / 任意文件读 / 接管 admin；prior to `1.83.0`；alias PYSEC-2026-2597 | 侦察交件；Chief 复核 advisory 页 200 + OSV alias |
| S310 | GitHub Advisory GHSA-jjhc-v7c2-5hh6（CVE-2026-35030） | 一手 | https://github.com/advisories/GHSA-jjhc-v7c2-5hh6 | OIDC userinfo 缓存键碰撞（`token[:20]`）→ 认证绕过；需 `enable_jwt_auth`；修复 `1.83.0`；alias PYSEC-2026-390 | 同上 |
| S311 | GitHub Advisory GHSA-hx8v-g79f-8w5f（CVE-2026-59823） | 一手 | https://github.com/advisories/GHSA-hx8v-g79f-8w5f | `user_config` 嵌套 `api_base` → SSRF；需有效 virtual key；修复 `1.83.9`；alias PYSEC-2026-4070 | 同上 |
| S312 | GitHub Advisory GHSA-3cv6-jpf6-8222（CVE-2026-84377） | 一手 | https://github.com/advisories/GHSA-3cv6-jpf6-8222 | 认证用户请求体路由参数未校验 → SSRF + provider 凭据外泄；**多分支修复表（OSV 原文，不是「双分支」）**：`<1.89`→`1.88.6`；`1.89.x`→`1.89.7`；`1.90.x`→`1.90.7`；`1.91.x`→`1.91.5`；`1.92.x`→`1.92.2`；`1.93.x`→`1.93.2`；`1.94.x`→`1.94.3`；`1.95.x`→`1.95.1`；`1.96.x`→`1.96.2`；alias PYSEC-2026-4066 | 侦察交件；**2026-10-21 二次复核**：`api.osv.dev` 原文 **9 条 ranges**（`<1.89`→`1.88.6`；`1.89.x`→`1.89.7`…`1.96.x`→`1.96.2`），证据 `evidence/osv-2026-10-21/GHSA-3cv6-jpf6-8222.json`（sha256 `95e4ca63…`）；**「双分支」说法错误** |
| S313 | LiteLLM 官方安全博客：2026-03 PyPI 供应链事故 | 一手 | https://docs.litellm.ai/blog/security-update-march-2026 | `litellm==1.82.7` / `1.82.8`（2026-03-24）被投毒，`1.82.8` 带 `.pth`；外泄至非官方域 `models.litellm.cloud`；clean = `1.83.0`；官方 Docker / Cloud 不受影响 | 侦察交件；细节仍待逐段复核 |
| S314 | Check Point Research：LiteLLM 网关研究 | 一手（研究方） | https://research.checkpoint.com/2026/when-llm-gateways-go-wrong-findings-from-litellm/ | 2026-10-13 发布，评估 LiteLLM v1.77.7；攻击链 `/config/update` 缺 RBAC → `UI_LOGO_PATH` 任意文件读 → admin 接管 → 云存储模块 RCE；Clientside Credentials SSRF 外泄 provider key；35029/59823 修于 1.83.9 | **2026-10-22 正文已抓**（`evidence/w3-2026-10-22/checkpoint-body.html`）；`02` 作佐证引用，综述不入条目表 |
| S315 | cvelistV5 原始记录 `CVE-2026-103663` | 一手（CVE 官方记录） | https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/103xxx/CVE-2026-103663.json | Ollama `>=0.34.2 <0.35.0`；`assignerShortName: CERT-PL`；条件 CVSS 4.0：无 `/usr/lib/ollama` 写权限 **6.9**、有写权限（多数 Docker 默认 root）**9.4**；CISA ADP SSVC `Exploitation: none`（未在野利用） | 2026-10-21 实抓 JSON 存档于 `evidence/cvelistV5-2026-10-21/`，sha256 `9c26b4d9…` |
| S316 | GitHub Advisory GHSA-69x8-hrgq-fjj8（**无 CVE 别名**） | 一手 | https://github.com/advisories/GHSA-69x8-hrgq-fjj8 | LiteLLM 密码哈希泄露 + pass-the-hash 登录；需认证；`<1.83.0` 修复 `1.83.0` | 侦察交件；02 引用 |

| S400 | php.net 2026-10-21 安全发布公告 | 一手 | https://www.php.net/archive/2026.php#2026-10-21-5 | CVE-2026-109618 / CVE-2026-109619；修复 `8.5.12` / `8.4.27` / `8.3.36` / `8.2.35`；技术细节与更新说明 | PHP Foundation 引用；php.net 官网存档页 |
| S401 | PHP Foundation：今日安全发布说明 | 一手 | https://thephp.foundation/blog/2026/10/21/todays-php-security-release-and-how-were-strengthening-php-security/ | mod_php 未认证、默认配置可 RCE；FPM 经应用层路径也确认 RCE；**CVSS 实际 9.2（泄露的 10.0 错误）**；发布时未确认在野利用；Chainguard 07:41 UTC 破 embargo；8.1 无补丁 | 2026-10-21 抓原文 |
| S402 | GHSA-w8hw-w9fx-j79w（php-src） | 一手 | https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w | CVE-2026-109618：RCE via OOM corruption | 侦察交件 |
| S403 | GHSA-6wmf-4rv5-p3rp（php-src） | 一手 | https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp | CVE-2026-109619：RCE via stale state（UAF） | 侦察交件 |
| S500 | Mozilla 安全团队 oss-security 披露：eMudhra 中间 CA 泄露 | 一手 | https://www.openwall.com/lists/oss-security/2026/10/20/1 | 8 张中间 CA 私钥被攻破（6 TLS + 2 代码签名）；3 个根 SPKI 全清单；eMudhra 10-18 吊销、Sectigo 10-19 吊销；OneCRL/CRLSets 已阻断；CT 暂未见签发记录；「abuse likely in the near future」 | 2026-10-21 抓原文（含 8 张 SPKI 与证书 SHA-256） |
| S501 | Mozilla 官方博客：保护 Firefox 用户 | 一手 | https://blog.mozilla.org/security/2026/10/20/protecting-firefox-users-following-the-compromise-of-emudhra-intermediate-certificates/ | 10-17 20:06 UTC 接报；OneCRL 3 小时内（22:59 UTC）全量分发；Firefox `158.0.1`（桌面+Android）、ESR `115.43.1`/`153.5.1`、NSS `3.131.1`；10-21 补 Android `158.0.2`（OneCRL 启动应用问题） | 2026-10-21 抓原文 |
| S502 | RUSTSEC-2026-0381（webpki-roots） | 一手 | https://raw.githubusercontent.com/rustsec/advisory-db/main/crates/webpki-roots/RUSTSEC-2026-0381.md | patched `>=1.0.10`；`=0.26.11` unaffected；alias **CVE-2026-111943**；references 含社区测试主机 | 2026-10-21 抓 raw |
| S503 | RUSTSEC-2026-0382（rustls-webpki） | 一手 | https://raw.githubusercontent.com/rustsec/advisory-db/main/crates/rustls-webpki/RUSTSEC-2026-0382.md | patched `>=0.103.16, <0.104.0-alpha.1` 与 `>=0.104.0-alpha.8`；alias **CVE-2026-111943** | 2026-10-21 抓 raw |
| S504 | RUSTSEC-2026-0383（webpki-root-certs） | 一手 | https://raw.githubusercontent.com/rustsec/advisory-db/main/crates/webpki-root-certs/RUSTSEC-2026-0383.md | patched `>=1.0.10`；`=0.26.11` unaffected；alias **CVE-2026-111943** | 2026-10-21 抓 raw |
| S505 | 社区测试锚点 `emudhra.we-have-a-problem.com` | 一手（社区工具，非厂商） | https://emudhra.we-have-a-problem.com/ | 被 RUSTSEC 三条 advisory 的 references 引用；用于验证信任库是否仍接受该链 | 只作快速验证，不作唯一验收 |
| S601 | CISA KEV：SiteGuard Server Edition | 一手 | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | CVE-2026-106931；OS 命令注入（root/SYSTEM）；added 2026-10-20，due 2026-10-23 | catalogVersion 2026.10.21 实测 |
| S602 | CISA KEV：Plex Media Server | 一手 | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | CVE-2026-96652(SSRF,due 11-03) / CVE-2026-96654(编码 URI scheme,due 10-23) / CVE-2026-96655(SSRF,due 11-03) / CVE-2026-96656(路径控制→RCE,due 10-23)；均 added 2026-10-20 | 实测；fixed **`1.43.3.10861`**（#712 发布、#713 于 2026-08-04 16:09 全量；社区 v1.43.2 是错的） |
| S603 | CISA KEV：Siemens Software Center | 一手 | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | CVE-2026-110936；不受控搜索路径（DLL 侧载，本地→ACE）；added 2026-10-20，due 2026-11-03 | 实测 |
| S604 | CISA KEV：PAN-OS（10 月批） | 一手 | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | CVE-2026-0322；代码注入（认证攻击者→root）；added 2026-10-14，due 2026-10-17（已过） | 实测 |
| S605 | CISA KEV：PAN-OS（5 月批） | 一手 | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | CVE-2026-0257；认证绕过；added 2026-05-29，due 2026-06-01（已过）；**与 0322 是两条不同 CVE** | 实测 |
| S606 | CISA KEV：FortiMail | 一手 | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | CVE-2026-104286；路径穿越；added 2026-10-01，due 2026-10-04（已过）；受影响 `8.0.0–8.0.1 / 7.6.0–7.6.6 / 7.4.0–7.4.8 / 7.2.0–7.2.9`；fixed `8.0.2 / 7.6.7 / 7.4.9`，7.2 线跨分支升 7.4+（FG-IR-26-175） | 实测 |
| S607 | Siemens ProductCERT News：`CVE-2026-110936` 在野利用公告（含 IoC 章节 / 恶意文件哈希，2026-10-19） | 一手（厂商 PSIRT） | https://productcert.siemens.com/news/2026/10/19/active-exploitation-of-cve-2026-110936-in-siemens-software-center/ | CVE-2026-110936；在野利用确认 + IoC（文件哈希） | 2026-10-22 收原件 `evidence/w2-2026-10-23/siemens-news-CVE-2026-110936.html`；`10` 引用 |
| S506 | MFSA 2026-111（Firefox 158.0.1） | 一手 | https://www.mozilla.org/en-US/security/advisories/mfsa2026-111/ | CVE-2026-113470；high；OneCRL 阻断列表随发行版下发（防 RemoteSettings 被策略禁用） | 2026-10-21 抓原文 |
| S507 | Mozilla Bugzilla 2083449（eMudhra 私钥泄露） | 一手 | https://bugzilla.mozilla.org/show_bug.cgi?id=2083449 | 根因：8 把 P384 私钥均为**小于 256 的整数**，可秒级恢复（BSGS/枚举）；Mozilla 独立复现；Sectigo 交叉签证书当时**仍未吊销** | 2026-10-21 抓原文。**批注（R7）**：标题里的「私钥泄露」是 Bugzilla 原文名，不是本队结论；本队口径为**弱密钥**（见 09 / index G16），标题按 R7 不改 |
| S508 | oss-security 披露（Dennis Jackson / Mozilla） | 一手 | https://www.openwall.com/lists/oss-security/2026/10/20/1 | eMudhra 事件全貌：8 中间 CA（6 TLS + 2 代码签名）+ 3 根 + Sectigo 交叉签 SPKI 全哈希；根因 KGC 弱密钥；事件时间线 | 一手原文；SPKI 全表已誊录到 `evidence/spki-emudhra-2026-10-21.md` |
| S108 | Traefik 官方安全公告 GHSA-rh7m-2m44-x32f（K8s annotation 跨命名空间引用） | 一手 | https://github.com/traefik/traefik/security/advisories/GHSA-rh7m-2m44-x32f | CVE-2026-112778；修 **2.11.46 / 3.6.17 / 3.7.1**；CVSS 4.0 **6.4**（NVD Secondary）；修复引入 `crossProviderNamespaces` | 2026-10-22 收原件；`04` 引用 |
| S404 | MSRC CVE-2026-88092（Kestrel HTTP/1 请求走私）+ dotnet/aspnetcore GHSA-rv87-ccxw-8ggf | 一手（厂商/GHSA） | https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-88092 | CVE-2026-88092；CWE-444；CVSS 3.1 **9.4**；修 `8.0.32`/`9.0.21`/`10.0.13`/`11.0.0-rc.2` | 2026-10-22 收 GHSA 原件；`11` 引用 |
| S405 | MSRC CVE-2026-70183（Blazor 授权竞态）+ GHSA-494h-xx7x-5frh | 一手 | https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-70183 | CVE-2026-70183；CWE-362；CVSS 3.1 **7.5**；修同上 | 2026-10-22 收原件；`11` 引用 |
| S406 | MSRC CVE-2026-70186（Kestrel HTTP/3 DoS）+ GHSA-mf4x-w4gh-4656 | 一手 | https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-70186 | CVE-2026-70186；CWE-833；CVSS 3.1 **7.5**；修同上 | 2026-10-22 收原件；`11` 引用 |
| S407 | MSRC CVE-2026-96230（Blazor WASM 开发服务器调试页）+ GHSA-qjpx-jqm5-h2c4 | 一手 | https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-96230 | CVE-2026-96230；CWE-79；CVSS 3.1 **8.8**；修同上 | 2026-10-22 收原件；`11` 引用 |
| S408 | MSRC CVE-2026-96233（DateTime 希伯来数字越界读 DoS）+ GHSA-87vj-4hqv-22p9 | 一手 | https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-96233 | CVE-2026-96233；CWE-787；CVSS 3.1 **7.5**；修同上 | 2026-10-22 收原件；`11` 引用 |
| S409 | GHSA-w6wh-p4g7-mpj2（Unix 命名互斥/共享内存提权；无 MSRC 页） | 一手（**无 MSRC 页**、NVD 无发布日） | https://github.com/advisories/GHSA-w6wh-p4g7-mpj2 | CVE-2026-96225；CWE-59；CVSS 3.1 **7.8**；修同上 | 2026-10-22 收原件；`11` 引用 |
| S410 | NVD CVE-2026-105221 + gist 上游 commit/issue（RubyGem 硬编码 `VERIFY_NONE`） | 一手（NVD + 上游 commit） | https://nvd.nist.gov/vuln/detail/CVE-2026-105221 | CVE-2026-105221；CWE-295；CVSS 3.1 **7.4** / 4.0 **9.1**；修 `6.1.0` | 2026-10-22 收原件；`09` 引用 |
| S411 | NVD CVE-2026-85086（Apache Thrift perl bindings 不安全 TLS 默认） | 一手（NVD；**Apache 原文需 JS，未取到**） | https://nvd.nist.gov/vuln/detail/CVE-2026-85086 | CVE-2026-85086；CWE-295 + CWE-1188；CVSS 4.0 **6.9**；修 `0.25.0` | 2026-10-22 收原件；`09` 引用 |
| S412 | CVE 官方记录 `CVE-2026-85086`（**CNA = apache**，state PUBLISHED）+ lists.apache.org 线程 | 一手（CNA 记录） | https://lists.apache.org/thread/33otcgbqd27wf6qq810q56znzbomnhg1 | CVE-2026-85086；Apache Thrift perl bindings `<0.25.0` → `0.25.0`；title「Perl TLS client disables certificate verification by default」 | 2026-10-22 收 `cveawg-CVE-2026-85086.json`；`09` 引用（**补 S411 的「仅 NVD」口径**） |
| S413 | metacpan 发布说明 `Mozilla-CA-20261020` + NVD `CVE-2026-113812` | 一手（上游发布说明 + NVD） | https://metacpan.org/release/LWP/Mozilla-CA-20261020/changes | CVE-2026-113812；Perl `Mozilla::CA` `<20261020` → `20261020`；denylist 含 `emSign ECC Root CA - G3`（sha256 `86a1ecba…`） | 2026-10-22 收原件（`metacpan-Mozilla-CA-20261020-changes.txt` + `NVD-CVE-2026-113812.json`）；`09` 引用；编号 **S412/S413 已由工坊确认：S411 之后顺延，无冲突** |
| S414 | GHSA-6q48-6c7w-9gw2（Python `certifi` 打包 emSign 根证书，critical，无 CVE 别名） | 一手（GHSA） | https://github.com/advisories/GHSA-6q48-6c7w-9gw2 | `>=2019.03.09 <2026.10.19` → `2026.10.19` | 2026-10-22 收原件；`09` 引用（**闭环 W1 certifi 缺口**） |
| S415 | GHSA-hq85-5cpj-mr62（Python `uv` 内置 CA store，无 CVE 别名） | 一手（GHSA） | https://github.com/advisories/GHSA-hq85-5cpj-mr62 | `<0.13.4` → `0.13.4` | 2026-10-22 收原件；`09` 引用 |
| S416 | Plex 官方论坛版本公告 #712（Plex Media Server 1.43.3.10861） | 一手（厂商发布公告） | https://forums.plex.tv/t/plex-media-server/30447/712 | CVE-2026-96652/96654/96655/96656；`<1.43.3.10861` → `1.43.3.10861`；#712 为 Beta 公告，#713 起全量；社区流传 `v1.43.2` 是错的 | 2026-10-22 收原件；`10` 引用；#714 已到 10896（非本条必需） |
| S417 | Fortinet PSIRT `FG-IR-26-175`（FortiMail 路径穿越 + NULL 字节） | 一手（厂商 PSIRT） | https://www.fortiguard.com/psirt/FG-IR-26-175 | CVE-2026-104286；受影响 `8.0.0–8.0.1`/`7.6.0–7.6.6`/`7.4.0–7.4.8`/`7.2.0–7.2.9`；修 `8.0.2`/`7.6.7`/`7.4.9`；**7.2 无同分支修复**；workaround 关 IBE；IoC `79.141.169.187`/`45.129.0.192` | 2026-10-22 收原件；`10` 引用 |
| S418 | JVN#88474777（EG Secure Solutions SiteGuard Server Edition OS 命令注入） | 一手（JVN / IPA） | https://jvn.jp/en/jp/JVN88474777/ | CVE-2026-106931；受影响 `>=Ver2.20`（IIS 3.10–4.00U4 不受影响；需统计功能开启，默认开）；修 **Ver8.00 Update 5 / Ver7.00 Update 6**；CVSS 4.0 8.5 / 3.0 7.8；**已确认在野利用**；EOL 版本另有补丁 | 2026-10-22 收原件；`10` 引用；厂商页 302 已留证，以 JVN 为一手 |
| S419 | Siemens ProductCERT `SSA-580366`（Software Center 不受控搜索路径） | 一手（厂商 PSIRT） | https://cert-portal.siemens.com/productcert/html/ssa-580366.html | CVE-2026-110936；`All versions < V4.0.9.8` → `V4.0.9.8`（启动时自动更新）；另 ProductCERT News 确认**在野利用** + IoC 章节 | 2026-10-22 收原件；`10` 引用；ProductCERT News 独立 S 行见 S607 |
| S420 | Palo Alto 官方安全公告 `CVE-2026-0322`（管理面认证 RCE，逐分支 Product Status） | 一手（厂商 PSIRT） | https://security.paloaltonetworks.com/CVE-2026-0322 | CVSS-BT **8.6 HIGH**、`E:A ATTACKED`、`PR:H`；**无官方 workaround**；逐分支修复线（12.2/12.1/11.2/11.1/10.2）；Threat ID 510046/510047 有限覆盖（需 SSL 解密） | 2026-10-22 收原件；`10` 引用 |
| S421 | Palo Alto 官方安全公告 `CVE-2026-0257`（GlobalProtect 认证绕过） | 一手（厂商 PSIRT） | https://security.paloaltonetworks.com/CVE-2026-0257 | CVSS-BT **7.8 HIGH**、`E:A`；**有官方缓解**（关 Authentication Override / 专用证书）；逐分支修复线 + Prisma Access；**升级后 GP 用户需重认证一次** | 2026-10-22 收原件；`10` 引用 |
| S422 | Debian DSA-6572-1 + 安全 tracker + Bug #1151413（ca-certificates 移除 eMudhra/Comodo 根） | 一手（发行版安全公告） | https://security-tracker.debian.org/tracker/ca-certificates | trixie `20250419+deb13u1`（DSA-6572-1，2026-10-20）；unstable `20260816+nmu1`（NMU 2026-10-20）；bookworm changelog 未取到 | 2026-10-22 收原件（`w3-2026-10-22/debian-dsa-6572-1.html` 等）；`09` 引用 |
| S423 | OpenJDK JDK-8319187 `Add three eMudhra emSign roots`（+ master cacerts 目录清单仍含 3 张 emSign 根） | 一手（上游 bug/源码树） | https://bugs.openjdk.org/browse/JDK-8319187 | Java cacerts 含 `emsigeccrootcag3`/`emsignrootcag1`/`emsignrootcag2`；**无移除提交** → 无厂商修复版本 | 2026-10-22 收原件；`09` 引用 |
| S424 | GraalVM Native Image · Certificate Management（构建期捕获 TrustStore、`blacklisted.certs` 构建期加载） | 一手（厂商文档） | https://www.graalvm.org/latest/reference-manual/native-image/dynamic-features/CertificateManagement/ | native image 必须用**清洗后 cacerts 的构建机**重编译；改运行机无效 | 2026-10-22 收原件；`09` 引用 |
| S425 | MS Learn：.NET 跨平台加密（Windows Cert Store / Linux OpenSSL / macOS Keychain） | 一手（厂商文档） | https://learn.microsoft.com/en-us/dotnet/standard/security/cross-platform-cryptography | .NET **不自带 CA bundle、无独立处置版本**；处置 = 更新 OS/基础镜像 store | 2026-10-22 收原件；`09` 引用 |
| S426 | GHSA-2489-32vh-8rrc（Vyper 导入常量/默认参数名解析） | 一手（GHSA） | https://github.com/vyperlang/vyper/security/advisories/GHSA-2489-32vh-8rrc | `>=0.4.0b1`；**无修复版本** → 源码闸门 R1 | 2026-10-22 收原件；`12` 引用 |
| S427 | GHSA-6j9c-gvcw-74fj（Vyper 优化器折叠 `msg.value OR K`） | 一手（GHSA） | https://github.com/vyperlang/vyper/security/advisories/GHSA-6j9c-gvcw-74fj | `>=0.3.8`；**无修复版本** → 闸门 R2 | 2026-10-22 收原件；`12` 引用 |
| S428 | GHSA-cw3h-xwxq-8cx2（Vyper 三元嵌套数组越界读） | 一手（GHSA） | https://github.com/vyperlang/vyper/security/advisories/GHSA-cw3h-xwxq-8cx2 | `>=0.3.8 <=0.5.0b1`；**无修复版本** → 闸门 R3 | 2026-10-22 收原件；`12` 引用 |
| S429 | GHSA-fxg7-4wqg-c8gh（Vyper `create_from_blueprint` 偏移绕过） | 一手（GHSA） | https://github.com/vyperlang/vyper/security/advisories/GHSA-fxg7-4wqg-c8gh | `>=0.3.4`；**无修复版本** → 闸门 R4 | 2026-10-22 收原件；`12` 引用 |
| S430 | GHSA-r3c7-7xwm-6vfw（Vyper 多字节标识符改字面量） | 一手（GHSA） | https://github.com/vyperlang/vyper/security/advisories/GHSA-r3c7-7xwm-6vfw | `>=0.1.0b1 <0.1.0b12`、`=0.1.0b14`、`>=0.4.1`；**无修复版本** → 闸门 R5 | 2026-10-22 收原件；`12` 引用 |
| S431 | GHSA-wvx7-39qj-2g9v（Vyper 行分隔符改字面量/类型） | 一手（GHSA） | https://github.com/vyperlang/vyper/security/advisories/GHSA-wvx7-39qj-2g9v | `>=0.1.0b1 <0.1.0b17`、`>=0.4.1`；**无修复版本** → 闸门 R6 | 2026-10-22 收原件；`12` 引用 |
| S432 | Debian bookworm-security 源包 `ca-certificates_20250419~deb12u2.tar.xz`（含 `debian/changelog`；NMU 2026-10-20 21:45:34 +0200，`Closes: #1151413`，黑名单 `emSign ECC Root CA - G3` + `Comodo AAA Services root`） | 一手（Debian 源包） | https://snapshot.debian.org/archive/debian-security/20261020T211310Z/pool/updates/main/c/ca-certificates/ca-certificates_20250419~deb12u2.tar.xz | CVE-2026-111943；bookworm 修复版 = `20250419~deb12u2` | 2026-10-22 收原件 `evidence/w4-2026-10-22/bookworm-debian-tar.xz`；**注意：bookworm 修复不在 DSA-6572-1 正文内**（该 DSA 只列 trixie） |
| S433 | Debian `ca-certificates-java` 包描述（`uses the hooks of the ca-certificates package to update the cacerts JKS keystore`） | 一手（Debian 包页） | https://packages.debian.org/trixie/ca-certificates-java | Java cacerts：升 OS 包经钩子连带更新（**仅实证钩子机制**，实际 store 路径以 `keytool -list -cacerts` 为准） | 2026-10-22 收原件 `evidence/w4-2026-10-22/debian-ca-certificates-java.html` |
| S434 | RHEL/CentOS Stream `java-21-openjdk.spec`（c9s，`:2251` `ln -sf /etc/pki/java/cacerts .`） | 一手（发行版源码包） | https://gitlab.com/redhat/centos-stream/rpms/java-21-openjdk/-/raw/c9s/java-21-openjdk.spec | Java cacerts：RHEL 系 JDK 信任库跟随 OS store（**已实证**） | 2026-10-22 收原件 `evidence/w4-2026-10-22/redhat-java21-openjdk.spec` |
| S435 | Plex 官方论坛版本公告 #713（`1.43.3.10861 is now available to everyone`，2026-08-04 16:09） | 一手（厂商公告） | https://forums.plex.tv/t/plex-media-server/30447/713 | CVE-2026-96652 / 96654 / 96655 / 96656；Plex 稳定通道全量时间线（早于 KEV 收录 2026-10-20） | 2026-10-22 收原件 `evidence/w4-2026-10-22/plex-post-713-stable.html` |
| S436 | OSV/GHSA `GHSA-ph3r-5jfg-f84f`（vLLM 多模态 IPC 缓存不同步） | 一手（GHSA/OSV） | https://osv.dev/vulnerability/GHSA-ph3r-5jfg-f84f | CVE-2026-105753；vllm `<0.28.0` → `0.28.0` | 2026-10-22 入库；证据 `evidence/w7-2026-10-22/osv-vllm.json`；`05` 引用 |
| S437 | OSV/GHSA `GHSA-ph72-cqr5-qpp7`（vLLM 多模态传输信任调用方特征） | 一手（GHSA/OSV） | https://osv.dev/vulnerability/GHSA-ph72-cqr5-qpp7 | CVE-2026-105754；vllm `<0.30.0` → `0.30.0`（原 observe，一手到位升 verified） | 2026-10-22 入库；证据 `evidence/w7-2026-10-22/osv-vllm.json`；`05` 引用 |
| S438 | OSV/GHSA `GHSA-2823-qmq8-rwvj`（vLLM `cache_salt` 弱校验 → 单请求杀 EngineCore） | 一手（GHSA/OSV） | https://osv.dev/vulnerability/GHSA-2823-qmq8-rwvj | CVE-2026-105756；vllm `<0.30.0` → `0.30.0` | 2026-10-22 入库；证据 `evidence/w7-2026-10-22/osv-vllm.json`；`05` 引用 |
| S439 | OSV/GHSA `GHSA-x6mc-67gf-chw4`（vLLM Qwen2/3-VL 视频采样 `max_frames` 无界） | 一手（GHSA/OSV） | https://osv.dev/vulnerability/GHSA-x6mc-67gf-chw4 | CVE-2026-105758；vllm `>=0.24.0 <0.30.0` → `0.30.0` | 2026-10-22 入库；证据 `evidence/w7-2026-10-22/osv-vllm.json`；`05` 引用 |
| S440 | OSV/GHSA `GHSA-58v5-2m8f-94pr`（vLLM GLMGA 视频采样 CPU/内存耗尽） | 一手（GHSA/OSV） | https://osv.dev/vulnerability/GHSA-58v5-2m8f-94pr | CVE-2026-105760；vllm `>=0.23.0rc2 <0.30.0` → `0.30.0` | 2026-10-22 入库；证据 `evidence/w7-2026-10-22/osv-vllm.json`；`05` 引用 |
| S441 | OSV/PYSEC `PYSEC-2026-4319`（vLLM Penalty Handler `get_token_bin_counts_and_mask` DoS） | 一手（OSV/PYSEC） | https://osv.dev/vulnerability/PYSEC-2026-4319 | CVE-2026-105922；vllm `<0.32.0` → `0.32.0`（总修复线） | 2026-10-22 入库；证据 `evidence/w7-2026-10-22/osv-PYSEC-2026-4319.json`；`05` 引用 |

## 传闻区（二手 / 未确认，**不入结论**）

| 编号 | 来源 | 类型 | URL | 涉及 | 核实状态 |
|---|---|---|---|---|---|
| S900 | SystemTwo 情报交换：PoeLLM 僵尸网络 | 二手 | https://systemtwosecurity.com/intel-exchange/01a11b23-e3be-706c-bc82-7317b948c11d | 声称感染 3,400+ 暴露的 Ollama/vLLM，C2 藏 GitHub 诗 | 传闻；**不入结论** |
| S901 | LinuxSecurity：vLLM 0.31.0 批量修复 | 二手 | https://linuxsecurity.com/news/security-vulnerabilities/vllm-vulnerability-code-execution-server-crashes | 称 vLLM 0.31.0 批量修 RCE，候选 CVE-2026-114053 / 105754 | 传闻；官方 GHSA 未出，**不入结论** |
| S902 | CloudSEK 博客：TOPHIT（npm 抢注洪泛 + GPU 挖矿 C2） | 二手 | https://www.cloudsek.com/ar/blog/tophit-npm-typosquat-flood-gpu-cryptojacking-server | 单操作者批量抢注 npm 包 + GPU 挖矿 C2 | 传闻；**不入结论** |

## ID 分配（给 漏洞侦察 交件用）

| 区段 | 用途 |
|---|---|
| S001–S099 | 起点线索 / 通用（运行时、供应链、密钥轮换） |
| S100–S199 | Go 生态 |
| S200–S299 | npm 供应链 |
| S300–S399 | Python / LLM 基建 |
| S400–S499 | PHP / 其他运行时（GPT 情报集 P1 新增） |
| **S436–S441（例外）** | **LLM 10-15 批追加**（vLLM 6 条，2026-10-22 入库）：本应落 S3xx（Python/LLM）；S3xx 编号预留，LLM 10-15 批按组长批准落 S436–S441，在此登记例外 |
| S500–S599 | PKI / CA 证书事件（eMudhra 等，跨生态） |
| S600–S699 | 网络 / 边界设备（Plex、PAN-OS、Forti*、Siemens 等） |
| S900+ | 待确认 / 传闻 |

**去重规则**：交件编号可能与本表不同（同一 URL 两套 ID 是常态，例如侦察交件的 `S1xx` 与本表 `S1xx` 顺序不同）。一律**按 URL 去重**：URL 已收录 → 只吸收新字段，不新增行、不重编号；URL 未收录 → 才新增。

交件格式（一行一条，缺列就写「未确认」）：

```
S1xx | <来源名称> | 一手 | <URL> | <CVE/组件/版本> | 已核实
```

## 状态小结

- **LiteLLM（S003–S005、S008）**：一手齐。CVSS 9.8 / CWE-89 / KEV 收录 / 修复版本 PyPI 实查，可作结论。
- **Node.js（S001、S006、S007）**：一手齐（10 条 CVE 逐条核实）。**公告没有 CVSS 分数，只有 high/medium/low 标签**——不要再找「不存在的分数」，要么从 NVD/GHSA 取分，要么结论写「官方未给」。
- **Go（S100–S103）**：OSV 一手齐，fixed 区间与 playbook 04 逐条一致。**OSV 这四条同样没有 CVSS**（`severity: null`），04 的「高危」是定性表述，不是分数。
- **npm tensorlake**：S205（OSV）+ S206（Socket）+ S207（Sonatype）三重一手，可作结论。
- **Ollama CVE-2026-103663**：S305 为 CNA 记录（`assignerShortName` = CERT-PL），可作「影响面 + 修复版本」依据；Ollama release note 静默，「厂商已声明修复」这句仍不能说。受影响区间按 cvelistV5 原文 `>=0.34.2 <0.35.0`。
- **GitLab AI Gateway**：S308 厂商一手，**PR:L 需认证**——别写成未认证。
- 二手：S002、S306，仅用于时间线线索。

## 补充核实数据（2026-10-21 二次交件吸收，按 URL 映射到本表 ID）

| 编号 | 披露日 | CVSS / 备注 |
|---|---|---|
| S100 GO-2026-6610 | 2026-10-08 | — |
| S101 GO-2026-6611 | 2026-10-08 | — |
| S102 GO-2026-6809 | 2026-10-21 | — |
| S103 GO-2026-6668 | 2026-10-20 | — |
| S201 MAL-2026-17754 | 2026-10-10 | 别名 GHSA-8j36-pr5c-f6vx；CWE-506 |
| S202 MAL-2026-17744 | 2026-10-09 | — |
| S203 MAL-2026-18064 | 2026-10-20 | — |
| S204 tensorlake（ThaiCERT） | 2026-10-09 | 包已下架 |
| S301 CVE-2026-90553 | 2026-08-28 | CVSS 3.1 **7.8** / 4.0 **8.5**；CWE-94 |
| S302 CVE-2026-105752 | 2026-10-06 | 低危 |
| S303 CVE-2026-105775 | — | CVSS 3.1 **4.3**；`github_reviewed=false` |
| S304 CVE-2026-105192 | 2026-10-16 | CVSS **9.8** |
| S305 CVE-2026-103663 | 2026-10-08 | 条件 CVSS **6.9 / 9.4**；SSVC `Exploitation: none`；区间 `>=0.34.2 <0.35.0` |
| S306 CVE-2026-90970 | — | CVSS **9.9**（二手转述，已被 S308 替代） |
| S308 CVE-2026-90970 | — | CVSS 3.1 **9.9**；**PR:L（需认证）**，不是预认证 |
| S206 / S207 tensorlake | 2026-10-08 | Socket + Sonatype 两个研究方一手，互相印证 |

> Node.js 10 条仍**无 CVSS**：官方公告不给、NVD 同日未评分，已由侦察二次复查确认。

## W1 追加来源（2026-10-22，**已并入「已收录」**）

修复策略交件的 9 条已由工坊分配 S 号并入上表，本区不再保留重复行：

- `S108` Traefik（CVE-2026-112778）→ `04`
- `S404`–`S409` .NET / ASP.NET Core 6 条（CVE-2026-88092 / 70183 / 70186 / 96230 / 96233 / 96225）→ `11`
- `S410` Ruby gist（CVE-2026-105221）、`S411` Perl Thrift（CVE-2026-85086）→ `09`
- **W2 追加**：`S412` CNA=apache 记录（CVE-2026-85086，补 S411 的「仅 NVD」口径）、`S413` Mozilla::CA 20261020（CVE-2026-113812）→ `09`；编号**已确认**（S411 之后顺延，无冲突）
- **W2 二次追加（修复策略顺延占用，请工坊确认）**：`S414` certifi、`S415` uv → `09`；`S416` Plex、`S417` FortiMail、`S418` SiteGuard（JVN）、`S419` Siemens、`S420`/`S421` PAN-OS 逐分支 → `10`

证据原件：`evidence/w1-2026-10-22/`（45 份，sha256 见该目录 `evidence-manifest.sha256`）；W2 第二批在 `evidence/w2-2026-10-23/`（31 份，`evidence-manifest.sha256` = `8627892252a30c6b09e35199e7f57cdfbffa2a74697b0d5cdb7b83e5df7b7478`）。

## 待办

- [x] 补 CVE-2026-42208 一手来源 → S003 / S004 / S005
- [x] Node.js 10 条 CVE 逐条核实 → S006
- [ ] NVD / GHSA 是否为 Node 这 10 条给出 CVSS；无则明确记录「官方未给」（01 转 verified 的前置）
- [x] Go（S1xx）一手条目 → S100–S103（OSV API 复核，原始 JSON 已存 evidence/）
- [x] npm（S2xx）恶意包/投毒条目 → S201–S205
- [x] Python-LLM（S3xx）：vLLM / LMCache / Ollama / GitLab AI Gateway → S301–S307
- [ ] eMudhra 中间 CA 事件的一手通报（Node 与 Go 同源，目前只有各生态的「停止信任」公告，没有 CA 侧一手）
- [x] PoeLLM 报道 URL → S900；vLLM 0.31.0 批量修复 URL → S901
- [ ] 仍缺 URL：Sysdig 的 LiteLLM 披露博客（「披露日 2026-04-30」引用到现在没有链接）
- [x] `S305` 的 CNA 身份可点开证据 → S315（cvelistV5 原始 JSON，已存档）

## 线索集归档（**不入 S 表**）

`ingest/2026-10-21/` 存 GPT 产出情报集原件与 Chief 分流件（HTML + triage + urls + status，sha256 见 `ingest/README.md`）。

- 其内部 `S01–S43` 与本表 `Sxxx` 编号区间冲突，**禁止引用其编号**；
- 只作「去哪个 URL 查什么」的线索，数字必须逐条回一手核实后才可建行；
- 已吸收：侦察 W1–W4 回件并入表/入件（`inventory.tsv` 101 行）。

## 引用检查

```bash
cd /path/to/vuln-response-skill
# playbook 里出现的 CVE 是否都在本表出现
grep -rhoE 'CVE-[0-9]{4}-[0-9]+' playbooks/*.md playbooks/_draft/*.md | sort -u
grep -oE 'CVE-[0-9]{4}-[0-9]+' sources.md | sort -u
```
