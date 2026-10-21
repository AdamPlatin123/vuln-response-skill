---
id: "10"
title: 在野利用簇 · 边界与媒体设备 KEV 判定件（修复版本回厂商公告）
ecosystem: generic
cve: ["CVE-2026-106931", "CVE-2026-96652", "CVE-2026-96654", "CVE-2026-96655", "CVE-2026-96656", "CVE-2026-110936", "CVE-2026-0322", "CVE-2026-0257", "CVE-2026-104286"]
affects: "按 KEV 收录 + 暴露面判定（非 semver）；受影响版本区间未一手核实：SiteGuard Server Edition / Plex Media Server / Siemens Software Center / PAN-OS / FortiMail"
fixed: ["UNKNOWN（KEV 不含 fixed 字段；五家厂商修复版本未一手核实，须回厂商公告，见「待核实」）"]
severity: "严重（9 条全部在 CISA KEV = 已被实际利用；3 条 dueDate 已逾期，3 条 2026-10-23 到期（次日））"
status: draft
sources: ["https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"]
updated: 2026-10-21
---

# 在野利用簇 · 边界与媒体设备 KEV 判定件

**一句话**：这 9 条**全部在 CISA KEV**，即「已被实际利用」。**本件是判定件，不是升级件**——它回答「我是不是暴露了、该按几级处置」，**不回答「升到哪个版本」**；修复版本一律回厂商公告取，本文件不出现任何未经一手核实的升级版本号。

> **三条硬规则**
> 1. KEV **不含 fixed 字段**。本件不写升级版本；Plex `v1.43.2` 等数字只是社区流传，**未核实**，不得写进变更单或工单结论。
> 2. 判定顺序是 **暴露面 → 档位 → 厂商公告取 fixed → 升级**，不是「查版本再决定要不要修」。
> 3. 同厂商相邻编号的 CVE（如 PAN-OS `0322` / `0257`）**是不同漏洞、不同批次，分行列出、分行处置，禁止并号合并**。

## 适用版本区间

不按 semver 判定，按 **KEV 收录 + 暴露面** 判定。以下 KEV 字段均取自本地 `kev.json` 实测（catalogVersion **2026.10.21**，count 1754）：

| CVE | 产品 | KEV 原文要点（判定依据） | added / due | 处置档 |
|---|---|---|---|---|
| CVE-2026-106931 | EG Secure Solutions SiteGuard Server Edition | OS 命令注入，**可为 root 或 SYSTEM**（KEV 原文） | 10-20 / **10-23** | P0 |
| CVE-2026-96652 | Plex Media Server | SSRF，**任意 `X-Plex-Token` 值即可**，可强制服务端 POST 到攻击者目标；可与 96654/96655/96656 链式 | 10-20 / 11-03 | P0（公网暴露时） |
| CVE-2026-96654 | Plex Media Server | 编码 URI scheme 未中和 → 可调其他插件函数并自带参数；可链式 | 10-20 / **10-23** | P0 |
| CVE-2026-96655 | Plex Media Server | SSRF，**需已认证用户**，经 `/video/:/transcode/universal` 路径参数 | 10-20 / 11-03 | P1 |
| CVE-2026-96656 | Plex Media Server | 文件名/路径外部控制，**需 admin**，可写任意文件、加载时可能执行；可链式 | 10-20 / **10-23** | P1（**不是未认证 RCE**） |
| CVE-2026-110936 | Siemens Software Center | 不受控搜索路径，**需本地已认证**，DLL 侧载 → 以应用权限执行 | 10-20 / 11-03 | P2（终端侧） |
| CVE-2026-0322 | Palo Alto Networks PAN-OS | 代码注入，**需已认证 + 有网络访问** → 以 root 执行；10 月批 | 10-14 / **10-17（已过）** | P1 |
| CVE-2026-0257 | Palo Alto Networks PAN-OS | 认证绕过 → **建立未授权 VPN 连接**；5 月批；KEV 标 `knownRansomwareCampaignUse: Known` | 05-29 / **06-01（已过）** | P1 |
| CVE-2026-104286 | Fortinet FortiMail | 路径穿越 + NULL 字节未中和，**未认证**，经 HTTP/HTTPS 写任意文件 | 10-01 / **10-04（已过）** | P0 |

> **别混**：`CVE-2026-0257`（认证绕过→VPN，5 月收录）与 `CVE-2026-0322`（代码注入→root，10 月收录）是两条不同漏洞、两个批次；缓解措施不通用，**分行处置**（与 `index.md` §2.8 的写法一致）。
> **别夸**：`96656` 要 admin、`96655` 要认证、`110936` 要本地认证——写成「未认证 RCE」是错的，会误导定级。

**判断命令（KEV 核对：任何整改记录都要能对上这个输出）**

```bash
CVE_ID="${1:?usage: bash kev-check.sh CVE-2026-96656}"
curl -s https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json \
  | jq -r --arg id "$CVE_ID" '.vulnerabilities[] | select(.cveID==$id)
      | "\(.cveID)\t\(.vendorProject)\t\(.product)\tadded=\(.dateAdded)\tdue=\(.dueDate)\transomware=\(.knownRansomwareCampaignUse)"'
```

无输出 = 该 CVE 不在当前 KEV（可能编号错，或已移出）；有输出 = 直接按上表档位处置，不等版本确认。

## 检测

前置：先把设备清单写死到一个文件，后面命令直接循环，不留占位符。

```bash
# 0) 设备清单（按 CMDB 填；一行一个主机，型号/归属/暴露面写进变更单）
cat > /tmp/boundary-hosts.txt <<'EOF'
siteguard.example.internal
plex.example.internal
panos-mgmt.example.internal
fortimail.example.internal
EOF
```

```bash
# 1) 暴露面优先：这些产品的问题几乎都从「管理面/媒体端口裸奔公网」开始
while read -r h; do
  echo "== $h"
  curl -sk -m 5 -o /dev/null -w 'https=%{http_code}\n' "https://$h/"
  curl -s  -m 5 -o /dev/null -w 'plex32400=%{http_code}\n' "http://$h:32400/identity" 2>/dev/null
done < /tmp/boundary-hosts.txt
# 端口侧面：在「设备本身或其宿主机」上跑，不是在你的工作站上跑
ss -lntp 2>/dev/null | grep -E ':(32400|443|8443|10443)\b'

# 2) 版本探测：只用只读端点，不用带副作用的接口（升级前留档用，不用于定级）
#    Plex：/identity 直接返回版本
curl -s -m 5 http://plex.example.internal:32400/identity | head -c 400; echo
#    PAN-OS：只读 op 命令（需要 API key，用只读账号）
: "${PAN_KEY:?export PAN_KEY=只读API密钥}"
curl -sk -m 5 "https://panos-mgmt.example.internal/api/?type=op&cmd=<show><system><info></info></system></show>" \
  -H "X-PAN-KEY: $PAN_KEY" | grep -oE '<version>[^<]+' | head -1
#    FortiMail / SiteGuard / Siemens：管理界面版本页或厂商 CLI（人工截图留档，命令按型号走）
```

**命中判据**

- 产品在 KEV 表内 **且** 该设备曾/正暴露于不可信网络 → 直接按 P0/P1 处置，**不等版本确认**；
- 版本只用于两件事：① 升级前留档；② 拿到厂商公告后判定「是否已修」。**单独一个版本号不构成定级依据，也不构成「不用修」的依据**。

## 影响判定

| 条件 | 判定 |
|---|---|
| 边界设备管理面暴露公网 + 该 CVE 在 KEV | **P0**：已被利用的漏洞 + 可利用入口；先摘入口，再谈升级 |
| Plex 对公网开放（尤其开了远程访问/中继） | **P0**：`96652` 任意 token 值即 SSRF，可与 `96654/96655/96656` 链式放大；Plex 常放 DMZ |
| Plex 仅内网且无远程访问 | P1：仍升级，但先做网络收敛与账号盘点 |
| PAN-OS 有可认证面（管理用户 / 低权账号 / VPN 门户） | **P1**：`0322` 直通 root；`0257` 可直接建未授权 VPN（且 KEV 标勒索利用已发生）→ 查账号、查 VPN 会话 |
| KEV dueDate 已过（`0322` / `0257` / `104286`） | **合规风险**：按「逾期未整改」上报；不因「没出事」搁置 |
| FortiMail 对公网开放 | **P0**：`104286` 未认证写任意文件 |
| 仅内网、无远程入口 | P2：按变更窗口升级；仍要查是否被横向利用 |
| Siemens Software Center | **P2**：本地已认证利用（DLL 侧载），不因边界设备未暴露而排除，**终端侧同样要查** |

**误报排除**

- 只在 KEV 里看到名字、自家没部署该产品 → 不适用，别开工单；
- `0257` 是认证绕过、`0322` 是代码注入，**别用一条的缓解措施套另一条**；
- `96656` 需 admin、`96655` 需认证：内部已无相关账号 → 风险显著下降，但仍要升级（账号可能是共享/弱口令）；
- 设备型号不同、固件分支不同 → 版本比较无意义，必须对同一固件线取厂商公告。

## 修复

顺序：**摘入口（分钟级）→ 回厂商公告取 fixed（本件不代劳）→ 升级 → 复核**。

### 4.1 摘入口（先做，不等版本号）

```bash
# 管理面只留内网/VPN：安全组或设备 ACL 先收口，示例仅示意语义，按设备实际改写
#   iptables -I INPUT -p tcp --dport 443 -s <可信网段> -j ACCEPT
#   iptables -I INPUT -p tcp --dport 443 -j DROP
# Plex：关远程访问与中继；32400 不对公网；不用的插件禁用
# PAN-OS：管理面仅内网；VPN 门户核对账号与 MFA
```

### 4.2 回厂商公告取 fixed（本件的核心交付动作）

| 产品 | 公告入口（按 CVE 号检索） | 必须摘下来的字段 |
|---|---|---|
| SiteGuard Server Edition | 厂商安全公告（EG Secure Solutions） | 受影响版本、fixed 版本、workaround |
| Plex Media Server | Plex 官方 release notes / security 公告 | 四条 CVE 各自的 fixed 版本（**不接受社区流传数字**） |
| Siemens Software Center | Siemens ProductCERT（SSA 系列） | 受影响版本、fixed 版本 |
| PAN-OS | Palo Alto 官方安全公告站 | `0322` / `0257` **分开查**，各自 fixed 与缓解措施 |
| FortiMail | Fortinet PSIRT（FG-IR 系列） | 受影响版本矩阵、fixed 版本 |

记录格式（进变更单）：`CVE | 公告 URL | 阅读日期 | 我方当前版本 | 公告 fixed | 判定（已修/需升/无补丁）`。
**公告没写的版本号不许猜；公告只给 workaround 的，按 workaround 执行并标「未修复」。**

### 4.3 升级

```bash
# 形态示意：命令按产品实际改写，版本号来自 4.2 的公告，本件不提供
#   Plex:   停服务 → 换包 → 起服务 → /identity 核版本
#   PAN-OS: 管理面升级并重启（HA 对端顺序按厂商文档）
#   FortiMail: 固件升级（保留配置备份与旧固件包）
```

**加固（不依赖 CVE）**：管理面一律不裸公网；开 MFA；限来源 IP；Plex 关远程访问/中继；监控管理面登录失败、异常出站、设备日志外发。

## 验证

```bash
# 1) 暴露面已收敛（从公网位置跑，必须不可达）
curl -sk -m 5 -o /dev/null -w 'mgmt=%{http_code}\n' https://panos-mgmt.example.internal/   # 期望 000/超时
curl -s  -m 5 -o /dev/null -w 'plex=%{http_code}\n' http://plex.example.internal:32400/identity

# 2) 版本已到「公告里的 fixed」（对照 4.2 记录，不是对照本文件）
curl -s -m 5 http://plex.example.internal:32400/identity | head -c 400; echo
curl -sk -m 5 "https://panos-mgmt.example.internal/api/?type=op&cmd=<show><system><info></info></system></show>" \
  -H "X-PAN-KEY: $PAN_KEY" | grep -oE '<version>[^<]+' | head -1
#    FortiMail / SiteGuard / Siemens：管理面版本页截图留档

# 3) KEV 对账（整改记录要能对上 dueDate）
for c in CVE-2026-106931 CVE-2026-96652 CVE-2026-96654 CVE-2026-96655 CVE-2026-96656 CVE-2026-110936 CVE-2026-0322 CVE-2026-0257 CVE-2026-104286; do
  curl -s https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json \
    | jq -r --arg id "$c" '.vulnerabilities[] | select(.cveID==$id) | "\(.cveID) due=\(.dueDate)"'
done
```

**通过标准**

1. 管理面/媒体端口从不可信网络不可达（公网实测，留截图）；
2. 每条已处置 CVE 都有「厂商公告 URL + 阅读日期 + 公告 fixed + 我方当前版本」四件套；
3. 版本 = 公告 fixed（**不是**本文件或二手数字）；公告未给 fixed 的，标「未修复 + workaround 已上」；
4. 已查账号与会话：无异常管理账号、无异常 VPN 会话、无异常出站；
5. 整改记录写明 KEV 编号与 dueDate，逾期项有上报记录；
6. 终端侧（Siemens）单独确认，不因边界加固而跳过。

## 回退

```bash
# 设备类升级的回退依赖两样东西，升级前必须备好：
#   1) 配置全量导出 + 校验（升级后配置损坏是最常见回退原因）
#   2) 旧固件/安装包 + 回滚步骤（厂商文档中的 downgrade 路径）
# 示例形态（按产品改写）：
#   PAN-OS:  export configuration snapshot；确认 downgrade 受限条件
#   Plex:    保留旧版本安装包与 library 数据库备份
#   FortiMail/SiteGuard/Siemens: 导出配置、记录固件版本、留旧固件包
```

**回退后风险**：回退到仍在 KEV 的版本 = 继续暴露在**已被实际利用**的漏洞下；回退期间必须保留 4.1 的网络层隔离（管理面不出网），并给出再升级时间点。**不允许「回退即收工」。**

## 待核实

| 项 | 状态 | 缺什么才能定 |
|---|---|---|
| 五家厂商的精确 fixed 版本（SiteGuard / Plex / Siemens / PAN-OS / FortiMail） | **未确认** | 各自公告原文；**KEV 不提供** |
| Plex `v1.43.2` | **社区流传，未核实** | Plex 官方 release notes；核实前不得写入工单结论 |
| FortiMail `CVE-2026-104286` 受影响版本矩阵 | **未确认** | 厂商页此前 403，只索引可见，需一手正文 |
| `CVE-2026-110936` 是否仅本地利用 | 待核 | Siemens SSA 原文（KEV 原文已说明「authenticated local attacker」） |
| 各设备实际暴露面（谁在公网） | 待实测 | 本件 §检测 的暴露面扫描结果 |

## 来源

| 类型 | URL |
|---|---|
| 一手（CISA KEV catalog JSON；本地实测 catalogVersion 2026.10.21，count 1754，9 条逐条核对） | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json |
| 一手（CISA KEV 目录页，按 CVE 查询） | https://www.cisa.gov/known-exploited-vulnerabilities-catalog |

> 厂商公告 URL 待一手核实后补 `sources.md` 再引用；本件当前**只有 KEV 一个一手来源**，因此保持 `draft`。
