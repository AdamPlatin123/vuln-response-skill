---
id: "10"
title: 在野利用簇 · 边界与媒体设备应急（CISA KEV 收录）
ecosystem: generic
cve: ["CVE-2026-106931", "CVE-2026-96652", "CVE-2026-96654", "CVE-2026-96655", "CVE-2026-96656", "CVE-2026-110936", "CVE-2026-0322", "CVE-2026-0257", "CVE-2026-104286"]
affects: "KEV 收录即「已被利用」：SiteGuard Server Edition；Plex Media Server；Siemens Software Center；PAN-OS；FortiMail"
fixed: ["修复版本按厂商公告（未逐条确认，见「待核实」）；KEV 不含 fixed 字段"]
severity: "严重（全部已在 CISA KEV；其中多条 dueDate 已过）"
status: draft
sources: ["https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"]
updated: 2026-10-21
---

# 在野利用簇 · 边界与媒体设备应急

**一句话**：这 9 条**全部在 CISA KEV**，即「已被实际利用」，处置逻辑与「有补丁待升级」完全不同——**先摘暴露面，再查版本，最后谈升级**。KEV 不给修复版本，版本必须回厂商公告核，本文件不编版本号。

## 适用版本区间

不按 semver 判定，按 **KEV 收录 + 暴露面** 判定。KEV 数据本地实测（catalogVersion 2026.10.21）：

| CVE | 产品 | 类型 | 收入 KEV | dueDate |
|---|---|---|---|---|
| CVE-2026-106931 | EG Secure Solutions SiteGuard Server Edition | OS 命令注入（root/SYSTEM） | 2026-10-20 | **2026-10-23** |
| CVE-2026-96656 | Plex Media Server | 文件路径控制 → 可 RCE | 2026-10-20 | **2026-10-23** |
| CVE-2026-96654 | Plex Media Server | 编码 URI scheme 处理不当 | 2026-10-20 | **2026-10-23** |
| CVE-2026-96652 | Plex Media Server | SSRF | 2026-10-20 | 2026-11-03 |
| CVE-2026-96655 | Plex Media Server | SSRF | 2026-10-20 | 2026-11-03 |
| CVE-2026-110936 | Siemens Software Center | 不受控搜索路径（DLL 侧载，本地 → ACE） | 2026-10-20 | 2026-11-03 |
| CVE-2026-0322 | Palo Alto PAN-OS | 代码注入（**认证**攻击者 → root） | 2026-10-14 | **2026-10-17（已过）** |
| CVE-2026-0257 | Palo Alto PAN-OS | 认证绕过 | 2026-05-29 | **2026-06-01（已过）** |
| CVE-2026-104286 | Fortinet FortiMail | 路径穿越 | 2026-10-01 | **2026-10-04（已过）** |

> **不要混**：`CVE-2026-0257`（PAN-OS 认证绕过，5 月收录）与 `CVE-2026-0322`（PAN-OS 代码注入，10 月收录）是两条不同漏洞。

**判断命令**

```bash
CVE_ID="${1:?missing CVE id}"
curl -s https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json \
  | jq -r --arg id "$CVE_ID" '.vulnerabilities[] | select(.cveID==$id)
      | "\(.cveID)\t\(.vendorProject)\t\(.product)\tadded=\(.dateAdded)\tdue=\(.dueDate)"'
```

## 检测

```bash
# 1) 先把「暴露在不可信网络」的设备清单拉出来（这比版本号更重要）
#    边界设备/媒体服务器通常自管端口，先从外部扫自己
for h in <siteguard-host> <plex-host> <panos-mgmt> <fortimail>; do
  echo "== $h"; curl -sk -m 5 -o /dev/null -w '%{http_code}\n' "https://$h/"
done
ss -lntp 2>/dev/null | grep -E ':(32400|443|8443|10443)\b'

# 2) 版本探测（按产品各自的只读端点；不要用带副作用的接口）
#    Plex：/identity 返回版本
curl -s -m 5 http://<plex-host>:32400/identity | head -c 400
#    PAN-OS：管理面版本（需授权，只读）
curl -sk -m 5 'https://<panos-mgmt>/api/?type=op&cmd=<show><system><info></info></system></show>' \
  -H "X-PAN-KEY: $PAN_KEY" | head -c 400
#    FortiMail / SiteGuard / Siemens：以管理界面版本页或厂商 CLI 为准

# 3) 管理面是否暴露公网（这 9 条的常见失陷入口）
curl -sk -m 5 -o /dev/null -w 'mgmt=%{http_code}\n' https://<mgmt-host>/
```

**命中判据**：产品在 KEV 表内 + 该设备曾/正暴露于不可信网络 → **按 P0/P1 处置**，不等版本确认。版本只在「确认修复与否」时用。

## 影响判定

| 条件 | 判定 |
|---|---|
| 边界设备管理面暴露公网 + KEV 收录 | **P0**：已被利用的漏洞 + 可利用入口；先隔离 |
| 媒体服务器（Plex）对公网开放 | **P0**：96656 可 RCE，且 Plex 常被放在 DMZ |
| PAN-OS 有认证攻击面（管理用户/低权账号） | **P1**：0322 需认证但直通 root；查账号与会话 |
| KEV dueDate 已过（0322/0257/104286） | **合规风险**：按「逾期未整改」上报，不因「没出事」而搁置 |
| 纯内网、无远程入口 | P2：按变更窗口升级，仍要查是否被横向利用 |

**误报排除**

- 只在 KEV 里看到名字、自家没部署该产品 → 不适用，别进工单；
- PAN-OS 的 0257 是认证绕过、0322 是代码注入，**别用一条的缓解措施套另一条**；
- Siemens Software Center 是**本地**利用（DLL 侧载），不因边界设备未暴露而排除——终端侧同样要升。

## 修复

顺序：**摘入口 → 查版本 → 厂商公告定版本 → 升级 → 复核**。

```bash
# 1) 摘入口（分钟级，先做）：管理面只留内网/VPN
#    防火墙/安全组：禁止 0.0.0.0/0 访问管理端口
#    临时 ACL 示例（iptables 语义，按设备实际改写）
#    iptables -I INPUT -p tcp --dport 443 -s <可信网段> -j ACCEPT
#    iptables -I INPUT -p tcp --dport 443 -j DROP

# 2) 版本 → 修复版本：必须回厂商公告核对（KEV 不提供）
#    Plex：查官方 release notes 确认修复版本（社区流传 v1.43.2，本稿未核实）
#    PAN-OS：查 Palo Alto 安全公告对应 CVE 的 fixed 版本
#    FortiMail：查 Fortinet PSIRT 公告（FG-IR 系列）
#    SiteGuard：查厂商公告
#    Siemens：查 Siemens ProductCERT SSA

# 3) 升级（示例形态；命令按产品实际改写）
#    Plex: 停服务 → 换包 → 起服务 → /identity 核版本
#    PAN-OS: 管理面升级并重启（注意 HA 对端顺序）
```

**加固（不依赖 CVE）**

- 边界设备管理面一律不裸奔公网；开 MFA；限制来源 IP；
- Plex 关掉不需要的远程访问/中继；
- 监控：管理面登录失败、异常出站、设备日志外发。

## 验证

```bash
# 1) 版本已到厂商公告的 fixed 版本
curl -s -m 5 http://<plex-host>:32400/identity | head -c 400
#    PAN-OS / FortiMail / SiteGuard / Siemens：管理面版本页截图留档

# 2) 暴露面已收敛（从公网位置跑，必须不可达）
curl -sk -m 5 -o /dev/null -w '%{http_code}\n' https://<mgmt-host>/    # 期望 000/超时

# 3) KEV 复核（整改记录要能对上 dueDate）
CVE_ID="<整改的编号>"; curl -s https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json \
  | jq -r --arg id "$CVE_ID" '.vulnerabilities[] | select(.cveID==$id) | "\(.cveID) due=\(.dueDate)"'
```

**通过标准**

1. 管理面从不可信网络不可达（公网实测）；
2. 版本 = 厂商公告的修复版本（留截图/命令输出）；
3. 已查账号与会话：无异常管理账号、无异常出站；
4. 整改记录写明 KEV 编号与 dueDate，逾期项有上报记录；
5. 终端侧（Siemens）单独确认已升级，不因边界加固而跳过。

## 回退

```bash
# 设备类升级的回退依赖厂商镜像/配置备份：升级前导出配置 + 记录当前版本
# 例：PAN-OS 升级前 snapshot 配置；Plex 保留旧版本安装包
```

**回退后风险**：回退到仍在 KEV 的版本 = 继续暴露在已被利用的漏洞下。回退期间必须保留网络层隔离（管理面不出网），并给出再升级时间点。

## 待核实

| 项 | 状态 |
|---|---|
| 各产品精确 fixed 版本（Plex / PAN-OS / FortiMail / SiteGuard / Siemens） | **未确认**（本稿未抓厂商公告原文；Plex `v1.43.2` 为侦察交件，待核） |
| CVE-2026-110936 是否仅本地利用 | 侦察交件，待厂商公告确认 |
| FortiMail CVE-2026-104286 的受影响版本矩阵 | **未确认**（此前线索称厂商页正文 403，仅索引可见） |

## 来源

| 类型 | URL |
|---|---|
| 一手（CISA KEV catalog JSON，本地实测 catalogVersion 2026.10.21） | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json |
| 一手（CISA KEV 目录页，按 CVE 查询） | https://www.cisa.gov/known-exploited-vulnerabilities-catalog |
