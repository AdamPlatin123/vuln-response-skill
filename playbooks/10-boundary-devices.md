---
id: "10"
title: 在野利用簇 · 边界与媒体设备应急（KEV 9 条 · 逐分支厂商修复版已核）
ecosystem: generic
cve: ["CVE-2026-106931", "CVE-2026-96652", "CVE-2026-96654", "CVE-2026-96655", "CVE-2026-96656", "CVE-2026-110936", "CVE-2026-0322", "CVE-2026-0257", "CVE-2026-104286"]
affects: "按「分支 + hotfix 线」逐条判定（非合并 semver）：Plex `<1.43.3.10861`；FortiMail `8.0.0–8.0.1` / `7.6.0–7.6.6` / `7.4.0–7.4.8` / `7.2.0–7.2.9`；SiteGuard `>=Ver2.20`（IIS 3.10–4.00U4 不受影响）；Siemens `<V4.0.9.8`；PAN-OS `0322` 12.2.0–12.2.3 / 12.1.2–12.1.10-h* / 11.2.0–11.2.15 / 11.1.0–11.1.16-h* / 10.2.0–10.2.18-h*，`0257` 12.1.2–12.1.6 / 11.2.0–11.2.12 / 11.1.0–11.1.15 / 10.2.0–10.2.18-h* + Prisma Access"
fixed: ["Plex 1.43.3.10861（发布时为 Plex Pass Beta 通道；稳定通道待核）", "FortiMail 逐线 8.0.2 / 7.6.7 / 7.4.9（7.2 无同分支修复，需跨分支升 7.4+）", "SiteGuard Ver8.00 Update 5（8.00U5，Apache/Nginx/IIS）/ Ver7.00 Update 6（7.00U6，FreeBSD）+ EOL 补丁", "Siemens V4.0.9.8", "PAN-OS CVE-2026-0322 逐分支：12.2.4｜12.1.4-h12/12.1.7-h8/12.1.10-h2｜11.2.4-h22/11.2.7-h21/11.2.10-h15/11.2.13-h3/11.2.16｜11.1.4-h37/11.1.6-h39/11.1.7-h11/11.1.10-h35/11.1.13-h15/11.1.16-h3｜10.2.7-h38/10.2.10-h41/10.2.13-h26/10.2.16-h11/10.2.18-h12", "PAN-OS CVE-2026-0257 逐分支：12.1.4-h6/12.1.7｜11.2.4-h17/11.2.7-h14/11.2.10-h7/11.2.12｜11.1.4-h33/11.1.6-h32/11.1.7-h6/11.1.10-h25/11.1.13-h5/11.1.15｜10.2.7-h34/10.2.10-h36/10.2.13-h21/10.2.16-h7/10.2.18-h6｜Prisma 11.2.7-h13/10.2.10-h36"]
severity: "严重（9 条全部在 CISA KEV = 已被实际利用；3 条 dueDate 已逾期，3 条 2026-10-23 到期；PAN-OS `0322` CVSS-BT 8.6、`0257` 7.8，均 `E:A`；SiteGuard 4.0 8.5 / 3.0 7.8，厂商确认在野）"
status: verified
sources: ["https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "https://forums.plex.tv/t/plex-media-server/30447/712", "https://www.fortiguard.com/psirt/FG-IR-26-175", "https://jvn.jp/en/jp/JVN88474777/", "https://cert-portal.siemens.com/productcert/html/ssa-580366.html", "https://security.paloaltonetworks.com/CVE-2026-0322", "https://security.paloaltonetworks.com/CVE-2026-0257"]
updated: 2026-10-22
---

# 在野利用簇 · 边界与媒体设备应急

**一句话**：这 9 条**全部在 CISA KEV**（= 已被实际利用）。五家厂商的修复版本已**逐条取到一手**；本件最关键的不是记住某个版本号，而是**逐分支/逐线对表**——Plex / FortiMail / SiteGuard / PAN-OS 都是分支制，写成「升到最新版」会把已经在自己分支打过补丁的用户误标未修。

> **四条硬规则**
> 1. **fixed 来自厂商公告，不来自 KEV**（KEV 没有 fixed 字段）。社区流传的 Plex `v1.43.2` **是错的**，正确是 `1.43.3.10861`。
> 2. **分支/hotfix 不能合并成单区间**：同一分支上有多条 `<` 线，**任一条命中即受影响**；判据 = 拿自己分支的当前串对表。
> 3. **同厂商相邻 CVE 分行**：PAN-OS `0322`（10 月批，认证后 RCE）与 `0257`（5 月批，GlobalProtect 认证绕过）是两条不同漏洞，缓解与公告都不同。
> 4. **版本只用于「是否已修」**；定级看暴露面与 KEV，不看版本。

## 适用版本区间

以下 KEV 字段取自本地 `kev.json`（catalogVersion **2026.10.21**，count 1754）；修复版本来自各厂商一手公告。

| CVE | 产品 | KEV 原文要点（判定依据） | added / due | 处置档 |
|---|---|---|---|---|
| CVE-2026-106931 | EG Secure Solutions SiteGuard Server Edition | OS 命令注入，**可为 root 或 SYSTEM**（KEV 原文）；CVSS 4.0 **8.5** / 3.0 7.8 | 10-20 / **10-23** | P0 |
| CVE-2026-96652 | Plex Media Server | SSRF，**任意 `X-Plex-Token` 值即可**，可强制服务端 POST 到攻击者目标；可与 96654/96655/96656 链式 | 10-20 / 11-03 | P0（公网暴露时） |
| CVE-2026-96654 | Plex Media Server | 编码 URI scheme 未中和 → 可调其他插件函数并自带参数；可链式 | 10-20 / **10-23** | P0 |
| CVE-2026-96655 | Plex Media Server | SSRF，**需已认证用户**，经 `/video/:/transcode/universal` 路径参数 | 10-20 / 11-03 | P1 |
| CVE-2026-96656 | Plex Media Server | 文件名/路径外部控制，**需 admin**，可写任意文件、加载时可能执行；可链式 | 10-20 / **10-23** | P1（**不是未认证 RCE**） |
| CVE-2026-110936 | Siemens Software Center | 不受控搜索路径，**需本地已认证**，DLL 侧载 → 以应用权限执行；**厂商确认在野利用** | 10-20 / 11-03 | P2（终端侧） |
| CVE-2026-0322 | Palo Alto Networks PAN-OS | 管理面代码注入，**需已认证（PR:H）+ 网络访问** → root；CVSS-BT **8.6**、`E:A ATTACKED`；**无官方 workaround** | 10-14 / **10-17（已过）** | P1（逐分支表见 4.5） |
| CVE-2026-0257 | Palo Alto Networks PAN-OS | GlobalProtect 认证绕过 → **建立未授权 VPN 连接**；5 月批；CVSS-BT **7.8**、`E:A`；**有官方缓解** | 05-29 / **06-01（已过）** | P1（逐分支表见 4.5） |
| CVE-2026-104286 | Fortinet FortiMail | 路径穿越 + NULL 字节未中和，**未认证**，经 HTTP/HTTPS 写任意文件 | 10-01 / **10-04（已过）** | P0 |

**逐家受影响面与修复版（一张表看完）**

| 产品 | 受影响 | 修复 | 依据 |
|---|---|---|---|
| Plex Media Server | `<1.43.3.10861`（四条 CVE 同区间） | **`1.43.3.10861`**（发布时 **Plex Pass Beta 通道**；稳定通道待核） | 厂商版本公告 + CNA/NVD 记录 |
| FortiMail | `8.0.0–8.0.1` / `7.6.0–7.6.6` / `7.4.0–7.4.8` / `7.2.0–7.2.9` | **逐线** `8.0.2` / `7.6.7` / `7.4.9`；**7.2 无同分支修复 → 跨分支升 7.4+** | FG-IR-26-175 |
| SiteGuard Server Edition | `>=Ver2.20`（IIS **3.10–4.00U4 不受影响**；需统计功能开启，**默认开**） | **Ver8.00 Update 5**（Apache/Nginx/IIS）/ **Ver7.00 Update 6**（FreeBSD）；EOL 版本另有补丁 | JVN#88474777 |
| Siemens Software Center | `All versions < V4.0.9.8` | **`V4.0.9.8`**（启动时自动更新） | SSA-580366 |
| PAN-OS `CVE-2026-0322` | 12.2.0–12.2.3；12.1.2–12.1.10-h*；11.2.0–11.2.15；11.1.0–11.1.16-h*；10.2.0–10.2.18-h* | 逐分支，见 4.5 | security.paloaltonetworks.com |
| PAN-OS `CVE-2026-0257` | 12.1.2–12.1.6；11.2.0–11.2.12；11.1.0–11.1.15；10.2.0–10.2.18-h*；Prisma Access 11.2/10.2 | 逐分支，见 4.5 | security.paloaltonetworks.com |

> **别混**：`0257` 是认证绕过、`0322` 是代码注入；`0257` 有缓解、`0322` 没有；**别用一条的缓解措施套另一条**。
> **别夸**：`96656` 要 admin、`96655` 要认证、`110936` 要本地认证——写成「未认证 RCE」是错的。

## 检测

前置：把设备清单写死到文件，后面命令直接循环。

```bash
# 0) 设备清单（按 CMDB 填；一行一个主机，型号/归属写在变更单）
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
  curl -sk -m 5 -o /dev/null -w 'https=%{http_code}\n' "https://$h/" 2>/dev/null
  curl -s  -m 5 -o /dev/null -w 'plex32400=%{http_code}\n' "http://$h:32400/identity" 2>/dev/null
done < /tmp/boundary-hosts.txt
# 端口侧面：在「设备本身或其宿主机」上跑，不是在你的工作站上跑
ss -lntp 2>/dev/null | grep -E ':(32400|443|8443|10443)\b'

# 2) 版本探测：只用只读端点/命令，升级前留档
#    Plex：/identity 直接返回版本（形如 1.43.3.10861）
curl -s -m 5 http://plex.example.internal:32400/identity | head -c 400; echo
#    PAN-OS：**取分支+hotfix 全串**，不要归一成 base 版本
#      设备本地：ssh "$PAN_HOST" 'show system info | match sw-version'
#      API（只读账号）：
: "${PAN_KEY:?export PAN_KEY=只读API密钥}"
curl -sk -m 5 "https://panos-mgmt.example.internal/api/?type=op&cmd=<show><system><info></info></system></show>" \
  -H "X-PAN-KEY: $PAN_KEY" | grep -oE '<sw-version>[^<]+' | head -1   # 例：11.2.7-h20
#    FortiMail：CLI `get system status`（取 Version 行），或管理界面 About
#    SiteGuard / Siemens：管理界面版本页（SiteGuard 看 Update 号：8.00U5 / 7.00U6；Siemens 看 V4.0.9.8）
```

**PAN-OS 逐分支对表（可直接跑，判「已修/未修」）**

判定顺序：**先看自己维护线（同 base）的 hotfix 要求 → 若无同线要求，再看是否已到本分支最高修复版**。
只按「存在某条 `<` 线」判会在另一个方向出错（例：`11.2.7-h21` 已修，但仍 `< 11.2.10-h15`）。

```bash
python3 - <<'PY'
def vt(v):
    """'11.2.7-h21' → (11,2,7)：跨维护线比较；hotfix 只在同 base 内比较"""
    return tuple(int(x) for x in v.partition("-h")[0].split("."))

def state(cur, fixes):
    cb, _, ch = cur.partition("-h")
    br = vt(cur)[:2]                              # 只在本分支内兜底，别跨 minor
    same = [f for f in fixes if f.partition("-h")[0] == cb]
    if same:                                      # ① 同维护线：按 hotfix 要求判
        for f in same:
            _, _, fh = f.partition("-h")
            if not fh:
                return "FIXED"                    # 该维护线无需 hotfix
            if ch and int(ch) >= int(fh):
                return "FIXED"
        return "AFFECTED"
    in_branch = [f for f in fixes if vt(f)[:2] == br]
    if not in_branch:
        return "NO-DATA"                          # 本分支公告未列修复版（可能本就不受影响）→ 查公告
    plain = [f for f in in_branch if "-h" not in f]
    if plain and vt(cur) >= max(vt(f) for f in plain):
        return "FIXED"                            # ② 本分支最高修复版兜底
    return "AFFECTED"

fix_0322 = ["12.2.4",
            "12.1.4-h12","12.1.7-h8","12.1.10-h2",
            "11.2.4-h22","11.2.7-h21","11.2.10-h15","11.2.13-h3","11.2.16",
            "11.1.4-h37","11.1.6-h39","11.1.7-h11","11.1.10-h35","11.1.13-h15","11.1.16-h3",
            "10.2.7-h38","10.2.10-h41","10.2.13-h26","10.2.16-h11","10.2.18-h12"]
fix_0257 = ["12.1.4-h6","12.1.7",
            "11.2.4-h17","11.2.7-h14","11.2.10-h7","11.2.12",
            "11.1.4-h33","11.1.6-h32","11.1.7-h6","11.1.10-h25","11.1.13-h5","11.1.15",
            "10.2.7-h34","10.2.10-h36","10.2.13-h21","10.2.16-h7","10.2.18-h6"]

for cur in ["11.2.6","11.2.7-h20","11.2.7-h21","11.2.14","11.2.16","12.1.8","12.2.3","10.2.18-h5","10.2.18-h12"]:
    print(f"{cur:<12} 0322={state(cur, fix_0322):<8} 0257={state(cur, fix_0257)}")
# 自检（必须逐条对上）：
#   0322：11.2.6 / 11.2.7-h20 / 11.2.14 / 12.1.8 / 12.2.3 / 10.2.18-h5 → AFFECTED；11.2.7-h21 / 11.2.16 / 10.2.18-h12 → FIXED
#   0257：11.2.6 / 10.2.18-h5 → AFFECTED；11.2.14 / 11.2.16（≥11.2.12）/ 12.1.8 / 10.2.18-h12 → FIXED；12.2.3 → NO-DATA（该分支公告未列，查原文）
PY
```

**命中判据**

- 产品在 KEV 表内 **且** 该设备曾/正暴露于不可信网络 → 直接按 P0/P1 处置，**不等版本确认**；
- 版本只用于两件事：① 升级前留档；② 判定「是否已修」。**单独一个版本号不构成定级依据，也不构成「不用修」的依据**；
- 分支制产品：**先认分支/维护线，再比 hotfix**；把「比某条线小」跨线套用会两头出错（漏判或误判）。

## 影响判定

| 条件 | 判定 |
|---|---|
| 边界设备管理面暴露公网 + 该 CVE 在 KEV | **P0**：已被利用的漏洞 + 可利用入口；先摘入口，再谈升级 |
| Plex 对公网开放（尤其开了远程访问/中继） | **P0**：`96652` 任意 token 值即 SSRF，可与 `96654/96655/96656` 链式放大；Plex 常放 DMZ |
| Plex 仅内网且无远程访问 | P1：仍升级，但先做网络收敛与账号盘点 |
| PAN-OS 有可认证面（管理用户 / 低权账号 / VPN 门户） | **P1**：`0322` 直通 root；`0257` 可直接建未授权 VPN（KEV 标勒索利用已发生）→ 查账号、查 VPN 会话 |
| FortiMail 对公网开放 | **P0**：`104286` 未认证写任意文件 |
| SiteGuard 统计功能开启（**默认开**）+ 管理面可达 | **P0**：OS 命令注入可致 root/SYSTEM；厂商已确认在野利用 |
| Siemens 终端装了 Software Center | **P2**：本地已认证利用（DLL 侧载），不因边界设备未暴露而排除，**终端侧同样要查** |
| KEV dueDate 已过（`0322` / `0257` / `104286`） | **合规风险**：按「逾期未整改」上报；不因「没出事」搁置 |
| 仅内网、无远程入口 | P2：按变更窗口升级；仍要查是否被横向利用 |

**误报排除**

- 只在 KEV 里看到名字、自家没部署该产品 → 不适用，别开工单；
- **SiteGuard IIS 3.10–4.00U4 不受影响**（JVN 原文），别把整站都算命中；
- `96656` 需 admin、`96655` 需认证：内部已无相关账号 → 风险显著下降，但仍要升级（账号可能是共享/弱口令）；
- Plex 稳定通道用户暂时拿不到 `1.43.3.10861` → 不是「不受影响」，是「修复通道待核」，按暴露面先行收敛；
- 设备型号不同、固件分支不同 → 版本比较无意义，必须对同一分支线取厂商公告。

## 修复

顺序：**摘入口（分钟级）→ 按分支对表 → 升级/重发布 → 验证 → 记录**。

### 4.1 摘入口（先做，不等版本号）

```bash
# 管理面只留内网/VPN：安全组或设备 ACL 先收口（语义示意，按设备改写）
#   iptables -I INPUT -p tcp --dport 443 -s <可信网段> -j ACCEPT
#   iptables -I INPUT -p tcp --dport 443 -j DROP
# Plex：关远程访问与中继；32400 不对公网；不用的插件禁用
# PAN-OS：管理面仅内网；VPN 门户核对账号与 MFA
# FortiMail：关 IBE（官方 workaround）——config system encryption ibe / set status disable
```

### 4.2 Plex

```bash
# 升级到 1.43.3.10861（发布时走 Plex Pass Beta 通道；稳定通道到位时间待核）
# 容器：换镜像 tag 并认 digest；裸机：用官方安装包，保留旧版本包用于回退
docker pull "${PLEX_IMAGE:?export PLEX_IMAGE=plexinc/pms-docker:1.43.3.10861}"
docker inspect -f '{{index .RepoDigests 0}}' "$PLEX_IMAGE"
# 升级后核对：/identity 返回的 version 必须是 1.43.3.10861
curl -s -m 5 http://plex.example.internal:32400/identity | head -c 400; echo
```

### 4.3 FortiMail（逐线，7.2 只能跨分支）

| 线 | 受影响 | 修复 |
|---|---|---|
| 8.0 | `8.0.0–8.0.1` | `8.0.2` |
| 7.6 | `7.6.0–7.6.6` | `7.6.7` |
| 7.4 | `7.4.0–7.4.8` | `7.4.9` |
| 7.2 | `7.2.0–7.2.9` | **本线无修复** → 跨分支升 7.4+（回退风险单列） |

```bash
# 版本比较（Docker/generic）：v<fix 时 sort -V 会把 v 排在前
v="7.4.8"; fix="7.4.9"; printf '%s\n%s\n' "$v" "$fix" | sort -V | head -1   # 输出 7.4.8 = 需升级
# 升级：管理界面「系统 → 固件升级」上传对应线固件；升级前导出配置 + 留旧固件包
# 官方 workaround（升不了时）：关 IBE —— config system encryption ibe / set status disable
```

**7.2 跨分支升级**：先确认配置兼容性与厂商 downgrade 路径；**回退到 7.2 = 重新暴露**，回退风险必须单列进变更单，不能与同分支 patch 混写。

### 4.4 SiteGuard / Siemens

```bash
# SiteGuard：按部署形态选线，Update 号必须对上
#   Apache httpd / Nginx / IIS → Ver8.00 Update 5（8.00U5）
#   FreeBSD                 → Ver7.00 Update 6（7.00U6）
#   EOL 版本另有补丁（按 JVN 原文取，别当「无补丁」）
# Siemens Software Center：升到 V4.0.9.8（启动时自动更新；离线环境用厂商安装包）
#   核对：Software Center 的 About/版本页必须是 V4.0.9.8
```

### 4.5 PAN-OS 逐分支判定表（两条 CVE 分开，**任一 `<` 线命中即受影响**）

取值：`show system info | match sw-version` 得到**分支+hotfix 全串**（如 `11.2.7-h20`），按串比对。

**CVE-2026-0322**（认证后代码注入 → root；CVSS-BT **8.6**、`E:A ATTACKED`、`PR:H`；**无官方 workaround**）

| 分支 | 受影响的上界线（任一命中即受影响） | 对应修复（同维护线达到即算修） |
|---|---|---|
| 12.2 | `<12.2.4` | `12.2.4` |
| 12.1 | `<12.1.4-h12` / `<12.1.7-h8` / `<12.1.10-h2` | 同线对应版本之一 |
| 11.2 | `<11.2.4-h22` / `<11.2.7-h21` / `<11.2.10-h15` / `<11.2.13-h3` / `<11.2.16` | 同线对应版本之一 |
| 11.1 | `<11.1.4-h37` / `<11.1.6-h39` / `<11.1.7-h11` / `<11.1.10-h35` / `<11.1.13-h15` / `<11.1.16-h3` | 同线对应版本之一 |
| 10.2 | `<10.2.7-h38` / `<10.2.10-h41` / `<10.2.13-h26` / `<10.2.16-h11` / `<10.2.18-h12` | 同线对应版本之一 |

**CVE-2026-0257**（GlobalProtect 认证绕过 → 未授权 VPN；CVSS-BT **7.8**、`E:A`；**有官方缓解**）

| 分支 | 受影响的上界线（任一命中即受影响） | 对应修复（同维护线达到即算修） |
|---|---|---|
| 12.1 | `<12.1.4-h6` / `<12.1.7` | 同线对应版本之一 |
| 11.2 | `<11.2.4-h17` / `<11.2.7-h14` / `<11.2.10-h7` / `<11.2.12` | 同线对应版本之一 |
| 11.1 | `<11.1.4-h33` / `<11.1.6-h32` / `<11.1.7-h6` / `<11.1.10-h25` / `<11.1.13-h5` / `<11.1.15` | 同线对应版本之一 |
| 10.2 | `<10.2.7-h34` / `<10.2.10-h36` / `<10.2.13-h21` / `<10.2.16-h7` / `<10.2.18-h6` | 同线对应版本之一 |
| Prisma Access | `<11.2.7-h13` / `<10.2.10-h36` | 同线对应版本之一 |

- **`0257` 官方缓解**（升不了时止血，不是修复）：关闭 **Authentication Override**，或改用专用证书。
- **`0257` 升级后 GlobalProtect 用户需重新认证一次**（写进变更单，别让用户以为掉线）。
- `0322` 的 Threat ID **510046 / 510047** 仅有限覆盖且**需 SSL 解密**，不能当补偿控制。
- **标签对齐**：本表 `Prisma Access` 对应 inventory 标签 `prisma-11.2` / `prisma-10.2`（下游脚本按字符串匹配时别判成两套）。
- 升级顺序：管理面升级并重启；HA 对端顺序按厂商文档（先备后主，逐台）。
- **两条不是同一批**：`0322` 10 月批 / `0257` 5 月批——**分行查、分行处置**。
- **`NO-DATA` 的处置**：脚本输出 `NO-DATA` = 公告未给该分支修复版（如 `0257` 对 `12.2.x`），**不等于已修、也不等于未修**——回公告确认该分支是否在受影响面，确认前不得按「已修」上线，也不得盲目跨分支升级，记录写「已查公告 + 结论」。

### 4.6 加固（不依赖 CVE）

管理面一律不裸公网；开 MFA；限来源 IP；Plex 关远程访问/中继；FortiMail 关不必要的 IBE；监控管理面登录失败、异常出站、设备日志外发；SiteGuard 非必要时关统计功能（默认开）。

## 验证

```bash
# 1) 暴露面已收敛（从公网位置跑，必须不可达）
curl -sk -m 5 -o /dev/null -w 'mgmt=%{http_code}\n' https://panos-mgmt.example.internal/    # 期望 000/超时
curl -s  -m 5 -o /dev/null -w 'plex=%{http_code}\n' http://plex.example.internal:32400/identity

# 2) 版本串「在受影响线外」——逐家取证，不是看「升级成功」
curl -s -m 5 http://plex.example.internal:32400/identity | grep -oE '1\.43\.[0-9.]+' | head -1   # 期望 1.43.3.10861
#    PAN-OS：取全串后跑「检测」段的对表脚本，输出必须全为 FIXED
ssh "${PAN_HOST:?export PAN_HOST=panos-mgmt}" 'show system info | match sw-version'
#    FortiMail：另存 `get system status` 的 Version 行，与 4.3 表逐线比对
#    SiteGuard：管理界面 Update 号 = 8.00U5 或 7.00U6（按部署形态）
#    Siemens：About 页版本 = V4.0.9.8

# 3) GP 重认证（0257 专属，升级后执行）
#    通知 GlobalProtect 用户重新登录一次；核对 VPN 会话数回到基线

# 4) KEV 对账（整改记录要能对上 dueDate）
for c in CVE-2026-106931 CVE-2026-96652 CVE-2026-96654 CVE-2026-96655 CVE-2026-96656 CVE-2026-110936 CVE-2026-0322 CVE-2026-0257 CVE-2026-104286; do
  curl -s https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json \
    | jq -r --arg id "$c" '.vulnerabilities[] | select(.cveID==$id) | "\(.cveID) due=\(.dueDate)"'
done
```

**通过标准**

1. 管理面/媒体端口从不可信网络不可达（公网实测，留截图）；
2. **版本串对表结论为「已修」**：Plex = `1.43.3.10861`；FortiMail 在自己线上 ≥ `8.0.2`/`7.6.7`/`7.4.9`（7.2 已跨分支）；SiteGuard = `8.00U5` / `7.00U6`；Siemens = `V4.0.9.8`；PAN-OS 对表脚本结论为 `FIXED`，或 `NO-DATA` + 已查公告记录（`NO-DATA` 不得计为 `FIXED`）；
3. 每条已处置 CVE 都有「厂商公告 URL + 阅读日期 + 我方当前版本串 + 公告 fixed」四件套；
4. 已查账号与会话：无异常管理账号、无异常 VPN 会话、无异常出站；FortiMail 查 IoC（`79.141.169.187` / `45.129.0.192`，含 cron 型系统事件）；
5. 整改记录写明 KEV 编号与 dueDate，逾期项有上报记录；
6. 终端侧（Siemens）单独确认；SiteGuard 统计功能若已关，记录关闭范围与到期时间。

## 回退

```bash
# 0) 升级前落基线（版本串 / 配置导出 / 旧固件包 / 镜像 digest）
: "${CHG:?export CHG=变更单号}"; mkdir -p "/secure/change/$CHG"
{
  echo "plex=$(curl -s -m 5 http://plex.example.internal:32400/identity | grep -oE '1\.43\.[0-9.]+' | head -1)"
  echo "panos=$(ssh "$PAN_HOST" 'show system info | match sw-version')"
  echo "fortimail=$(ssh "$FMG_HOST" 'get system status' | grep -i '^Version')"
} | tee "/secure/change/$CHG/pre-boundary.txt"

# 1) Plex：回退旧安装包/旧镜像 digest（保留旧版本包是前提）
docker pull "<旧镜像 digest>"
# 2) FortiMail：回退旧固件（配置导出 + 厂商 downgrade 路径必须先确认）
# 3) SiteGuard：回退旧 Update 包（EOL 版本补丁需单独留档）
# 4) Siemens：回退旧安装包（自动更新环境下需先禁用自动更新）
# 5) PAN-OS：导入配置快照 + 回退旧固件（HA 对端顺序按厂商文档）
```

**回退后风险**：回退到仍在 KEV 的版本 = 继续暴露在**已被实际利用**的漏洞下。**FortiMail 7.2 属于跨分支升级，回退即回到无同分支修复的状态**，必须单列风险并给再升级时间点；PAN-OS 回退后必须保留 4.5 的缓解（`0257` 关 Authentication Override）。**不允许「回退即收工」。**

## 条目

| 编号 | 组件 | 受影响 | 修复 | 来源 |
|---|---|---|---|---|
| CVE-2026-106931 | SiteGuard Server Edition | `>=Ver2.20`（IIS 3.10–4.00U4 不受影响；统计功能默认开） | `8.00U5` / `7.00U6`（+ EOL 补丁） | https://jvn.jp/en/jp/JVN88474777/ |
| CVE-2026-96652 | Plex Media Server（SSRF） | `<1.43.3.10861` | `1.43.3.10861` | https://forums.plex.tv/t/plex-media-server/30447/712 |
| CVE-2026-96654 | Plex Media Server（URI scheme） | `<1.43.3.10861` | `1.43.3.10861` | 同上 |
| CVE-2026-96655 | Plex Media Server（SSRF，需认证） | `<1.43.3.10861` | `1.43.3.10861` | 同上 |
| CVE-2026-96656 | Plex Media Server（路径控制，需 admin） | `<1.43.3.10861` | `1.43.3.10861` | 同上 |
| CVE-2026-110936 | Siemens Software Center | `<V4.0.9.8` | `V4.0.9.8` | https://cert-portal.siemens.com/productcert/html/ssa-580366.html |
| CVE-2026-0322 | PAN-OS（认证后 RCE） | 12.2.0–12.2.3 / 12.1.2–12.1.10-h* / 11.2.0–11.2.15 / 11.1.0–11.1.16-h* / 10.2.0–10.2.18-h* | 逐分支，见 4.5 | https://security.paloaltonetworks.com/CVE-2026-0322 |
| CVE-2026-0257 | PAN-OS（GP 认证绕过，有缓解） | 12.1.2–12.1.6 / 11.2.0–11.2.12 / 11.1.0–11.1.15 / 10.2.0–10.2.18-h* / Prisma 11.2·10.2 | 逐分支，见 4.5 | https://security.paloaltonetworks.com/CVE-2026-0257 |
| CVE-2026-104286 | FortiMail | `8.0.0–8.0.1` / `7.6.0–7.6.6` / `7.4.0–7.4.8` / `7.2.0–7.2.9` | `8.0.2` / `7.6.7` / `7.4.9`；7.2 跨分支 | https://www.fortiguard.com/psirt/FG-IR-26-175 |

> 与 `vuln-w1/inventory.tsv` 对应：W1-046~054（`merge_key` 逐条 `kev-*`）。

## 待核

| 项 | 状态 | 说明 |
|---|---|---|
| Plex 稳定通道版本 | **待核** | `1.43.3.10861` 发布时为 Plex Pass Beta 通道；post #713 同为 10861，post #714 已到 `1.43.3.10896` |
| Plex「4 CVE ↔ 1.43.3.10861」的对应粒度 | 已注明 | 版本公告**未逐条点名**四个 CVE，是 CNA/NVD 描述 + 版本公告两处拼合；措辞按「CNA 记录 + 版本公告」，不写「厂商逐条确认」 |
| SiteGuard 厂商页 | 已留证 | `eg-secure.co.jp/siteguard/news/alert-202610-1` 302 跳首页；以 **JVN 一手**为准，厂商页恢复后补原文 |
| Siemens IoC 细节 | 待侦察补 | ProductCERT News 有 IoC 章节，本件只引用「厂商确认在野利用」 |

## 来源

| 类型 | URL |
|---|---|
| 一手（CISA KEV catalog JSON；catalogVersion 2026.10.21，count 1754，9 条逐条核对） | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json |
| 一手（Plex 版本公告 #712，1.43.3.10861 发布原文） | https://forums.plex.tv/t/plex-media-server/30447/712 |
| 一手（Fortinet PSIRT FG-IR-26-175：受影响矩阵 / 逐线 fixed / IBE workaround / IoC） | https://www.fortiguard.com/psirt/FG-IR-26-175 |
| 一手（JVN#88474777：受影响条件 / Update 号 / CVSS / 在野确认 / EOL 补丁） | https://jvn.jp/en/jp/JVN88474777/ |
| 一手（Siemens SSA-580366：`<V4.0.9.8` → `V4.0.9.8`）+ ProductCERT News 在野确认 | https://cert-portal.siemens.com/productcert/html/ssa-580366.html |
| 一手（PAN-OS CVE-2026-0322：逐分支 Product Status / CVSS-BT 8.6 / E:A / 无 workaround / Threat ID） | https://security.paloaltonetworks.com/CVE-2026-0322 |
| 一手（PAN-OS CVE-2026-0257：逐分支 fixed / CVSS-BT 7.8 / 缓解 / GP 重认证 / Prisma Access） | https://security.paloaltonetworks.com/CVE-2026-0257 |
