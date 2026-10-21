---
id: "02"
title: LiteLLM 多 CVE 升级矩阵与 1.82.7/1.82.8 供应链事故处置
ecosystem: python-llm
cve: ["CVE-2026-42208", "CVE-2026-35029", "CVE-2026-35030", "CVE-2026-59823", "CVE-2026-84377"]
affects: "CVE-2026-42208: >=1.81.16 <1.83.7；CVE-2026-35029/35030 与 GHSA-69x8: <1.83.0；CVE-2026-59823: <1.83.9；CVE-2026-84377: <1.88.6 且 1.89–1.96 各分支低于对应分支修复版；投毒包: 1.82.7 / 1.82.8（仅 2026-03-24 窗口）"
fixed: ["1.83.0", "1.83.7", "1.83.9", "1.88.6", "1.89.7", "1.90.7", "1.91.5", "1.92.2", "1.93.2", "1.94.3", "1.95.1", "1.96.2", "1.106.2"]
severity: "严重（42208 未认证 9.8 + KEV；其余需已认证 key，含 RCE 与凭据外泄）"
status: verified
sources: ["https://github.com/advisories/GHSA-r75f-5x8p-qvmc", "https://github.com/advisories/GHSA-3cv6-jpf6-8222", "https://github.com/advisories/GHSA-hx8v-g79f-8w5f", "https://docs.litellm.ai/blog/security-update-march-2026"]
updated: 2026-10-21
---

# LiteLLM 多 CVE 升级矩阵与供应链事故

**一句话**：「升到 1.83.7」只修了那一条未认证 SQLi。**LiteLLM 现在是 5 条 CVE + 1 起投毒事故、多分支修复**，按全局 semver 比较必然升错线。

## 适用版本区间

| 编号 | 类型 | 认证前提 | 受影响 | 修复 |
|---|---|---|---|---|
| CVE-2026-42208 | 未认证 SQLi（**CVSS 9.8，KEV 收录**） | **无** | `>=1.81.16 <1.83.7` | `1.83.7` |
| CVE-2026-35029 | `/config/update` 无角色校验 → RCE / 任意文件读 / 接管 admin | 需**有效 key** | `<1.83.0` | `1.83.0` |
| CVE-2026-35030 | OIDC userinfo 缓存键碰撞（`token[:20]`）→ 认证绕过 | 需开 `enable_jwt_auth`（默认关） | `<1.83.0` | `1.83.0` |
| GHSA-69x8-hrgq-fjj8 | 密码哈希泄露 + pass-the-hash 登录（**无 CVE 别名**） | 认证 | `<1.83.0` | `1.83.0` |
| CVE-2026-59823 | `user_config` 嵌套 `api_base` SSRF | 有效 virtual key | `<1.83.9` | `1.83.9` |
| CVE-2026-84377 | 已认证 SSRF + **provider 凭据外泄** | 认证 | `<1.88.6`；且 1.89–1.96 各分支低于下表 | **分支表** |
| PyPI 投毒（非 CVE） | `litellm==1.82.7` / `1.82.8` 凭据窃取器 | — | 2026-03-24 **10:39–16:00 UTC** 窗口内装到 | clean = `1.83.0`；两版已从 PyPI 移除 |

**CVE-2026-84377 分支修复表（OSV 原文，禁止合并成「升到 1.96.2 就行」）**

| 分支 | 修复版本 |
|---|---|
| `<1.89` | `1.88.6` |
| `1.89.x` | `1.89.7` |
| `1.90.x` | `1.90.7` |
| `1.91.x` | `1.91.5` |
| `1.92.x` | `1.92.2` |
| `1.93.x` | `1.93.2` |
| `1.94.x` | `1.94.3` |
| `1.95.x` | `1.95.1` |
| `1.96.x` | `1.96.2` |

**不在区间内的判断命令**

```bash
python3 - <<'PY'
import importlib.metadata as m, re
raw = m.version("litellm")
v = tuple(int(x) for x in re.match(r"\d+\.\d+\.\d+", raw).group(0).split("."))
branch_fix = {(1,88):(1,88,6),(1,89):(1,89,7),(1,90):(1,90,7),(1,91):(1,91,5),(1,92):(1,92,2),
              (1,93):(1,93,2),(1,94):(1,94,3),(1,95):(1,95,1),(1,96):(1,96,2)}
if v < (1,83,0):   print(f"{raw}: AFFECTED 35029/35030/GHSA-69x8 -> 1.83.0")
if v < (1,83,7):   print(f"{raw}: AFFECTED 42208 -> 1.83.7")
if v < (1,83,9):   print(f"{raw}: AFFECTED 59823 -> 1.83.9")
if v < (1,88,6):   print(f"{raw}: AFFECTED 84377 -> 1.88.6")
elif v[:2] in branch_fix and v < branch_fix[v[:2]]:
    print(f"{raw}: AFFECTED 84377 on branch -> {branch_fix[v[:2]]}")
elif v[:2] in branch_fix:
    print(f"{raw}: 84377 OK on branch")
else:
    print(f"{raw}: 不在 GHSA-3cv6 范围表内，先查 OSV 再宣称安全")
PY
```

## 检测

```bash
# 1) 版本（进程所在环境，不是宿主机）
pip show litellm 2>/dev/null | grep -i '^version'
python3 -c 'import importlib.metadata as m; print(m.version("litellm"))'
docker exec <CONTAINER> pip show litellm | grep -i '^version'

# 2) 是否踩过 1.82.7/1.82.8 投毒窗口（这步不能用自己的 python/pip 执行）
#    被投毒环境里的 python 一启动就可能执行 .pth，所以用 find/grep 只读盘点
find / -name 'litellm_init.pth' 2>/dev/null
grep -rIl 'models\.litellm\.cloud' /usr/lib/python3*/site-packages /usr/local/lib/python3*/site-packages /opt 2>/dev/null | head
grep -rIl 'checkmarx\.zone' /usr/lib/python3*/site-packages /usr/local/lib/python3*/site-packages 2>/dev/null | head

# 3) 部署面
docker ps --format '{{.Names}}\t{{.Image}}' | grep -i litellm
kubectl get deploy -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{"\t"}{..image}{"\n"}{end}' 2>/dev/null | grep -i litellm

# 4) 暴露面（42208 只看这一条是否公网可达）
curl -s -m 5 -o /dev/null -w 'public=%{http_code}\n' https://<公网域名>/health/readiness

# 5) 相关开关（35030 需要 JWT 才命中）
grep -Rn 'enable_jwt_auth' config.yaml .env 2>/dev/null
```

**命中判据**：版本命中上表任一行；或磁盘上存在 `litellm_init.pth` / `models.litellm.cloud` / `checkmarx.zone` 字符串（**投毒命中，直接走重建流程，不要先升级**）。

## 影响判定

| 条件 | 判定 |
|---|---|
| 版本 <1.83.7 且 proxy 曾公网可达 | **P0**：42208 未认证 + KEV → 立即止血、升级、轮换全部密钥 |
| 版本 <1.83.0 | **P1**：同时命中 3 条（含 RCE 与哈希泄露），先升 1.83.0+ |
| 1.83.0–1.83.6 | P1：42208 未认证优先；其余已含 1.83.0 修复 |
| 1.83.7–1.83.8 | P2：59823 仍在，升 1.83.9 |
| 1.83.9–1.88.5 | P2：84377 仍在（需认证），按分支表升 |
| 1.89–1.96 低于分支修复版 | P2：按分支表升，**不许跨大版本跳** |
| 命中投毒文件/字符串 | **P0 事故**：视为机器已被窃密，走「重建 + 吊销」，升级救不了 |

**误报排除**

- 只用 SDK、没跑 proxy：42208/35029/59823/84377 都打 proxy 路径，暴露面为 0，但仍升级；
- `enable_jwt_auth` 未开：35030 不命中（不是「没风险」）；
- 1.82.7/1.82.8 已从 PyPI 消失（`pip index versions` 看不到）——**看不到 ≠ 没装过**，必须查磁盘。

## 修复

顺序：**止血（若 42208 暴露过）→ 按分支升级 → 投毒则重建 → 全量轮换 → 取证**。

### 4.1 止血（只针对 42208 / 公网暴露）

```bash
# A. 入口摘除或拒绝（业务可降级时）
#    nginx: location = /chat/completions { deny all; }
# B. 官方 workaround：切断错误处理路径（缓解，不是修复）
#    config.yaml -> general_settings.disable_error_logs: true
docker restart <CONTAINER>
# C. 确认外网不可达
curl -s -m 5 -o /dev/null -w '%{http_code}\n' https://<公网域名>/health/readiness
```

### 4.2 按分支升级（决策树）

```bash
# ① 还在 1.83 线：升到该线终点（覆盖 42208/35029/35030/69x8/59823）
pip install "litellm[proxy]==1.83.10"

# ② 1.84–1.88 线：升到 1.88.6
pip install "litellm[proxy]==1.88.6"

# ③ 1.89–1.96 线：升到本分支修复版，不跨线
pip install "litellm[proxy]==1.89.7"   # 或 1.90.7 / 1.91.5 / 1.92.2 / 1.93.2 / 1.94.3 / 1.95.1 / 1.96.2

# ④ 已经 >=1.97：不在这张表内 -> 先用前一段脚本判定，再查 OSV 确认
# ⑤ 想一步到位：1.106.2（2026-10-21 PyPI 最新）可作目标，但跨度大，必须回归
pip install -U "litellm[proxy]"
```

> 云/容器部署：镜像 tag 必须先 `docker run --rm <image> pip show litellm` 验证版本，再切流量。别信「tag 写了 stable 就是新版」。

### 4.3 投毒命中（1.82.7 / 1.82.8）——重建，不升级

```bash
# 1) 保全：磁盘只读快照 + 可疑 .pth 文件哈希（不要执行该环境的 python）
sha256sum $(find / -name 'litellm_init.pth' 2>/dev/null) >> /secure/incident/pth.sha256
# 2) 重建：新机器/新镜像从 1.83.0+ 干净安装（锁 hash）
pip install --require-hashes -r requirements.txt
# 3) 吊销：全部凭据按 06 轮换（env / SSH / 云 / K8s token / DB 口令都在窃取清单里）
# 4) 审计：CI 构建缓存、pip cache、镜像层里是否留有旧 .pth
grep -rIl 'litellm_init.pth' /root/.cache /var/cache 2>/dev/null
```

### 4.4 密钥轮换与取证

```bash
# 轮换按 playbook 06（先加后减、双读窗口、引用计数归零才禁用）
# 取证：SQL 错误痕迹（42208）+ 出站到 models.litellm.cloud（投毒）
docker logs <CONTAINER> --since 720h 2>&1 | grep -Ei 'syntax error at or near|unterminated quoted string' | wc -l
```

```sql
SELECT calls, total_exec_time, query FROM pg_stat_statements
WHERE query ILIKE '%LiteLLM_VerificationToken%' ORDER BY total_exec_time DESC LIMIT 50;
```

### 4.5 CI 防复发

```yaml
- run: pip install --require-hashes -r requirements.txt   # 锁 hash，挡掉投毒版本
- run: pip-audit -r requirements.txt
- run: trivy image --severity HIGH,CRITICAL --exit-code 1 <image>
```

## 验证

```bash
# 1) 版本落在「本分支修复版」而不是随便一个高版本
python3 -c 'import importlib.metadata as m;print(m.version("litellm"))'

# 2) 42208 复现探针：必须是 401，不能 200/500
curl -s -o /dev/null -w 'sqli=%{http_code}\n' -X POST http://127.0.0.1:4000/chat/completions \
  -H "Authorization: Bearer x' OR '1'='1" -H 'Content-Type: application/json' -d '{}'

# 3) 认证类 CVE 边界：无 key 不得触达 admin 路由
curl -s -o /dev/null -w 'config_update=%{http_code}\n' -X POST http://127.0.0.1:4000/config/update \
  -H 'Content-Type: application/json' -d '{}'          # 期望 401/403

# 4) 投毒残留：必须为空
find / -name 'litellm_init.pth' 2>/dev/null | wc -l                                   # 期望 0
grep -rIl 'models\.litellm\.cloud' /usr/lib/python3*/site-packages 2>/dev/null | wc -l # 期望 0

# 5) 功能回归
curl -s -o /dev/null -w 'liveliness=%{http_code}\n' http://127.0.0.1:4000/health/liveliness
curl -s -o /dev/null -w 'models=%{http_code}\n' http://127.0.0.1:4000/models -H "Authorization: Bearer $NEW_MASTER_KEY"
```

**通过标准**

1. 版本 = 所在分支的修复版（不是「看起来够高」），容器内一致；
2. 42208 探针 401、`/config/update` 未授权 403；
3. 投毒残留扫描全为 0；若曾命中，重建与吊销均有记录；
4. 旧 key 全部失效（401），新 key 全链路可用（06 的验收门槛）；
5. 出站无 `models.litellm.cloud` / `checkmarx.zone` 连接；
6. 回归：`/health/liveliness` 200、模型调用成功、用量记账正常。

## 回退

```bash
# 只允许在同一分支内回退，且不得低于该分支修复版
pip install "litellm[proxy]==<本分支修复版>"
```

**回退后风险**：回退到 `1.83.7` 以下 = 重开 42208（未认证 9.8 + KEV）；回退到 `1.88.6` 以下 = 重开 84377（凭据外泄）。新版本若有业务回归，只能回退到**本分支修复版**并保留网络层止血；禁止跨分支回退到更低修复线。

## 观察项（不进处置结论）

| 编号 | 内容 | 状态 |
|---|---|---|
| GHSA-7hp6-4w63-5g45 | salt key 伪造 admin → RCE | 二手定位，修复版本与 CVE 号待补；不写进处置步骤 |
| GHSA-g5ff-… | viewer LFI | 待补精确编号与修复版本 |
| Check Point 研究原文 | https://research.checkpoint.com/2026/when-llm-gateways-go-wrong-findings-from-litellm/ | 正文未抓取，不作引用 |

## 来源

| 类型 | URL |
|---|---|
| 一手（LiteLLM 官方：42208 影响/修复/推荐版本） | https://docs.litellm.ai/blog/cve-2026-42208-litellm-proxy-sql-injection |
| 一手（GHSA-r75f-5x8p-qvmc：42208，CVSS 9.8、CWE-89、workaround） | https://github.com/advisories/GHSA-r75f-5x8p-qvmc |
| 一手（GHSA-53mr-6c8q-9789：CVE-2026-35029，修 1.83.0） | https://github.com/advisories/GHSA-53mr-6c8q-9789 |
| 一手（GHSA-jjhc-v7c2-5hh6：CVE-2026-35030，修 1.83.0） | https://github.com/advisories/GHSA-jjhc-v7c2-5hh6 |
| 一手（GHSA-hx8v-g79f-8w5f：CVE-2026-59823，修 1.83.9） | https://github.com/advisories/GHSA-hx8v-g79f-8w5f |
| 一手（GHSA-3cv6-jpf6-8222：CVE-2026-84377，多分支修复表） | https://github.com/advisories/GHSA-3cv6-jpf6-8222 |
| 一手（GHSA-69x8-hrgq-fjj8：密码哈希泄露，修 1.83.0，无 CVE） | https://github.com/advisories/GHSA-69x8-hrgq-fjj8 |
| 一手（官方 3 月供应链事件：1.82.7/1.82.8、时间窗、IoC、clean=1.83.0） | https://docs.litellm.ai/blog/security-update-march-2026 |
| 一手（CISA KEV：42208 已被利用） | https://www.cisa.gov/known-exploited-vulnerabilities-catalog |
