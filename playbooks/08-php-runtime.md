---
id: "08"
title: PHP 运行时 RCE 应急（CVE-2026-109618 / CVE-2026-109619）
ecosystem: php
cve: ["CVE-2026-109618", "CVE-2026-109619"]
affects: "8.2.x <8.2.35；8.3.x <8.3.36；8.4.x <8.4.27；8.5.x <8.5.12；8.1 及更早**无补丁**（已过安全维护期）"
fixed: ["8.2.35", "8.3.36", "8.4.27", "8.5.12"]
severity: "严重 CVSS 9.2（官方口径；泄露传播的 10.0 是错的）"
status: verified
sources: ["https://www.php.net/archive/2026.php#2026-10-21-5", "https://thephp.foundation/blog/2026/10/21/todays-php-security-release-and-how-were-strengthening-php-security/", "https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w", "https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp"]
updated: 2026-10-21
---

# PHP 运行时 RCE 应急

**一句话**：两条 RCE 落在**内存管理与错误处理**上——几乎每个请求都会碰到的位置。**Apache + mod_php 上未认证请求可在应用代码执行前触发**，默认配置下已演示完整 RCE。修复版本 `8.2.35 / 8.3.36 / 8.4.27 / 8.5.12`；**8.1 没有补丁，只能升分支**。

## 适用版本区间

| 分支 | 受影响 | 修复 |
|---|---|---|
| 8.5.x | `<8.5.12` | `8.5.12` |
| 8.4.x | `<8.4.27` | `8.4.27` |
| 8.3.x | `<8.3.36` | `8.3.36` |
| 8.2.x | `<8.2.35` | `8.2.35` |
| **8.1 及更早** | 全部 | **无补丁**（已过安全维护期）→ 升分支 |

**不在区间内的判断命令**

```bash
php -v | head -1
php -r 'echo PHP_VERSION, PHP_EOL;' 2>/dev/null
# CLI 与 web SAPI 可能是两个包/两个二进制，必须分别查
php-fpm -v 2>/dev/null | head -1
```

## 检测

```bash
# 1) 关键：先确认是不是 mod_php（决定未认证面）
for p in $(which -a php php-fpm 2>/dev/null); do echo "== $p"; "$p" -v 2>/dev/null | head -1; done
php -i 2>/dev/null | grep -E '^Server API'      # "Apache 2.0 Handler" = mod_php（最高风险面）
php -i 2>/dev/null | grep -E '^Loaded Configuration|^Thread Safety'

# 2) 发行版包与是否有 backport 通道
dpkg -l 2>/dev/null | awk '/^ii/ && /php/{print $2, $3}' | head -30
apt-cache policy php8.3-fpm 2>/dev/null | head -6
rpm -qa 2>/dev/null | grep -E '^php' | head -20

# 3) 容器与镜像
docker ps --format '{{.Names}}\t{{.Image}}' | grep -iE 'php|fpm|apache'
docker exec <CONTAINER> php -v | head -1

# 4) 暴露面：mod_php + 公网 = 最危险组合
ss -lntp 2>/dev/null | grep -E ':(80|443|9000)\b'
curl -s -m 5 -o /dev/null -w 'public=%{http_code}\n' https://<站点>/health

# 5) 扩展/opcache（升级会牵动）
php -m 2>/dev/null | tr '\n' ' '; echo
php -i 2>/dev/null | grep -E 'opcache.enable|memory_limit' | head -4
```

**命中判据**：`php -v` 低于所在分支修复版即命中；`Server API` 为 **Apache 2.0 Handler** 的实例按 P0 排；8.1 及更早无论 `php -v` 显示什么，都按「无补丁」处理。

## 影响判定

| 条件 | 判定 |
|---|---|
| **mod_php** + 公网可达 | **P0**：未认证请求在应用代码前触发，默认配置已演示 RCE |
| PHP-FPM + 公网 | **P1**：RCE 已在应用层代码路径上确认；不是「FPM 就安全」 |
| 仅内网 / 需认证 | P1–P2：仍升级，按变更窗口排 |
| 8.1 及更早 | P1：**结构性无补丁**，只能升分支；不因「暂无在野」而降低 |
| CLI 批处理 | P3：无 HTTP 面，随镜像一起升 |

**两个必须说清的现状**

1. **官方口径：发布时尚未确认在野利用**（PHP Foundation 原文：「did not identify any functional exploits at the time of release」）。但 embargo 已被 Chainguard 于 **07:41 UTC** 单方面打破并发布含修复镜像，PoC 在 10-21 加速扩散——**按「数小时内会出现可用利用」排期，不按「暂无在野」拖**。
2. **CVSS 是 9.2，不是 10.0**。10.0 是 10-20 泄露时传播的错误分数，别引用。

**误报排除**

- 容器 tag 写 `php:8.3` 不代表已含补丁，必须看 `php -v` 小版本；
- 只有 CLI、没有 web SAPI 的机器攻击面为 0，但仍随镜像升级；
- 8.1 的发行版 backport 若存在（需查发行版 tracker），可先用 backport，但**不能当长期方案**。

## 修复

顺序：**先确认 SAPI → 立刻打补丁 → 8.1 升分支 → 回归**。这两条没有可靠的配置级 workaround：漏洞在内存管理与错误处理，几乎每个请求都会走到。

```bash
# 1) 发行版补丁（最快；发行版通常已提前拿到补丁）
apt-get update && apt-get -y --only-upgrade install 'php8.2-*' 'php8.3-*' 'php8.4-*' 'php8.5-*'
apt list --upgradable 2>/dev/null | grep -i php
dnf -y upgrade 'php*' 2>/dev/null

# 2) 版本断言：打完必须核对，别只看 apt 说成功
php -v | head -1
php-fpm -v 2>/dev/null | head -1

# 3) 容器：换 digest，不在容器里 apt upgrade
docker pull php:8.3-fpm-bookworm
docker image inspect php:8.3-fpm-bookworm --format '{{json .RepoDigests}}'
# Dockerfile: FROM php:8.3-fpm-bookworm@sha256:<digest>

# 4) 8.1 升分支（无补丁，唯一解）
#    先冻结 CI/部署 → 预发跑全量 → 切 alternatives → 重启 FPM
apt-get -y install php8.3-fpm php8.3-cli php8.3-<扩展清单>
update-alternatives --set php /usr/bin/php8.3
systemctl restart php8.3-fpm
```

**高成本缓解（补丁未到位时的窗口期）**

| 手段 | 效果 | 代价 |
|---|---|---|
| mod_php → php-fpm | 把「未认证、应用代码前」降为「应用层路径可达」 | 架构改动，需回归 |
| 入口限流 + 只放行已知来源 | 降低被扫到的概率 | 有限，不是修复 |
| 关闭不必要模块、减少并发触发面 | 降低触发概率 | 不确定，别当解决方案 |

> 不要把「调 `memory_limit`」当成修复——OOM 是触发条件之一，不是全部。

**CI / 防复发**

```bash
docker run --rm <image> php -v | head -1
composer check-platform-reqs 2>/dev/null
```

## 验证

```bash
# 1) 每个 SAPI 的版本都到修复版（CLI 与 FPM 分开）
php -v | head -1                 # 期望 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12
php-fpm -v 2>/dev/null | head -1
docker exec <CONTAINER> php -v | head -1

# 2) 扩展与配置没被升级弄丢
php -m 2>/dev/null | wc -l       # 与升级前基线对比
php -i 2>/dev/null | grep -E 'opcache.enable|memory_limit'

# 3) 业务冒烟（走 web SAPI，不是 CLI）
curl -s -o /dev/null -w '%{http_code}\n' https://<站点>/health

# 4) 回退演练
systemctl status php8.3-fpm --no-pager | head -5
```

**通过标准**

1. CLI 与 web SAPI 的 `php -v` 都在修复版本（不允许「CLI 升了 FPM 没升」）；
2. `php -m` 与基线一致，opcache 正常加载；
3. 站点健康检查 200、核心链路冒烟通过；
4. 容器 digest 已固定，CI 断言运行时版本；
5. 若从 8.1 升级，弃用告警已收敛或有处理计划；
6. 8.1 实例已排入升分支计划（不是「先观察」）。

## 回退

```bash
# 0) 升级前先落基线（包版本 / 镜像 digest 都要记）
#    CHG=变更单号，CURRENT_IMAGE=当前运行镜像
: "${CHG:?export CHG=变更单号}" "${CURRENT_IMAGE:?export CURRENT_IMAGE=当前运行镜像}"
mkdir -p "/secure/change/$CHG"
PRE_FPM=$(dpkg-query -W -f='${Version}' php8.3-fpm 2>/dev/null)
PRE_DIGEST=$(docker inspect -f '{{index .RepoDigests 0}}' "$CURRENT_IMAGE" 2>/dev/null)
printf '%s\n%s\n' "$PRE_FPM" "$PRE_DIGEST" | tee "/secure/change/$CHG/pre-php.txt"

# 包路线（回退到基线 deb 版本，再重启 FPM）
apt-get -y install "php8.3-fpm=$PRE_FPM" && systemctl restart php8.3-fpm
php-fpm -v 2>/dev/null | head -1

# 容器路线（认 digest，不认 tag）
docker pull "$PRE_DIGEST"   # RepoDigests 已是 name@sha256: 完整引用
kubectl set image "deploy/${APP:?export APP=deployment名}" "${CONTAINER:?export CONTAINER=容器名}=$PRE_DIGEST"

# 回退后立刻确认 SAPI 与版本（CLI 与 FPM 分开看）
php -v | head -1; php -i 2>/dev/null | grep -E '^Server API'
```

**回退后风险**：回退即重新暴露 CVE-2026-109618 / 109619——mod_php + 公网 = 未认证 RCE。回退只允许出现在「升级引发业务故障」的短窗口，且必须同时：入口限流/摘流量、把再升级时间点写进变更单；不允许回退即收工。

## 来源

| 类型 | URL |
|---|---|
| 一手（php.net 发布公告：8.5.12 / 8.4.27 / 8.3.36 / 8.2.35） | https://www.php.net/archive/2026.php#2026-10-21-5 |
| 一手（PHP Foundation 原文：mod_php 未认证、默认配置 RCE、FPM 应用层路径、CVSS 9.2、embargo 被打破） | https://thephp.foundation/blog/2026/10/21/todays-php-security-release-and-how-were-strengthening-php-security/ |
| 一手（GHSA-w8hw-w9fx-j79w：CVE-2026-109618，OOM corruption） | https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w |
| 一手（GHSA-6wmf-4rv5-p3rp：CVE-2026-109619，stale state / UAF） | https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp |
| 一手（php.net 支持分支列表：只列 8.2–8.5） | https://www.php.net/supported-versions.php |
