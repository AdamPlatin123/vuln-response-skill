---
id: "11"
title: .NET / ASP.NET Core 2026-10 安全更新（Kestrel HTTP/1 走私 9.4 领衔，6 条）
ecosystem: generic          # 模板枚举无 nuget；inventory 该 6 行 ecosystem=nuget，映射见文末
cve: ["CVE-2026-88092", "CVE-2026-70183", "CVE-2026-70186", "CVE-2026-96230", "CVE-2026-96233", "CVE-2026-96225"]
ghsa: ["GHSA-rv87-ccxw-8ggf", "GHSA-494h-xx7x-5frh", "GHSA-mf4x-w4gh-4656", "GHSA-qjpx-jqm5-h2c4", "GHSA-87vj-4hqv-22p9", "GHSA-w6wh-p4g7-mpj2"]
affects: "8.0.0–8.0.31 / 9.0.0–9.0.20 / 10.0.0–10.0.12 / 11.0.0-preview.1–11.0.0-rc.1（6 条同一组区间）"
fixed: ["8.0.32", "9.0.21", "10.0.13", "11.0.0-rc.2"]
severity: "严重（CVE-2026-88092 Kestrel HTTP/1 请求走私 CVSS 3.1 9.4；其余 7.5–8.8）"
status: verified
sources: ["https://github.com/advisories/GHSA-rv87-ccxw-8ggf", "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-88092", "https://github.com/advisories/GHSA-w6wh-p4g7-mpj2", "https://github.com/dotnet/announcements/issues/472"]
updated: 2026-10-22
---

# .NET / ASP.NET Core 2026-10 安全更新

**一句话**：6 条同一批补丁，**四条分支一个修法**（`8.0.32` / `9.0.21` / `10.0.13` / `11.0.0-rc.2`）；最急的是 `CVE-2026-88092`（Kestrel HTTP/1 请求走私，CVSS 9.4）。

> **最容易修错的一点**：**自包含（self-contained）/ 单文件（single-file）发布，换 runtime 包、装新运行时都不算修**——运行时已被打进产物，必须用含修复 runtime 的 SDK **重新编译、重新发布、重新部署**。框架依赖（framework-dependent）应用才是「装新运行时即可」。

## 适用版本区间

| 分支 | 受影响 | 修复 |
|---|---|---|
| 8.0.x | `>=8.0.0 <=8.0.31` | `8.0.32` |
| 9.0.x | `>=9.0.0 <=9.0.20` | `9.0.21` |
| 10.0.x | `>=10.0.0 <=10.0.12` | `10.0.13` |
| 11.0.0 预览 | `>=11.0.0-preview.1 <=11.0.0-rc.1` | `11.0.0-rc.2` |

6 条 CVE 的区间与修复版本**逐条一致**（各 GHSA 的 `vulnerable_version_range` / `first_patched_version` 原文）。

**不在区间内的判断命令**

```bash
dotnet --list-runtimes | grep -E 'Microsoft\.(AspNetCore|NETCore)\.App'
```

判定：任一 `Microsoft.AspNetCore.App` / `Microsoft.NETCore.App` 版本 `< 8.0.32`（8 线）/ `< 9.0.21`（9 线）/ `< 10.0.13`（10 线）/ `< 11.0.0-rc.2`（11 线）→ 命中。

## 检测

**三处都要查**（只看 `--list-runtimes` 会漏掉自包含/单文件发布）。

```bash
# 1) 共享框架运行时（宿主机 / 容器内）——最直接
dotnet --list-runtimes | grep -E 'Microsoft\.(AspNetCore|NETCore)\.App'

# 2) 主机全貌：RID、base path、SDK 与运行时是否同步（SDK 自带运行时，别只升 SDK 不核对）
dotnet --info

# 3) 已发布产物的 runtimeconfig.json —— 框架依赖 / 自包含 的判据在这里
for f in $(find /srv -name '*.runtimeconfig.json' -not -path '*/obj/*' 2>/dev/null); do
  echo "== $f"
  jq -c '{fw:.runtimeOptions.framework, incl:[.runtimeOptions.includedFrameworks[]?|{name,version}]}' "$f"
done
```

```bash
# 4) 单文件发布没有独立 runtimeconfig.json —— 从构建侧确认（本项为唯一可靠入口）
grep -rn --include='*.csproj' --include='*.props' --include='*.yml' --include='Dockerfile*' \
  -E 'PublishSingleFile|SelfContained|RuntimeIdentifier' . | head -20

# 5) Blazor WASM 服务端包（CVE-2026-96230 专用）
dotnet list package --include-transitive 2>/dev/null | grep -i 'Components.WebAssembly.Server'

# 6) 容器镜像里的运行时（别只看宿主机）
docker ps --format '{{.Names}}\t{{.Image}}' | grep -E 'mcr\.microsoft\.com/dotnet|dotnet|aspnet'
IMAGE="${IMAGE:?export IMAGE=当前运行镜像}"
docker run --rm --entrypoint dotnet "$IMAGE" --list-runtimes | grep -E 'AspNetCore|NETCore'

# 7) 是否真的开了 HTTP/3（CVE-2026-70186 的前提）
grep -rn --include='*.json' --include='*.cs' -E 'Http3|Http1AndHttp2|Protocols' . | head -20
```

**命中判据**

- 第 1 处任一运行时版本落在上表区间 → 命中；
- 第 3 处 `includedFrameworks[].version` 落在区间 → **自包含发布命中**（此时第 1 处可能显示宿主机已是新版，仍然命中）；
- 第 4 处命中 `PublishSingleFile` / `SelfContained` → 该产物按自包含处理，**升级必须重发布**；
- `_framework/debug`（Blazor WASM 开发服务器）对非本机可达 → `CVE-2026-96230` 命中。

**误报排除**

- `dotnet --list-sdks` 显示的 SDK 版本**不是**运行时版本，不能用来判定；
- 宿主机运行时已升到 `8.0.32`，但自包含产物里仍是 `8.0.31` → **仍命中**；
- 只装 SDK 不装 `aspnetcore-runtime-*`：容器/服务器上跑 ASP.NET Core 应用仍可能是旧版。

## 影响判定

| CVE | 组件 | 缺陷 | 触发前提（查这个） | 暴露面 |
|---|---|---|---|---|
| CVE-2026-88092 | `Microsoft.AspNetCore.Server.Kestrel.Core` | HTTP/1 连接被中断后把未读请求体当新请求重解析 → **请求走私 / 失步**（CWE-444） | 对外 HTTP/1 入口 + 前置反代/CDN **复用上行连接**；Kestrel 直接对不可信客户端 | **公网入口 = P0**（CVSS 9.4，AV:N/PR:N） |
| CVE-2026-70183 | Blazor `AuthorizeRouteView`（`Components.Authorization`） | 过期的异步授权结果在导航/授权态变更后被应用 → 绕过当前 `[Authorize]` 判定（CWE-362） | Blazor Server/WebAssembly + 异步授权；**需已认证用户**触发 | 需认证 = P1 |
| CVE-2026-70186 | Kestrel HTTP/3 | 畸形 HTTP/3 reset/abort → 连接处理死锁、线程阻塞堆积 → DoS（CWE-833） | **仅当启用 HTTP/3**；未认证远程可达 | 启用 h3 + 公网 = P1 |
| CVE-2026-96230 | `Components.WebAssembly.Server` | 开发服务器调试页反射未编码异常文本 → 跨源脚本注入（CWE-79，UI:R） | **仅 `dotnet watch` 开发服务器**的未认证 `/_framework/debug` 端点可达 | 开发机被暴露到网络 = P1；仅本机 = P2 |
| CVE-2026-96233 | `System.Runtime`（DateTime 解析） | 希伯来数字格式解析越界读 → **进程终止**（CWE-787） | 应用解析希伯来数字（`he-IL` 等）格式的 DateTime 输入 | 输入可控且公网 = P1 |
| CVE-2026-96225 | .NET Runtime（命名互斥 / 共享内存） | 不安全全局目录 + 符号链接竞态 → 截断/覆盖文件、放宽目录权限、**提权**（CWE-59） | **Linux/macOS 本地攻击者**；应用使用命名 mutex / 共享内存 | 需本地 = P2 |

**误报排除**

- `CVE-2026-88092` 的 GHSA 标题写「Security Feature Bypass」，但摘要与 CWE-444 都是**请求走私/失步**——按走私处置，别被标题带偏；
- 未启用 HTTP/3 → `CVE-2026-70186` 不命中（但版本仍要升）；
- 生产环境不跑 `dotnet watch`、不部署 dev server 包 → `CVE-2026-96230` 暴露面为 0；
- 纯 Windows 服务端 + 无本地多用户 → `CVE-2026-96225` 显著下降（该条平台为 Linux/macOS）。

## 修复

顺序：**判形态（框架依赖 / 自包含）→ 止血（可选）→ 升级或重发布 → 部署 → 验证**。

### 4.1 止血（官方**未给** workaround；以下是缓解，不是修复）

```bash
# CVE-2026-70186：关 HTTP/3，只留 HTTP/1+2（Kestrel 侧）
#   "Kestrel": { "Endpoints": { "Https": { "Protocols": "Http1AndHttp2" } } }
#   或代码：listenOptions.Protocols = HttpProtocols.Http1AndHttp2;
# CVE-2026-96230：不暴露 dotnet watch 开发服务器；生产镜像不含 dev server 包
# CVE-2026-88092：入口网关拒绝「同时带 Transfer-Encoding 与 Content-Length」及畸形 framing（**待验证**，非修复）
# CVE-2026-96225：收紧本地账号与共享内存/mutex 用法（代码级，非通用）
# CVE-2026-96233：无 workaround
```

> 缓解只降概率，不消除漏洞。**能升级就必须升级。**

### 4.2 框架依赖应用：装新运行时

```bash
# 8 线（9/10 线把包名换成 dotnet-runtime-9.0 / 10.0；11 线为预览通道）
sudo apt-get update && sudo apt-get install -y 'aspnetcore-runtime-8.0' 'dotnet-runtime-8.0'
# 构建机同时升 SDK（自带运行时，但必须核对，别只升 SDK）
sudo apt-get install -y 'dotnet-sdk-8.0'

# 升级后按实际输出核对（不要相信包名或 tag）
dotnet --list-runtimes | grep -E 'Microsoft\.(AspNetCore|NETCore)\.App'
```

### 4.3 自包含 / 单文件发布：**必须重编译重发布**

```bash
# 1) 确认构建机 SDK 已含修复 runtime
dotnet --list-runtimes | grep -E 'Microsoft\.(AspNetCore|NETCore)\.App'
# 2) 重发布（自包含 + 单文件示例；RID 按实际）
dotnet publish -c Release -r "${RID:?export RID=linux-x64}" --self-contained true -p:PublishSingleFile=true
# 3) 产物自证：includedFrameworks 的 version 必须已是修复版
jq -c '[.runtimeOptions.includedFrameworks[]?|{name,version}]' "${APP:?export APP=发布产物名}.runtimeconfig.json"
# 4) 重新打镜像 → 按 07 的 G3/G4 部署与验收（旧产物不可复用）
```

**注意**：`dotnet build` 不会替换已发布产物里的 runtime 文件；在宿主机 `apt install` 新运行时对自包含产物**无效**。

### 4.4 容器与 CI

```bash
# 基础镜像换到含修复 runtime 的版本；tag 存在性必须实测，不能只按命名推断
IMAGE="${IMAGE:?export IMAGE=mcr.microsoft.com/dotnet/aspnet:8.0.32-bookworm-slim}"
docker pull "$IMAGE"
docker run --rm --entrypoint dotnet "$IMAGE" --list-runtimes | grep -E 'AspNetCore|NETCore'
```

```yaml
# CI：SDK 版本钉死 + 依赖漏洞扫描进闸门
- run: dotnet list package --vulnerable --include-transitive
- run: dotnet test -c Release
```

- `global.json` 固定 SDK 版本（按升级后 `dotnet --list-sdks` 的实际输出写，**不要照抄推测号**）；
- 自包含产物的构建必须锁 SDK 版本，否则下次构建会悄悄换回旧 runtime。

## 验证

```bash
# 1) 三处版本一致（宿主机 / 容器 / 发布产物）
dotnet --list-runtimes | grep -E 'Microsoft\.(AspNetCore|NETCore)\.App'      # 期望 8.0.32 / 9.0.21 / 10.0.13 / 11.0.0-rc.2
docker run --rm --entrypoint dotnet "$IMAGE" --list-runtimes | grep -E 'AspNetCore|NETCore'
jq -c '[.runtimeOptions.includedFrameworks[]?|{name,version}]' "${APP:?}.runtimeconfig.json"

# 2) Blazor WASM 服务端包已到修复版（若使用）
dotnet list package --include-transitive | grep -i 'Components.WebAssembly.Server'

# 3) 功能回归
dotnet test -c Release
curl -s -o /dev/null -w 'health=%{http_code}\n' "https://${HOST:?export HOST=业务域名}/health"

# 4) HTTP/3 关闭确认（做了 4.1 止血时）
curl -sI --http3 "https://${HOST}" 2>/dev/null | head -1     # 期望失败/回落，且业务不受影响
```

**通过标准**

1. 三处版本都达到所在线修复版，且**自包含产物的 `includedFrameworks` 与宿主机一致**（这是自包含修好的唯一硬证据）；
2. 重新发布的产物 digest 与部署记录一致（按 07 G3/G4）；
3. `dotnet test` 全绿，核心链路健康检查 200；
4. 若做过止血：HTTP/3 已关且业务无回归；开发服务器不再对非本机可达；
5. 容器镜像 digest 固定，CI 断言运行时版本。

## 回退

```bash
# 0) 升级前落基线（运行时清单 / 镜像 digest / 发布产物哈希，三项进变更单）
: "${CHG:?export CHG=变更单号}"; mkdir -p "/secure/change/$CHG"
dotnet --list-runtimes > "/secure/change/$CHG/pre-runtimes.txt"
dotnet --info >> "/secure/change/$CHG/pre-runtimes.txt"
docker inspect -f '{{index .RepoDigests 0}}' "$IMAGE" | tee "/secure/change/$CHG/pre-image.txt"
sha256sum "$APP" | tee "/secure/change/$CHG/pre-app.sha256"

# 1) 框架依赖：回退运行时包到基线版本（版本号取自 pre-runtimes.txt，别凭记忆）
sudo apt-get install -y "dotnet-runtime-8.0=$(grep -oE '8\.0\.[0-9]+' "/secure/change/$CHG/pre-runtimes.txt" | head -1)"
# 2) 容器：认 digest 回滚
docker pull "$(cat "/secure/change/$CHG/pre-image.txt")"
# 3) 自包含：回退到上一版发布产物（升级前必须留档，否则没有回退路径）
```

**回退后风险**：回退即重新暴露全部 6 条，包括可走私的 `CVE-2026-88092`。回退窗口内必须保留 4.1 的入口缓解，并给出再升级时间点；**不允许「回退即收工」**。

## 条目

| 编号 | 组件 | 影响区间 | 修复 | 来源 |
|---|---|---|---|---|
| CVE-2026-88092 (GHSA-rv87-ccxw-8ggf) | Kestrel.Core（HTTP/1 走私，CWE-444，CVSS 3.1 9.4） | 8.0.0–8.0.31 / 9.0.0–9.0.20 / 10.0.0–10.0.12 / 11.0.0-preview.1–rc.1 | 8.0.32 / 9.0.21 / 10.0.13 / 11.0.0-rc.2 | https://github.com/advisories/GHSA-rv87-ccxw-8ggf |
| CVE-2026-70183 (GHSA-494h-xx7x-5frh) | Blazor `AuthorizeRouteView`（CWE-362，7.5） | 同上 | 同上 | https://github.com/advisories/GHSA-494h-xx7x-5frh |
| CVE-2026-70186 (GHSA-mf4x-w4gh-4656) | Kestrel HTTP/3（CWE-833，7.5） | 同上 | 同上 | https://github.com/advisories/GHSA-mf4x-w4gh-4656 |
| CVE-2026-96230 (GHSA-qjpx-jqm5-h2c4) | Blazor WASM 服务端调试页（CWE-79，8.8） | 同上 | 同上 | https://github.com/advisories/GHSA-qjpx-jqm5-h2c4 |
| CVE-2026-96233 (GHSA-87vj-4hqv-22p9) | System.Runtime DateTime 解析（CWE-787，7.5） | 同上 | 同上 | https://github.com/advisories/GHSA-87vj-4hqv-22p9 |
| CVE-2026-96225 (GHSA-w6wh-p4g7-mpj2) | Runtime 命名互斥/共享内存（CWE-59，7.8） | 同上 | 同上 | https://github.com/advisories/GHSA-w6wh-p4g7-mpj2 |

> 与 `vuln-w1/inventory.tsv` 的对应：W1-055 ~ W1-060（`merge_key` 逐条 `dotnet-cve-*`）。inventory 的 `ecosystem=nuget`，本件 front-matter 用模板枚举 `generic`——**字段映射请工坊在 lint 里认**。

## 来源

| 类型 | URL |
|---|---|
| 一手（GHSA：Kestrel HTTP/1 走私，含区间与修复版本） | https://github.com/advisories/GHSA-rv87-ccxw-8ggf |
| 一手（GHSA：Blazor 授权竞态） | https://github.com/advisories/GHSA-494h-xx7x-5frh |
| 一手（GHSA：Kestrel HTTP/3 DoS） | https://github.com/advisories/GHSA-mf4x-w4gh-4656 |
| 一手（GHSA：Blazor WASM 调试页） | https://github.com/advisories/GHSA-qjpx-jqm5-h2c4 |
| 一手（GHSA：DateTime 解析 DoS） | https://github.com/advisories/GHSA-87vj-4hqv-22p9 |
| 一手（GHSA：Unix mutex 提权；**无 MSRC 页**） | https://github.com/advisories/GHSA-w6wh-p4g7-mpj2 |
| 一手（MSRC 更新指南，逐 CVE 可查） | https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-88092 |
| 一手（dotnet 公告汇总，含本批各 CVE） | https://github.com/dotnet/announcements/issues/472 |
