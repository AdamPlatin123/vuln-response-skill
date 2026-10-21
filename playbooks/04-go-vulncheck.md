---
id: "04"
title: Go 运行时与依赖漏洞排查（stdlib / x/net / Coraza WAF）
ecosystem: go
cve: ["CVE-2026-111943", "CVE-2026-78660", "CVE-2026-78669", "CVE-2026-41510", "CVE-2026-112778"]
affects: "stdlib <1.26.9/<1.26.10 与 <1.27.2/<1.27.3；golang.org/x/net <0.60.0；Coraza v3.0.0–<3.8.1；Traefik K8s provider >=2.0.0 <=2.11.45 / >=3.0.0 <=3.6.16 / =3.7.0"
fixed: ["1.26.9", "1.26.10", "1.27.2", "1.27.3", "x/net 0.60.0", "Coraza v3.8.1", "Traefik 2.11.46", "Traefik 3.6.17", "Traefik 3.7.1"]
severity: "高危（HTTP/2 响应走私、CPU DoS、WAF 规则绕过、CA 信任面；Traefik 跨命名空间引用为 4.0 6.4 中危）"
status: verified
sources: ["https://osv.dev/vulnerability/GO-2026-6610", "https://osv.dev/vulnerability/GO-2026-6809", "https://osv.dev/vulnerability/GO-2026-6611", "https://osv.dev/vulnerability/GO-2026-6668", "https://github.com/traefik/traefik/security/advisories/GHSA-rh7m-2m44-x32f"]
updated: 2026-10-22
---

# Go 运行时与依赖漏洞排查

**一句话**：`govulncheck` 是唯一可信的判定入口；stdlib 两条 HTTP/2 缺陷在 1.26.9 / 1.27.2 修，CA 信任面在 1.26.10 / 1.27.3 修，`x/net` 要单独升到 `0.60.0`。

## 适用版本区间

| 组件 | 受影响 | 修复版本 | 说明 |
|---|---|---|---|
| Go stdlib `<1.26.9`、`1.27.0–<1.27.2` | HTTP/2 响应走私、CPU DoS | `1.26.9` / `1.27.2` | 见 CVE-2026-78660 / CVE-2026-78669 |
| Go stdlib `<1.26.10`、`1.27.0–<1.27.3` | 不再信任被攻破的 eMudhra 中间 CA | `1.26.10` / `1.27.3` | CVE-2026-111943，与 Node.js 同源 CA 事件 |
| `golang.org/x/net <0.60.0` | 同上两条 HTTP/2 缺陷 | `v0.60.0` | 用 module 方式单独发补，不升工具链也要升它 |
| `github.com/corazawaf/coraza/v3` `v3.0.0–<3.8.1` | 参数洪泛绕过 WAF 规则 | `v3.8.1` | CVE-2026-41510 |
| Traefik K8s provider | `>=2.0.0 <=2.11.45` / `>=3.0.0 <=3.6.16` / `=3.7.0` | `2.11.46` / `3.6.17` / `3.7.1` | CVE-2026-112778；**仅 Ingress/Service annotation 路径**，K8s CRD 路径默认已拒跨命名空间 |

**不在区间内的判断命令**

```bash
go version
go list -m -f '{{.Path}} {{.Version}}' all 2>/dev/null | grep -E 'golang.org/x/net|corazawaf'
```

## 检测

```bash
# 1) 工具链版本（含 GOTOOLCHAIN 自动切换后的真实版本）
go version
go env GOTOOLCHAIN GOVERSION

# 2) 官方漏洞扫描：唯一可信的「我用没用」判定
go install golang.org/x/vuln/cmd/govulncheck@latest
govulncheck ./...

# 3) 依赖树里的 x/net / Coraza
go list -m -json all 2>/dev/null | grep -E '"Path": "(golang.org/x/net|github.com/corazawaf/coraza[^"]*)"' -A1

# 4) 容器与 CI 里的 Go 版本
docker ps --format '{{.Names}}\t{{.Image}}' | grep -iE 'golang|go1\.'
rg -n --no-heading 'golang:[0-9]|GO_VERSION|go-version' Dockerfile* .github/workflows 2>/dev/null

# 5) CA 信任面两层都要查（CVE-2026-111943）
#    a) 系统 trust store：Linux 上 Go 的 x509 池读这里
openssl crl2pkcs7 -nocrl -certfile /etc/ssl/certs/ca-certificates.crt \
  | openssl pkcs7 -print_certs -noout | grep -i emudhra
#    b) 已编译二进制：拒绝逻辑随工具链烤进二进制，`go version` 升了不算修
#    先 export BIN=./bin/app
BIN="${BIN:?export BIN=线上二进制路径}"; go version -m "$BIN" | grep -E 'go1\.[0-9]+' | head -1

# 6) Traefik（K8s provider，CVE-2026-112778）：版本 + annotation 引用面
kubectl get deploy -A -l app.kubernetes.io/name=traefik -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{"\t"}{..image}{"\n"}{end}' 2>/dev/null
helm list -A 2>/dev/null | grep -i traefik
kubectl get ingress,svc -A -o json 2>/dev/null | jq -r '
  .items[] | select(.metadata.annotations // {} | to_entries[]?.key | test("traefik.ingress.kubernetes.io/(router.middlewares|service.serverstransport|router.tlsoption)"))
  | "\(.metadata.namespace)/\(.metadata.name)"' | head -30
# 有输出 = 存在通过 annotation 引用 Traefik 资源的对象；再看是否跨命名空间引用
```

**命中判据**：`govulncheck` 报告 `GO-2026-6610 / 6611 / 6668 / 6809` 任一，或版本区间命中上表；`go version` 低于所在线修复版本；Traefik 版本落在区间**且**启用 `kubernetesIngress` provider（默认启用）。

## 影响判定

| CVE / OSV | 缺陷 | 触发前提（查这个） | 暴露面 |
|---|---|---|---|
| CVE-2026-78660 (GO-2026-6610) | 畸形 framing 头 → 反向代理**响应走私** | Go 服务用 HTTP/2（`http2.Server`、`ListenAndServeTLS` 默认 h2、或 `h2c`），前面有反代/CDN 复用连接 | 公网入口 = P0 |
| CVE-2026-78669 (GO-2026-6611) | `SETTINGS_INITIAL_WINDOW_SIZE` 洪泛 → CPU DoS | 同上，接受 HTTP/2 连接 | 公网可达 = P1 |
| CVE-2026-111943 (GO-2026-6809) | 停止信任被攻破的 eMudhra 中间 CA | 出站 TLS 到「曾由该中间 CA 签发」的站点；不修则继续信任被攻破链路 | 需中间人位置 |
| CVE-2026-41510 (GO-2026-6668) | 超 `ArgumentLimit` 后静默丢参 → 绕过 WAF 规则 | 部署 Coraza 且被保护应用接受大量参数（表单/查询串） | 前置 WAF 的入口 = P1 |
| CVE-2026-112778 (GHSA-rh7m-2m44-x32f) | K8s Ingress/Service **annotation** 可引用其他命名空间的 Middleware / ServersTransport / TLSOption → 绕过命名空间隔离，可能读到他人注入的凭据或复用其客户端证书 | Traefik 装在 K8s + `kubernetesIngress` provider 启用（默认）+ **攻击者能在某个命名空间创建/更新 Ingress 或 Service** | 多租户集群 = P1；单租户 = P2 |

**误报排除**

- 只用 HTTP/1.1、且前面没有复用连接的反代 → 走私与 DoS 两条暴露面显著下降，但仍要升级（库在依赖树里就算命中）。
- `govulncheck` 报 `not called` 的条目不算命中：它区分「依赖里存在」与「代码路径可达」，以 `Vulnerable` 段为准。
- Coraza 只在测试环境 → 排期升级，不必当 P1。
- Traefik 只用 **CRD** 路径（`kubernetesCRD`）：CRD 在 `allowCrossNamespace` 关闭时**本就拒绝**跨命名空间引用，`CVE-2026-112778` 打的是 **annotation 路径**；但仍要升级。
- **mTLS fail-open 不是 CVE**：`clientAuthType: RequestClientCert` / 缺 `requireAndVerifyClientCert` 是**配置缺陷**，任何 Traefik 版本都存在，别当漏洞报、也别等补丁——按配置项修（见下）。

## 修复

```bash
# 1) 工具链：在 go.mod 里钉死，避免成员机器/CI 用旧版
go mod edit -toolchain=go1.26.10        # 或 go1.27.3
go get go@1.26.10
go mod tidy

# 2) x/net 单独升到修复版（模块依赖，不随工具链走）
go get golang.org/x/net@v0.60.0
go mod tidy

# 3) Coraza WAF
go get github.com/corazawaf/coraza/v3@v3.8.1
go mod tidy

# 4) 验证所有依赖一致（-mod=readonly 防止偷偷改 go.mod）
go build -mod=readonly ./...
```

**Traefik（K8s，CVE-2026-112778）**

```bash
# 1) 升级到所在线的修复版（Helm 为例；镜像 tag 与 chart 版本按实际发布核对）
helm repo update && helm upgrade traefik traefik/traefik -n "${NS:?export NS=traefik命名空间}" \
  --set image.tag=v3.7.1          # 2.x 线用 v2.11.46；3.6 线用 v3.6.17

# 2) 关键：修复引入 crossProviderNamespaces —— 不显式配置时「所有命名空间仍被允许」
#    升级本身不恢复隔离，必须显式收口：
helm upgrade traefik traefik/traefik -n "$NS" \
  --set providers.kubernetesIngress.crossProviderNamespaces="${NS}"   # 只允许本命名空间
# 3) 顺带把 mTLS 从 fail-open 改成 fail-closed（这是配置，不是 CVE）
kubectl get tlsoptions.traefik.io -A -o yaml \
  | grep -nE 'clientAuth|requireAndVerifyClientCert|clientAuthType'
#    正确形态：clientAuth.clientAuthType: RequireAndVerifyClientCert
```

**CI 与镜像**

```yaml
- uses: actions/setup-go@v5
  with:
    go-version: '1.26.10'     # 或 1.27.3
- run: govulncheck ./...
```

```dockerfile
FROM golang:1.26.10-bookworm AS build
```

**止血（无法立即升级时）**

```bash
# 关掉 HTTP/2 入口：前置反代只放 HTTP/1.1；Go 侧禁用 h2
#   http.Server{TLSConfig: &tls.Config{NextProtos: []string{"http/1.1"}}}
# Coraza 侧：把请求参数上限调到业务真实上限以下，避免静默丢参（治标）
# Traefik：annotation 路径先回退到 CRD 路径或加准入策略（**治标**，不能替代升级）
```

## 验证

```bash
# 1) 工具链与依赖已到修复版
go version                                   # 期望 go1.26.10 / go1.27.3
go list -m golang.org/x/net                   # 期望 v0.60.0
go list -m github.com/corazawaf/coraza/v3     # 期望 v3.8.1

# 2) 官方扫描器判定
govulncheck ./...                             # 期望无 Vulnerable 段命中

# 3) 构建与测试回归
go build -mod=readonly ./... && go test ./... -count=1

# 4) 协议协商冒烟（若止血阶段禁用了 h2，本条改为验证 HTTP/1.1 正常、且 h2 已被拒）
curl -sI --http2 https://<服务地址>/ | head -3   # 未禁用 h2 时期望 HTTP/2 200
curl -sI https://<服务地址>/ | head -1           # 期望 HTTP/1.1 200（业务未被打死）

# 5) Traefik 已到修复版 + 跨命名空间引用已收口
helm list -A 2>/dev/null | grep -i traefik                                  # 期望 chart/app 版本 ≥ 修复线
kubectl -n "${NS:?export NS=traefik命名空间}" get deploy traefik -o jsonpath='{.spec.template.spec.containers[0].image}'; echo
#    再跑一次「检测」第 6 条的 annotation 扫描：跨命名空间引用必须为 0
```

**通过标准**

1. `go version` 达到所在线修复版本，CI 与镜像内一致；
2. `govulncheck ./...` 无 `Vulnerable` 命中（`not called` 可接受，但要在报告里注明）；
3. `golang.org/x/net` ≥ `v0.60.0`、Coraza ≥ `v3.8.1`（若使用）；
4. `go build -mod=readonly` 与 `go test ./...` 全绿；
5. 出站 TLS 对正常站点成功率不下降（CA 信任面变更的回归）；
6. Traefik ≥ `2.11.46` / `3.6.17` / `3.7.1`，**且 `crossProviderNamespaces` 已显式配置**（不配 = 所有命名空间仍被允许）；
7. mTLS 若使用：`clientAuthType` 为 `RequireAndVerifyClientCert`（fail-closed），这条与 CVE 无关但必须一起收口。

## 回退

```bash
# 回退工具链与依赖到锁定的上一版
git checkout HEAD~1 -- go.mod go.sum
go mod download

# Traefik：回退 Helm release（chart 与镜像一起回，别只回镜像）
helm history traefik -n "${NS:?export NS=traefik命名空间}" | tail -5
helm rollback traefik <上一个 revision> -n "$NS"
```

**回退后风险**：回退即重新暴露响应走私 / CPU DoS / WAF 绕过；CA 信任面变更不可局部关掉，回退只能靠网络层限制出站 TLS 目标作缓解；Traefik 回退到区间版本 = 重新开放跨命名空间引用（多租户集群必须同时保留准入策略/CRD 路径）。回退必须同时给出再升级时间点。

## 条目

| 编号 | 组件 | 影响区间 | 修复 | 来源 |
|---|---|---|---|---|
| CVE-2026-78660 (GO-2026-6610) | net/http（HTTP/2） | `<1.26.9`、`<1.27.2`、`x/net<0.60.0` | `1.26.9` / `1.27.2` / `x/net v0.60.0` | https://osv.dev/vulnerability/GO-2026-6610 |
| CVE-2026-78669 (GO-2026-6611) | net/http（HTTP/2） | 同上 | 同上 | https://osv.dev/vulnerability/GO-2026-6611 |
| CVE-2026-111943 (GO-2026-6809) | crypto/x509 | `<1.26.10`、`1.27.0–<1.27.3` | `1.26.10` / `1.27.3` | https://osv.dev/vulnerability/GO-2026-6809 |
| CVE-2026-41510 (GO-2026-6668) | Coraza WAF | `v3.0.0–<3.8.1` | `v3.8.1` | https://osv.dev/vulnerability/GO-2026-6668 |
| CVE-2026-112778 (GHSA-rh7m-2m44-x32f) | Traefik K8s provider（annotation 跨命名空间引用） | `>=2.0.0 <=2.11.45` / `>=3.0.0 <=3.6.16` / `=3.7.0` | `2.11.46` / `3.6.17` / `3.7.1`；**另需显式配 `crossProviderNamespaces`** | https://github.com/traefik/traefik/security/advisories/GHSA-rh7m-2m44-x32f |

> 与 `vuln-w1/inventory.tsv` 对应：W1-067（`merge_key=traefik-k8s-112778`）。

## 来源

| 类型 | URL |
|---|---|
| 一手（OSV / Go vuln DB） | https://osv.dev/vulnerability/GO-2026-6610 |
| 一手（OSV / Go vuln DB） | https://osv.dev/vulnerability/GO-2026-6611 |
| 一手（OSV / Go vuln DB） | https://osv.dev/vulnerability/GO-2026-6809 |
| 一手（OSV / Go vuln DB） | https://osv.dev/vulnerability/GO-2026-6668 |
| 一手（Traefik 官方安全公告：区间、patches、`crossProviderNamespaces`） | https://github.com/traefik/traefik/security/advisories/GHSA-rh7m-2m44-x32f |
| 一手（NVD：CVE-2026-112778，CVSS 4.0 6.4） | https://nvd.nist.gov/vuln/detail/CVE-2026-112778 |
