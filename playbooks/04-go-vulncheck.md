---
id: "04"
title: Go 运行时与依赖漏洞排查（stdlib / x/net / Coraza WAF）
ecosystem: go
cve: ["CVE-2026-111943", "CVE-2026-78660", "CVE-2026-78669", "CVE-2026-41510"]
affects: "stdlib <1.26.9/<1.26.10 与 <1.27.2/<1.27.3；golang.org/x/net <0.60.0；Coraza v3.0.0–<3.8.1"
fixed: ["1.26.9", "1.26.10", "1.27.2", "1.27.3", "x/net 0.60.0", "Coraza v3.8.1"]
severity: "高危（HTTP/2 响应走私、CPU DoS、WAF 规则绕过、CA 信任面）"
status: verified
sources: ["https://osv.dev/vulnerability/GO-2026-6610", "https://osv.dev/vulnerability/GO-2026-6809", "https://osv.dev/vulnerability/GO-2026-6611", "https://osv.dev/vulnerability/GO-2026-6668"]
updated: 2026-10-21
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

# 5) 系统 CA 信任面（CVE-2026-111943 与 Go 内置信任库两层都要查）
go env GOROOT | xargs -I{} sh -c 'grep -c "eMudhra" {}/lib/time/../.. 2>/dev/null || true'
openssl crl2pkcs7 -nocrl -certfile /etc/ssl/certs/ca-certificates.crt \
  | openssl pkcs7 -print_certs -noout | grep -i emudhra
```

**命中判据**：`govulncheck` 报告 `GO-2026-6610 / 6611 / 6668 / 6809` 任一，或版本区间命中上表；`go version` 低于所在线修复版本。

## 影响判定

| CVE / OSV | 缺陷 | 触发前提（查这个） | 暴露面 |
|---|---|---|---|
| CVE-2026-78660 (GO-2026-6610) | 畸形 framing 头 → 反向代理**响应走私** | Go 服务用 HTTP/2（`http2.Server`、`ListenAndServeTLS` 默认 h2、或 `h2c`），前面有反代/CDN 复用连接 | 公网入口 = P0 |
| CVE-2026-78669 (GO-2026-6611) | `SETTINGS_INITIAL_WINDOW_SIZE` 洪泛 → CPU DoS | 同上，接受 HTTP/2 连接 | 公网可达 = P1 |
| CVE-2026-111943 (GO-2026-6809) | 停止信任被攻破的 eMudhra 中间 CA | 出站 TLS 到「曾由该中间 CA 签发」的站点；不修则继续信任被攻破链路 | 需中间人位置 |
| CVE-2026-41510 (GO-2026-6668) | 超 `ArgumentLimit` 后静默丢参 → 绕过 WAF 规则 | 部署 Coraza 且被保护应用接受大量参数（表单/查询串） | 前置 WAF 的入口 = P1 |

**误报排除**

- 只用 HTTP/1.1、且前面没有复用连接的反代 → 走私与 DoS 两条暴露面显著下降，但仍要升级（库在依赖树里就算命中）。
- `govulncheck` 报 `not called` 的条目不算命中：它区分「依赖里存在」与「代码路径可达」，以 `Vulnerable` 段为准。
- Coraza 只在测试环境 → 排期升级，不必当 P1。

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

# 4) h2 行为冒烟：确认服务实际协商的协议
curl -sI --http2 https://<服务地址>/ | head -3   # 期望 HTTP/2 200
```

**通过标准**

1. `go version` 达到所在线修复版本，CI 与镜像内一致；
2. `govulncheck ./...` 无 `Vulnerable` 命中（`not called` 可接受，但要在报告里注明）；
3. `golang.org/x/net` ≥ `v0.60.0`、Coraza ≥ `v3.8.1`（若使用）；
4. `go build -mod=readonly` 与 `go test ./...` 全绿；
5. 出站 TLS 对正常站点成功率不下降（CA 信任面变更的回归）。

## 回退

```bash
# 回退工具链与依赖到锁定的上一版
git checkout HEAD~1 -- go.mod go.sum
go mod download
```

**回退后风险**：回退即重新暴露响应走私 / CPU DoS / WAF 绕过；CA 信任面变更不可局部关掉，回退只能靠网络层限制出站 TLS 目标作缓解。回退必须同时给出再升级时间点。

## 条目

| 编号 | 组件 | 影响区间 | 修复 | 来源 |
|---|---|---|---|---|
| CVE-2026-78660 (GO-2026-6610) | net/http（HTTP/2） | `<1.26.9`、`<1.27.2`、`x/net<0.60.0` | `1.26.9` / `1.27.2` / `x/net v0.60.0` | https://osv.dev/vulnerability/GO-2026-6610 |
| CVE-2026-78669 (GO-2026-6611) | net/http（HTTP/2） | 同上 | 同上 | https://osv.dev/vulnerability/GO-2026-6611 |
| CVE-2026-111943 (GO-2026-6809) | crypto/x509 | `<1.26.10`、`1.27.0–<1.27.3` | `1.26.10` / `1.27.3` | https://osv.dev/vulnerability/GO-2026-6809 |
| CVE-2026-41510 (GO-2026-6668) | Coraza WAF | `v3.0.0–<3.8.1` | `v3.8.1` | https://osv.dev/vulnerability/GO-2026-6668 |

## 来源

| 类型 | URL |
|---|---|
| 一手（OSV / Go vuln DB） | https://osv.dev/vulnerability/GO-2026-6610 |
| 一手（OSV / Go vuln DB） | https://osv.dev/vulnerability/GO-2026-6611 |
| 一手（OSV / Go vuln DB） | https://osv.dev/vulnerability/GO-2026-6809 |
| 一手（OSV / Go vuln DB） | https://osv.dev/vulnerability/GO-2026-6668 |
