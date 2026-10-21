---
id: "01"
title: Node.js 2026-10-21 安全版本升级（Brotli RCE / TLS 绕过 / crypto 熵缓存）
ecosystem: node
cve: ["CVE-2026-111497", "CVE-2026-105482", "CVE-2026-105483", "CVE-2026-106069", "CVE-2026-105481", "CVE-2026-106072", "CVE-2026-106074", "CVE-2026-106073", "CVE-2026-106070", "CVE-2026-106071"]
affects: "26.x <26.12.1；24.x <24.22.1；22.x <22.23.4（EOL 线一律视为受影响且无补丁）"
fixed: ["22.23.4", "24.22.1", "26.12.1"]
severity: "高危（官方公告标 HIGH，未给 CVSS 分数）"
status: verified
sources: ["https://nodejs.org/en/blog/vulnerability/october-2026-security-releases"]
updated: 2026-10-21
---

# Node.js 2026-10-21 安全版本升级

公告日 **2026-10-21**，影响 26.x / 24.x / 22.x 三线，最高 **HIGH**。修复版本：`22.23.4` / `24.22.1` / `26.12.1`。

**一句话**：按所在线升到对应修复版本；P0 是 Brotli 越界写（可 RCE）。普通 `node app.js` 不受 `CVE-2026-106074` 影响，只有 startup snapshot / SEA 产物受影响。

## 适用版本区间

| 分支 | 受影响 | 修复版本 |
|---|---|---|
| 22.x | `>=22.0.0 <22.23.4` | `22.23.4` |
| 24.x | `>=24.0.0 <24.22.1` | `24.22.1` |
| 26.x | `>=26.0.0 <26.12.1` | `26.12.1` |
| 20.x / 23.x 等 EOL 线 | 受同一批缺陷影响，**无补丁** | 迁移到 24.x 或 22.x |

**不在区间内的判断命令**

```bash
node -v
node -p "'node='+process.versions.node+' ares='+process.versions.ares+' openssl='+process.versions.openssl+' undici='+process.versions.undici+' brotli='+process.versions.brotli"
```

判定：`22.23.4` 之前 / `24.22.1` 之前 / `26.12.1` 之前 → 命中。

## 检测

### 1) 运行时版本（服务器 / CI runner / 容器）

```bash
# 本机与 nvm 里所有已装版本
node -v; nvm ls 2>/dev/null | sed -n '1,40p'; fnm ls 2>/dev/null

# 容器镜像基线
docker ps --format '{{.Names}}\t{{.Image}}' | grep -Ei 'node|22\.|24\.|26\.'
docker images --format '{{.Repository}}:{{.Tag}}' | grep -E '^node:|/-node:' | sort -u

# k8s 工作负载
kubectl get deploy,sts -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{"\t"}{..image}{"\n"}{end}' 2>/dev/null | grep -Ei 'node'
```

### 2) 仓库 / CI 里的版本声明

```bash
# 版本文件与 engines
rg -n --no-heading '"node"\s*:' package.json
for f in .nvmrc .node-version .tool-versions; do [ -f "$f" ] && { echo "--- $f"; cat "$f"; }; done

# CI 与 Dockerfile 固定版本
rg -n --no-heading 'node-version|FROM\s+node:' .github .gitlab-ci.yml Dockerfile* docker-compose*.yml 2>/dev/null

# 作为 devDependency 安装的 node 二进制（会影响 CI 实际运行版本）
npm ls node 2>/dev/null | head -20
```

**命中判据**：任一版本声明 `< 22.23.4`（22 线）/ `< 24.22.1`（24 线）/ `< 26.12.1`（26 线），或镜像 tag 落在旧版本。

### 3) 关键分流：是否使用 startup snapshot / SEA

```bash
# 命中则 CVE-2026-106074 对你有效，必须做「验证」段第 4/5 条（普通进程 + SEA 产物各跑一遍）
rg -n --no-heading 'build-snapshot|snapshot-blob|experimental-sea|NODE_SEA|sea-config' -g '!node_modules' .
rg -n --no-heading 'pkg|nexe|@vercel/ncc' package.json 2>/dev/null
```

### 4) 系统 CA 信任面（ca-cert 依赖更新）

```bash
# Node 内置 CA 随运行时升级；这里查系统信任库是否仍含被攻破的 eMudhra 中间 CA
openssl crl2pkcs7 -nocrl -certfile /etc/ssl/certs/ca-certificates.crt \
  | openssl pkcs7 -print_certs -noout | grep -i emudhra
```

**命中判据**：有输出 → 系统 curl/openssl/其他语言运行时仍信任该中间 CA，Node 升级不会修掉这部分，需单独更新 `ca-certificates` 包。

## 影响判定

按 CVE 逐条给触发前提，可直接对着代码/配置查：

| CVE | 级别 | 影响线 | 缺陷 | 触发前提（查这个） | 暴露面 |
|---|---|---|---|---|---|
| CVE-2026-111497 | 高 | 22/24/26 | Brotli 解码越界写，可 RCE | 进程对**不可信数据**调 `zlib.brotliDecompress*`，或框架自动解 `Content-Encoding: br` 的请求体 | 外网可达且收 br 请求体 = P0 |
| CVE-2026-105482 | 高 | 22/24/26 | `dns.resolve` 对含 NUL 的名字截断 | 把用户可控主机名交给 `dns.resolve*`（SSRF / DNS 重绑定链） | 需攻击者能控制入参主机名 |
| CVE-2026-105483 | 高 | **24/26（不含 22.x）** | IP 写成全角数字时 TLS 主机名校验被绕过 | 出站 TLS 且对端证书 SAN 用全角数字 IP | 需中间人位置 |
| CVE-2026-106069 | 高 | 22/24/26 | 主机「松散解析」到 IP 时绕过校验 | 出站 TLS 到攻击者可影响的域名 | 需中间人 / 可控 DNS |
| CVE-2026-105481 | 中 | 22/24/26 | keep-alive 连接会处理「请求发出前写入的响应」 | 长连接复用 + 能注入乱序流量 | 内网为主 |
| CVE-2026-106072 | 中 | 22/24/26 | 非规范 IPv4 主机名校验不当，DNS SAN 可认证 IP 端点 | 用 IP 字面量做 TLS 校验、对端证书只有 DNS SAN | 中间人 |
| CVE-2026-106074 | 中 | 22/24/26 | `randomUUID/randomInt` 熵缓存被写进 snapshot/SEA，每进程重复 | **仅** SEA / `--build-snapshot` 产物；产物里有 crypto 随机值 | 若给 session/token 签名 = P1 |
| CVE-2026-106073 | 低 | 22/24/26 | Permission Model 被 `fs.realpathSync` 绕过 | 使用 `--permission` 做沙箱 | 需已有本地代码执行 |
| CVE-2026-106070 | 低 | **26 only** | ZipFile 头校验失败后返回攻击者可控前缀字节 | 用 `ZipFile` 解析不可信 ZIP | 数据污染 |
| CVE-2026-106071 | 低 | **26 only** | Permission Model 通配符 radix 查找越权 | `--permission` + 通配符授权 | 本地 |

**误报排除**

- `CVE-2026-106074` 只打 snapshot / SEA，**普通 `node server.js` 不命中**；只有压缩响应、从不解压 br 的服务基本不命中 `CVE-2026-111497`。
- 22.x 不受 `CVE-2026-105483`（官方只列 26.x/24.x），别照抄成三条线全中。
- 官方公告**没有 CVSS 分数**，只有 high/medium/low 标签；对外引用不要自造分数。

## 修复

### 4.1 止血（无法立即升级时）

```bash
# 1) 入口拒绝 br 请求体，掐掉 Brotli 解压面（示例：nginx 前置）
#    if ($http_content_encoding ~* 'br') { return 415; }
# 2) 出站 TLS 收紧：校验对端证书 SAN 类型，禁用把 IP 当主机名的调用
# 3) 若产物是 SEA/snapshot 且用它签发 token：先停用该功能，或临时换成外部密钥源
```

> 注：官方未给 `CVE-2026-111497` / `106074` 的代码级 workaround，上述是网络与功能层缓解。**能升级就必须升级**。

### 4.2 升级（按线一条命令）

```bash
# 22.x → 22.23.4（LTS）
nvm install 22.23.4 && nvm use 22.23.4 && node -v

# 24.x → 24.22.1（LTS，推荐）
nvm install 24.22.1 && nvm use 24.22.1 && node -v

# 26.x → 26.12.1（Current）
nvm install 26.12.1 && nvm use 26.12.1 && node -v

# fnm / asdf 等价
fnm install 22.23.4 && fnm use 22.23.4
asdf install nodejs 22.23.4 && asdf local nodejs 22.23.4
```

### 4.3 容器与 CI

```bash
# 官方镜像 tag 已核实存在（Docker Hub 2026-10-21）
docker pull node:22.23.4-bookworm-slim
docker pull node:24.22.1-bookworm-slim
docker pull node:26.12.1-bookworm-slim

# 锁 digest，避免 tag 漂移
docker inspect --format='{{index .RepoDigests 0}}' node:24.22.1-bookworm-slim
```

Dockerfile 用 digest 固定：

```dockerfile
FROM node:24.22.1-bookworm-slim@sha256:<上面查到的digest>
```

CI 只认 `.nvmrc`，避免 runner 默认版本漂移：

```yaml
# .github/workflows/*.yml
- uses: actions/setup-node@v4
  with:
    node-version-file: .nvmrc
```

### 4.4 锁文件与仓库改动

```bash
# 版本文件
printf '24.22.1\n' > .nvmrc

# engines 约束（避免成员机器残留旧版）
node -e 'const fs=require("fs");const p=JSON.parse(fs.readFileSync("package.json"));p.engines={...(p.engines||{}),node:">=24.22.1 <25"};fs.writeFileSync("package.json",JSON.stringify(p,null,2)+"\n")'
```

**不需要**改 `package-lock.json`：c-ares / OpenSSL / Undici / SQLite / ca-cert 都随 Node 二进制发行，不是 npm 依赖。若 `devDependencies` 里有 `node` 这个下载器包，则同步升到对应版本并 `npm ci`。

### 4.5 防复发

```bash
# CI 里加硬断言，版本不对直接 fail
node -e 'const v=process.versions.node.split(".").map(Number);const ok=(v[0]===22&&v[1]>=23&&(v[1]>23||v[2]>=4))||(v[0]===24&&(v[1]>22||(v[1]===22&&v[2]>=1)))||(v[0]===26&&(v[1]>12||(v[1]===12&&v[2]>=1)));if(!ok){console.error("node "+process.versions.node+" below security baseline");process.exit(1)}'
```

- Dependabot/Renovate 加 `docker` 与 `.nvmrc`（regex manager）监控；
- 每季度核对 [Node.js release schedule](https://github.com/nodejs/release#release-schedule)，EOL 线提前迁移。

## 验证

```bash
# 1) 运行时版本与内置依赖已到修复版
node -v
node -p "process.versions.ares+' '+process.versions.openssl+' '+process.versions.undici+' '+process.versions.sqlite"

# 2) 容器镜像内版本（别只看宿主机）
docker run --rm node:24.22.1-bookworm-slim node -v

# 3) Brotli 解码基础健壮性冒烟（不是 PoC；官方未公开 PoC）
node -e 'const z=require("zlib");for (const b of [Buffer.from("AAAA"),Buffer.alloc(0)]){try{z.brotliDecompressSync(b)}catch(e){if(e.code!=="ERR_PADDING_1"&&e.code!=="Z_BUF_ERROR")console.log("unexpected:",e.code)}};console.log("brotli smoke ok")'

# 4) 普通进程随机值不复用
for i in 1 2 3; do node -e 'const c=require("crypto");console.log(c.randomUUID(),c.randomInt(1e9))'; done
# 期望：3 行互不相同

# 5) 有 SEA/snapshot 产物：同一二进制跑两次必须不同
#    ./dist/app --print-uuid   两次输出相同 = 仍受影响（该入口需应用自检支持）
```

**通过标准**

1. `node -v` 等于或高于所在线修复版本，且容器内一致；
2. `process.versions` 里 ares/openssl/undici/sqlite 与新版一致（升级生效，不是只换了 `.nvmrc`）；
3. 普通进程随机值三次各不相同；
4. SEA 产物两次启动随机值不同；若没有自检入口，用 `strings` 对比不了，需应用加一个 `/health/random` 探针（标记为**本次未闭环**）；
5. 出站 TLS 回归：对正常域名调用成功率不下降。

## 回退

```bash
# 0) 升级前先落基线（回退点是数字，不是记忆；三项都进变更单）
#    先 export 两个变量：CHG=变更单号，CURRENT_IMAGE=当前运行镜像（如 node:24.22.1-bookworm-slim）
: "${CHG:?export CHG=变更单号}" "${CURRENT_IMAGE:?export CURRENT_IMAGE=当前运行镜像}"
PRE_NODE=$(node -v | tr -d v)
PRE_COMMIT=$(git rev-parse HEAD)
PRE_IMAGE=$(docker inspect -f '{{index .RepoDigests 0}}' "$CURRENT_IMAGE")
mkdir -p "/secure/change/$CHG"
printf '%s\n%s\n%s\n' "$PRE_NODE" "$PRE_COMMIT" "$PRE_IMAGE" | tee "/secure/change/$CHG/pre-node.txt"

# 1) 回退仓库改动（已推送的升级提交用 revert，未推送可 reset）
git revert --no-edit "$PRE_COMMIT"

# 2) 回退运行时到基线版本
nvm install "$PRE_NODE" && nvm use "$PRE_NODE" && node -v

# 3) 回退镜像（认 digest，不认 tag，防 tag 已漂移）
docker pull "$(sed -n 3p "/secure/change/$CHG/pre-node.txt")"   # RepoDigests 已是 name@sha256: 完整引用

# 26.x → 24.x 降级注意：26 专属 API（如只有 26 有的实验特性）不可用
# 24.x ↔ 22.x 降级注意：先跑完整测试，`node:sqlite` 等实验 API 行为有差异（待验证具体清单）
```

**回退后风险**：回退即重新暴露全部 10 条缺陷，包括可 RCE 的 Brotli 越界写。必须同时挂 4.1 的网络层缓解，并给出再升级时间点；不允许「回退即收工」。

## 来源

| 类型 | URL |
|---|---|
| 一手（官方公告，含 10 条 CVE 与三个修复版本） | https://nodejs.org/en/blog/vulnerability/october-2026-security-releases |
| 一手（22.23.4 发布页） | https://nodejs.org/en/blog/release/v22.23.4 |
| 一手（24.22.1 发布页） | https://nodejs.org/en/blog/release/v24.22.1 |
| 一手（26.12.1 发布页） | https://nodejs.org/en/blog/release/v26.12.1 |
