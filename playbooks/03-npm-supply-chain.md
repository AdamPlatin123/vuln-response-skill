---
id: "03"
title: npm 供应链投毒排查与清理（恶意包 / 站外 tarball / 依赖混淆）
ecosystem: npm
cve: []
affects: "tensorlake 0.5.144；@library-wide/library-shell 99.9.1；kmf-vendor-pack 99.0.0 / 100.100.x；sc-announcer 99.9.1"
fixed: ["无上游修复，只能移除恶意包并回滚锁文件"]
severity: "严重（凭据窃取、生命周期脚本任意执行、持久化后门）"
status: verified
sources: ["https://osv.dev/vulnerability/MAL-2026-17754", "https://osv.dev/vulnerability/MAL-2026-17744", "https://osv.dev/vulnerability/MAL-2026-18064", "https://osv.dev/vulnerability/MAL-2026-17650"]
updated: 2026-10-21
---

# npm 供应链投毒排查与清理

**一句话**：这类包**没有「升级到修复版」这个选项**——只有「移除 + 回滚锁文件 + 轮换已泄露凭据 + 查持久化」。装上即失守，`npm install` 的 postinstall 就是执行入口。

## 适用版本区间

| 包 | 恶意版本 | 手法 | 处置 |
|---|---|---|---|
| `tensorlake` | `0.5.144` | preinstall 窃取 npm/GitHub/AWS/K8s/Vault/SSH/.env 凭据，写 `.claude` / `.vscode` 持久化 | 移除 + 全量轮换 |
| `@library-wide/library-shell` | `99.9.1` | 依赖指向站外 tarball（`ltidi.storage.googleapis.com`），无哈希无锁版本，install 时执行任意生命周期脚本 | 移除 + 锁 registry |
| `kmf-vendor-pack` | `99.0.0` / `100.100.x` | 依赖混淆，postinstall 原生 addon 外泄 hostname/用户名/registry 到裸 IP | 移除 + 查外联 |
| `sc-announcer` | `99.9.1` | 与恶意域通信 | 移除 + 查外联 |

> 「版本区间」对恶意包不适用：**任何**包含上述包的锁文件都算命中，不存在安全版本。

**不在区间内的判断命令**

```bash
npm ls --all 2>/dev/null | grep -Ei 'tensorlake|library-wide|kmf-vendor-pack|sc-announcer'
```

## 检测

```bash
# 1) 依赖树 / 锁文件（npm / pnpm / yarn 三种都查）
npm ls --all 2>/dev/null | grep -Ei 'tensorlake|library-wide|kmf-vendor-pack|sc-announcer'
pnpm why tensorlake 2>/dev/null; yarn why tensorlake 2>/dev/null

# 2) 锁文件里是否有「站外 tarball」（依赖混淆/投毒的核心特征）
jq -r '(.packages // {}) | to_entries[]
  | select(.value.resolved? and (.value.resolved | startswith("https://registry.npmjs.org/") | not))
  | "\(.key)\t\(.value.resolved)"' package-lock.json 2>/dev/null | head -50
grep -nE '"resolved": *"https?://' package-lock.json 2>/dev/null | grep -v 'registry.npmjs.org' | head -20

# 3) 生命周期脚本面（postinstall 是投毒执行点）
npm query ':attr(hasInstallScript)' 2>/dev/null
node -e 'const fs=require("fs"),p=require("path");for(const d of fs.readdirSync("node_modules")){if(d.startsWith("."))continue;const f=p.join("node_modules",d,"package.json");try{const j=JSON.parse(fs.readFileSync(f));const s=j.scripts||{};for(const k of ["preinstall","install","postinstall","prepare"])if(s[k])console.log(d,k,"=",s[k].slice(0,120))}catch(e){}}'

# 4) 官方恶意包库扫描
npx --yes osv-scanner@latest --lockfile=package-lock.json

# 5) 持久化痕迹（tensorlake 会写这些）
ls -la .claude .vscode 2>/dev/null; cat .claude/settings*.json 2>/dev/null | head -40
ls -la ~/.claude ~/.vscode 2>/dev/null | head -20
```

**命中判据**：`npm ls` 出现上表任一包；或锁文件出现 `registry.npmjs.org` 以外的 tarball；或 `.claude` / `.vscode` 出现非本人写入的配置（指向外部命令/域名）。

## 影响判定

| 条件 | 判定 |
|---|---|
| 该包出现在 `dependencies` 且**跑过 `npm install`**（本地或 CI） | P0：postinstall 已执行，按凭据已泄露处理 |
| 只在 lockfile 里、从未 `npm ci` | P1：移除即可，仍要查一次缓存与 CI 历史 |
| CI 装过（含缓存命中） | P0：CI 里的 token / 云凭据 / 部署密钥全部视为泄露 |
| 出现 `.claude` / `.vscode` 新增配置 | P0：已持久化，需人工清点 |
| 只有 `devDependencies` | 仍执行 postinstall，不降低等级 |

**误报排除**

- `@library-wide/*` 这类 `99.9.x` 版本号本身就是投毒特征（远超正常语义化版本），别当正常升级。
- 站外 tarball 不等于恶意：私有 registry（Artifactory/Nexus）也会有站外 URL。判定看域名是否可信 + 是否带 integrity 哈希。

## 修复

```bash
# 1) 移除恶意包（同时改 package.json 与锁文件）
npm uninstall tensorlake @library-wide/library-shell kmf-vendor-pack sc-announcer

# 2) 清 node_modules 与缓存，防止残留生命周期脚本再执行
rm -rf node_modules
npm cache clean --force

# 3) 回滚锁文件到「最后可信提交」（比 uninstall 更彻底）
git checkout <最后可信 commit> -- package-lock.json package.json
npm ci --ignore-scripts

# 4) 查这些包是否被写进 npmrc / 全局
grep -niE 'registry|_authToken' .npmrc ~/.npmrc 2>/dev/null | sed 's/=.*/=<redacted>/'
```

**凭据轮换（默认已泄露，逐项打勾）**

| 凭据 | 动作 |
|---|---|
| npm token（发布权） | 在 npm 侧 revoke，重新签发 |
| GitHub PAT / gh CLI | revoke，检查新增 deploy key、Actions secret、fork |
| AWS / GCP / K8s / Vault 凭据 | 轮换并查异常调用 |
| SSH key | 换新，检查 `authorized_keys` |
| `.env` 里的第三方 key | 全部轮换 |
| CI/CD secrets | 全部重设，查近期 workflow 运行 |

**P0 额外检查**：`gh-token-monitor` 类后门会在 token 被撤销时触发破坏命令——轮换前先冻结 CI、保留磁盘快照。

**CI 防复发**

```yaml
# 安装阶段禁生命周期脚本；显式允许的包单独列白名单
- run: npm ci --ignore-scripts
- run: npx --yes osv-scanner@latest --lockfile=package-lock.json
```

```bash
# 仓库级：锁 registry + 强制 integrity
echo 'registry=https://registry.npmjs.org/' >> .npmrc
npm config set ignore-scripts true   # 谨慎：会跳过所有包的必要构建
```

## 验证

```bash
# 1) 依赖树已无恶意包
npm ls --all 2>/dev/null | grep -Ei 'tensorlake|library-wide|kmf-vendor-pack|sc-announcer'; echo "grep_exit=$?"

# 2) 锁文件只剩官方 registry
grep -cE '"resolved": *"https?://' package-lock.json
grep -E '"resolved": *"https?://' package-lock.json | grep -vc 'registry.npmjs.org'   # 期望 0

# 3) 干净安装后无 postinstall 执行
npm ci --ignore-scripts && echo "clean install ok"

# 4) 持久化痕迹已清
ls -la .claude .vscode 2>/dev/null

# 5) 恶意包库扫描通过
npx --yes osv-scanner@latest --lockfile=package-lock.json
```

**通过标准**

1. `grep_exit=1`（无命中）；
2. 锁文件非官方 registry 的 `resolved` 数量为 `0`；
3. `npm ci --ignore-scripts` 成功，无异常生命周期输出；
4. 凭据轮换清单全部完成并留记录；
5. `osv-scanner` 无恶意包告警；
6. 若有 `.claude` / `.vscode` 命中，已清点并删除，且有文件哈希留档。

## 回退

```bash
# 回退 = 恢复锁文件/依赖到投毒前状态；不存在「回退到旧版本仍安全」的路径
git revert <移除 commit>
```

**回退后风险**：恢复到含恶意包的锁文件 = 下次 `npm install` 再次执行后门。回退只允许用于「业务依赖无法立即移除」的场景，且必须：`--ignore-scripts` 安装 + 断网构建 + 记录例外并设到期时间。

## 条目

| 编号 | 包 / 版本 | 手法 | 来源 |
|---|---|---|---|
| MAL-2026-17754 | `@library-wide/library-shell@99.9.1` | 站外 tarball，无哈希无锁版本，install 执行任意生命周期脚本 | https://osv.dev/vulnerability/MAL-2026-17754 |
| MAL-2026-17744 | `kmf-vendor-pack@99.0.0 / 100.100.x` | 依赖混淆，postinstall 原生 addon 外泄主机与 registry 信息 | https://osv.dev/vulnerability/MAL-2026-17744 |
| MAL-2026-18064 | `sc-announcer@99.9.1` | 与恶意域通信 | https://osv.dev/vulnerability/MAL-2026-18064 |
| MAL-2026-17650（含 GHSA-rqxj-g25x-4v9v） | `tensorlake@0.5.144` | 恶意代码（CWE-506）：preinstall 窃密 + `.claude`/`.vscode` 持久化；「撤销 token 触发破坏」细节仅见二手 | https://osv.dev/vulnerability/MAL-2026-17650 |
| Socket 研究（ChainDrop / Shai-Hulud） | `tensorlake@0.5.144` | 投毒链条与窃密目标（npm/GitHub/AWS/K8s/Vault/SSH/.env） | https://badge.socket.dev/blog/tensorlake-compromise |
| Sonatype 研究 | `tensorlake@0.5.144` | 安装即失守的凭据风险分析，交叉印证 | https://www.sonatype.com/blog/hijacked-tensorlake-npm-turned-install-into-credential-risk |

## 来源

| 类型 | URL |
|---|---|
| 一手（OSV 恶意包库） | https://osv.dev/vulnerability/MAL-2026-17754 |
| 一手（OSV 恶意包库） | https://osv.dev/vulnerability/MAL-2026-17744 |
| 一手（OSV 恶意包库） | https://osv.dev/vulnerability/MAL-2026-18064 |
| 一手（OSV 恶意包库，tensorlake@0.5.144） | https://osv.dev/vulnerability/MAL-2026-17650 |
| 一手（Socket 官方研究博客，tensorlake@0.5.144 投毒） | https://badge.socket.dev/blog/tensorlake-compromise |
| 一手（Sonatype 官方研究博客，交叉印证） | https://www.sonatype.com/blog/hijacked-tensorlake-npm-turned-install-into-credential-risk |
| 二手（ThaiCERT 转述，仅作时间线交叉印证） | https://www.thaicert.or.th/en/2026/10/09/supply-chain-attack-through-tensorlake-npm-package-steals-credentials-and-spreads-malware/ |
