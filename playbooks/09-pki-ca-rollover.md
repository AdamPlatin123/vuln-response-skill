---
id: "09"
title: eMudhra 中间 CA 弱密钥（P384 私钥可秒级恢复）· PKI 处置与五套信任库更新
ecosystem: pki
cve: ["CVE-2026-111943", "CVE-2026-113470", "CVE-2026-105221", "CVE-2026-85086", "CVE-2026-113812"]
aliases: ["RUSTSEC-2026-0381", "RUSTSEC-2026-0382", "RUSTSEC-2026-0383", "GHSA-phqh-xp3p-h6mr", "GHSA-6q48-6c7w-9gw2", "GHSA-hq85-5cpj-mr62"]
affects: "① 信任库面：证书链经过 3 个根（AAA Certificate Services / emSign Root TLS CA - G3 / emSign ECC Root CA - G3）的中间 CA；受影响的是**信任库**而非某个软件版本：Go <1.26.10 / <1.27.3、Rust webpki-roots <1.0.10（`=0.26.11` 是 unaffected 兼容包，**不是修复版**）、rustls-webpki `<0.103.16` 或 `0.104.0-alpha.1–<0.104.0-alpha.8`（两段，取「或」）、webpki-root-certs <1.0.10、Node 22/24/26 修复线之前、Perl `Mozilla::CA` <20261020、Python `certifi >=2019.03.09 <2026.10.19`（修 `2026.10.19`）、`uv <0.13.4`（修 `0.13.4`）；Java cacerts **无厂商修复版本**（OpenJDK master 源码树仍含 `emsigneccrootcag3` / `emsignrootcag1` / `emsignrootcag2`，处置为手工删别名或指向清洗后 trustStore）、Debian ca-certificates `20250419+deb13u1`（trixie；unstable `20260816+nmu1`；**bookworm 未确认**）、.NET 随 OS 信任库（Windows Cert Store / Linux OpenSSL / macOS Keychain），**无独立处置版本**。② 应用层 TLS 校验关断面（与信任库无关）：gist RubyGem `<6.1.0`、Apache Thrift perl bindings `<0.25.0`"
fixed: ["Go 1.26.10", "Go 1.27.3", "webpki-roots 1.0.10", "webpki-root-certs 1.0.10", "rustls-webpki 0.103.16", "rustls-webpki 0.104.0-alpha.8", "Node 22.23.4", "Node 24.22.1", "Node 26.12.1", "Firefox 158.0.1", "Firefox ESR 115.43.1", "Firefox ESR 153.5.1", "Firefox Android 158.0.2", "NSS 3.131.1", "gist 6.1.0", "Thrift 0.25.0", "Mozilla::CA 20261020"]
severity: "高危（伪造 HTTPS 证书做中间人；私钥已广为人知，CT 日志暂未见签发记录，但厂商明确「近期很可能被滥用」）；另含两条应用层 TLS 校验关断：gist 4.0 **9.1** / Thrift 4.0 **6.9**"
status: verified
sources: ["https://www.openwall.com/lists/oss-security/2026/10/20/1", "https://blog.mozilla.org/security/2026/10/20/protecting-firefox-users-following-the-compromise-of-emudhra-intermediate-certificates/", "https://raw.githubusercontent.com/rustsec/advisory-db/main/crates/webpki-roots/RUSTSEC-2026-0381.md", "https://osv.dev/vulnerability/GO-2026-6809"]
updated: 2026-10-22
---

# eMudhra 中间 CA 弱密钥 · PKI 处置

> **覆盖说明（三条）**
> 1. **包级事实 verified**：本件 CVE 号、受影响区间、修复版本均有一手来源（oss-security / RUSTSEC / OSV / MFSA / NVD / CNA 记录 / GHSA）。
> 2. **三套信任库收口（W3）**：Debian ca-certificates **已确认**——stable/trixie `20250419+deb13u1`（DSA-6572-1，2026-10-20）、unstable/testing `20260816+nmu1`（NMU 2026-10-20，changelog 明写黑名单 `emSign ECC Root CA - G3` + `Comodo AAA Services root`），**bookworm 未确认**；Java cacerts **无厂商修复版本**（Oracle CPU 0 命中、OpenJDK master 仍含 3 张 emSign 根）→ 处置为手工 `keytool -delete` 或指向清洗后 trustStore；.NET **无独立处置版本**，随 OS/基础镜像 trust store 更新。
> 3. 本件按「verified + 未确认子项」归档：**不下调 status、不改统计口径**，缺口在 `index.md` 未闭环清单单列。

> 措辞口径：根因是**弱密钥**（私钥本身可被秒级恢复，见下「根因」段），不是普通「私钥被盗」。标题与正文按根因写，别再叫「私钥泄露」。

**一句话**：**只升浏览器/运行时修不掉系统 trust store**。Go、Rust、Node、Python、Java、Linux 各自有独立信任库，随二进制或系统发行，要**逐个更新并逐个验证**；同时「对外证书换 CA 重签」和「客户端信任库更新」是两件事，不能互相替代。

## 变量清单（先 export，再抄命令）

下面命令只认环境变量，**先 export 再逐条抄**；`${VAR:?...}` 会在变量缺失时直接报错退出。

```bash
: "${BASELINE_VERSION:?未设置 BASELINE_VERSION（回退目标版本，如 gist 6.1.0 之前 / Thrift 0.25.0）}"
```

## 适用版本区间

本事件的判定不按单一软件版本，而按**信任库**：只要你的信任库仍信任这 3 个根或其交叉签名，你就可被伪造证书欺骗。

| 信任库 | 受影响条件 | 处置版本 | 来源等级 |
|---|---|---|---|
| Go crypto/x509 | `<1.26.10`、`1.27.0–<1.27.3` | `1.26.10` / `1.27.3` | 一手（OSV GO-2026-6809） |
| Rust `webpki-roots` | `<1.0.10`（`=0.26.11` 为 unaffected 兼容包，**不是修复版**） | `>=1.0.10` | 一手（RUSTSEC-2026-0381） |
| Rust `rustls-webpki` | `<0.103.16` **或** `0.104.0-alpha.1–<0.104.0-alpha.8`（两段，取「或」） | `0.103.16` / `0.104.0-alpha.8` | 一手（RUSTSEC-2026-0382） |
| Rust `webpki-root-certs` | `<1.0.10`（`0.26.11` 不受影响） | `>=1.0.10` | 一手（RUSTSEC-2026-0383） |

**第二面：应用层 TLS 校验关断（与信任库更新无关，各自升级）**

| 组件 | 受影响 | 修复 | 说明 |
|---|---|---|---|
| `gist` RubyGem | `<6.1.0` | `6.1.0` | `CVE-2026-105221`；`lib/gist.rb` 硬编码 `VERIFY_NONE` → 任意证书可被接受，GitHub API 流量可被中间人读取/篡改（CWE-295） |
| Apache Thrift **perl bindings** | `<0.25.0` | `0.25.0` | `CVE-2026-85086`；不安全 TLS 默认（CWE-295 + CWE-1188）。**依据：CVE 记录（`assignerShortName=apache`、state PUBLISHED，含 lists.apache.org 线程引用）+ NVD；Apache 公告页正文需 JS 未取到** |
| Node.js 内置 CA（ca-cert 依赖） | 22/24/26 三条线修复版之前 | `22.23.4` / `24.22.1` / `26.12.1` | 一手（Node 安全公告） |
| Firefox / NSS | OneCRL 未生效或自定义设置阻断更新 | `158.0.1` / ESR `115.43.1`·`153.5.1` / Android `158.0.2` / NSS `3.131.1`（**CVE-2026-113470**，MFSA 2026-111，high） | 一手（Mozilla 博客 + MFSA） |
| Python `certifi` | `>=2019.03.09 <2026.10.19`（打包 emSign 根证书） | `2026.10.19` | 一手（GHSA-6q48-6c7w-9gw2，critical） |
| Python `uv`（内置 CA store） | `<0.13.4` | `0.13.4` | 一手（GHSA-hq85-5cpj-mr62） |
| Debian `ca-certificates` | 仍含 `emSign ECC Root CA - G3` / `Comodo AAA Services root` 的旧包 | trixie `20250419+deb13u1`；unstable/testing `20260816+nmu1`；**bookworm 未确认** | 一手（DSA-6572-1 + unstable changelog） |
| **Java cacerts** | **无厂商修复版本**；OpenJDK master cacerts 仍含 `emsigneccrootcag3`/`emsignrootcag1`/`emsignrootcag2` | **手工处置**：`keytool -delete -alias` 清 3 个别名，或 `-Djavax.net.ssl.trustStore` 指向清洗后 store；GraalVM native image 必须用清洗后 cacerts **重编译** | 一手（JDK-8319187 + Oracle 25.0.4 relnotes + GraalVM 文档） |
| **Chrome / Android** | CRLSets 阻断 | 侦察交件；Google 原文正文未能抓取 | **待核** |
| **.NET** | 不自带 bundle：Windows → Windows Cert Store；Linux → OpenSSL（`SSL_CERT_FILE`/`SSL_CERT_DIR`，空则 `/etc/ssl/certs`）；macOS → Keychain | **无独立处置版本**：更新 OS / 基础镜像 trust store（Linux 走 Debian 那条，Windows 走 Root 更新） | 一手（.NET 文档 + dotnet/announcements 0 命中） |

**判断命令（先看版本，再看信任库内容）**

```bash
go version
node -v
cargo tree -i webpki-roots 2>/dev/null; cargo tree -i rustls-webpki 2>/dev/null
python3 -c 'import certifi;print(certifi.__version__, certifi.where())' 2>/dev/null
keytool -list -cacerts -storepass changeit 2>/dev/null | head -3
firefox --version 2>/dev/null
```

## 检测

### 1) SPKI 清单（**唯一可信的检测锚点**，来自 oss-security 披露原文）

**3 个根**（SPKI SHA-256）：

| 根 | SPKI SHA-256 |
|---|---|
| AAA Certificate Services | `bd153ed7b0434f6886b17bce8bbe84ed340c7132d702a8f4fa318f756ecbd6f3` |
| emSign Root TLS CA - G3 | `c619e4780ed8e0abeda24ad732567de4383a7ea941338f6d1a7d1b49ac792fe9` |
| emSign ECC Root CA - G3 | `8d417db2dd8bf5e3084d1e3f196d583849d81bdd4c00c70b9d39369e96b8c782` |

**8 张中间 CA**（6 TLS + 2 代码签名；同一公钥也被 Sectigo 交叉签名，**SPKI 相同**）：

| 中间 CA | 用途 | SPKI SHA-256 |
|---|---|---|
| EM EV TLS CA - G3B | TLS | `e0254c7fcdc265e2f0f8a428dabb75ab4ae039b4872d62f5ee57f0877d5a8a4` |
| EM OV TLS CA - G3B | TLS | `43bffa19d6ef651451f6841e019931e96f6f2eaeff28ab4b6f1ce4576de2717` |
| EM DV TLS CA - G3B | TLS | `ebed6475c2c2d80fcb199f3fe8dd6e6b3ce60b77eb15d4e42c3dec0c6f5b5105` |
| EM EV TLS CA - G3C | TLS | `5c0660a2b164910d8ff589c18e14552e9e0ec237dcefe2cb736d41a4811f81a0` |
| EM OV TLS CA - G3C | TLS | `63ecefee431d49523bc1136c4e72d0206a477086caf606cd5cf025686c109cf8` |
| EM DV TLS CA - G3C | TLS | `49dd353dc2b919a3770645117d0e60c16115e7d1bc259eefe734b00ea434fe5f` |
| EM OV CS CA - G3B | 代码签名 | `ec4ffa1ad0ac88081314b7aaffef6a91f97cd57291bb5ba686c5415f5eb4f6b6` |
| EM OV CS CA - G3C | 代码签名 | `92c063d67e8f14db71d288e11266ffdaf69cbf115f7bab14f3bc2f68d25e0e30` |

> 检测**只认 SPKI**：同一密钥被 Sectigo 交叉签名后证书 SHA-256 不同，但 SPKI 不变。

### 2) 全量扫描：系统 trust store

```bash
cat > /tmp/emudhra-spki.txt <<'EOF'
bd153ed7b0434f6886b17bce8bbe84ed340c7132d702a8f4fa318f756ecbd6f3
c619e4780ed8e0abeda24ad732567de4383a7ea941338f6d1a7d1b49ac792fe9
8d417db2dd8bf5e3084d1e3f196d583849d81bdd4c00c70b9d39369e96b8c782
e0254c7fcdc265e2f0f8a428dabb75ab4ae039b4872d62f5ee57f0877d5a8a4
43bffa19d6ef651451f6841e019931e96f6f2eaeff28ab4b6f1ce4576de2717
ebed6475c2c2d80fcb199f3fe8dd6e6b3ce60b77eb15d4e42c3dec0c6f5b5105
5c0660a2b164910d8ff589c18e14552e9e0ec237dcefe2cb736d41a4811f81a0
63ecefee431d49523bc1136c4e72d0206a477086caf606cd5cf025686c109cf8
49dd353dc2b919a3770645117d0e60c16115e7d1bc259eefe734b00ea434fe5f
ec4ffa1ad0ac88081314b7aaffef6a91f97cd57291bb5ba686c5415f5eb4f6b6
92c063d67e8f14db71d288e11266ffdaf69cbf115f7bab14f3bc2f68d25e0e30
EOF

rm -rf /tmp/pki-scan && mkdir -p /tmp/pki-scan
openssl crl2pkcs7 -nocrl -certfile /etc/ssl/certs/ca-certificates.crt \
  | openssl pkcs7 -print_certs -out /tmp/pki-scan/bundle.pem
csplit -sz -f /tmp/pki-scan/c- /tmp/pki-scan/bundle.pem '/-----BEGIN CERTIFICATE-----/' '{*}'
for c in /tmp/pki-scan/c-*; do
  spki=$(openssl x509 -in "$c" -pubkey -noout | openssl pkey -pubin -outform der \
        | openssl dgst -sha256 -r | cut -d' ' -f1)
  subj=$(openssl x509 -in "$c" -noout -subject | cut -c1-70)
  echo "$spki|$subj"
done | grep -F -f /tmp/emudhra-spki.txt
# 有输出 = 命中；无输出 = 系统信任库已不含这些锚点
```

### 3) 五套信任库逐个查

```bash
# Python certifi（独立 bundle，不跟系统走）——先看版本，再看内容
python3 -c 'import certifi;print(certifi.__version__, certifi.where())'   # <2026.10.19 即命中
python3 -c 'import certifi;print(certifi.where())'
openssl crl2pkcs7 -nocrl -certfile "$(python3 -c 'import certifi;print(certifi.where())')" \
  | openssl pkcs7 -print_certs -noout | grep -iE 'emSign|eMudhra|AAA Certificate'

# Node 内置根（按 SPKI 精确匹配，别按 subject 猜）
node -e '
const {X509Certificate,createHash}=require("crypto");
const bad=new Set(require("fs").readFileSync("/tmp/emudhra-spki.txt","utf8").split("\n").filter(Boolean));
const hits=[];
for(const p of require("tls").rootCertificates){try{
  const c=new X509Certificate(p);
  const h=createHash("sha256").update(c.publicKey.export({type:"spki",format:"der"})).digest("hex");
  if(bad.has(h)) hits.push(c.subject);
}catch(e){}}
console.log("rootCertificates",require("tls").rootCertificates.length,"hits",hits.length,hits);'

# Debian ca-certificates：版本 + 包内是否仍含被移除的根
dpkg-query -W -f='${Version}\n' ca-certificates
grep -icE 'emSign ECC Root CA - G3|Comodo AAA Services' /usr/share/ca-certificates/mozilla/*.crt 2>/dev/null || true

# Java cacerts：**按别名精确查这 3 张根**（alias 小写、无分隔符）
keytool -list -cacerts -storepass changeit 2>/dev/null | grep -iE 'emsigneccrootcag3|emsignrootcag1|emsignrootcag2|comodoaaaca'
keytool -list -cacerts -storepass changeit 2>/dev/null | grep -iE 'emSign|eMudhra|AAA Certificate' | head

# .NET：不自带 bundle，查它实际读的 OS store
dotnet --version >/dev/null 2>&1 && echo "dotnet present（trust store 走 OS）"
echo "SSL_CERT_FILE=${SSL_CERT_FILE:-<unset, 默认 /etc/ssl/certs>} SSL_CERT_DIR=${SSL_CERT_DIR:-<unset>}"
openssl version -d

# Rust
cargo tree -i webpki-roots 2>/dev/null; cargo tree -i rustls-webpki 2>/dev/null; cargo tree -i webpki-root-certs 2>/dev/null

# Python uv（内置 CA store，独立于 certifi）
uv --version 2>/dev/null || python3 -c 'import importlib.metadata as m;print(m.version("uv"))' 2>/dev/null   # <0.13.4 即命中

# Go（system pool + 自带逻辑：升级运行时才算修）
go version; go env GOROOT
```

### 4) 端到端探针（RUSTSEC 引用的社区测试主机）

```bash
# 修复后：证书链应被拒绝（握手失败或明确 distrust）
openssl s_client -connect emudhra.we-have-a-problem.com:443 -verify_return_error </dev/null 2>&1 \
  | grep -E 'Verify return code|verify error|alert'
```

> 该主机是社区测试锚点（出现在 RUSTSEC 的 references 里），**不是厂商提供的服务**；只作为「信任库是否仍接受该链」的快速验证，不作为唯一验收。

### 5) 应用层 TLS 校验关断（gist / Thrift，与信任库无关）

```bash
# gist RubyGem：装了哪个版本 + 源码里是否仍硬编码 VERIFY_NONE
gem list gist 2>/dev/null; bundle info gist 2>/dev/null | head -3
ruby -e 'spec=Gem::Specification.find_all_by_name("gist").first; puts(spec ? spec.version : "not installed")' 2>/dev/null
grep -rn 'VERIFY_NONE' "$(gem which gist 2>/dev/null | xargs -r dirname)" 2>/dev/null | head -5
#   命中判据：版本 <6.1.0，或源码里仍出现 VERIFY_NONE

# Apache Thrift perl bindings：装了哪个版本（CPAN 模块名 Thrift）
perl -MThrift -e 'print "$Thrift::VERSION\n"' 2>/dev/null || echo "Thrift 未安装（perl）"
perl -MThrift::Socket -e 'print "socket ok\n"' 2>/dev/null
#   命中判据：版本 <0.25.0
```

## 影响判定

| 条件 | 判定 |
|---|---|
| 客户端**可靠检查吊销且 fail-closed**，且只走 eMudhra 原生链 | Mozilla 博客：无需动作（10-18 已吊销） |
| 客户端走 **Sectigo 交叉签名链** | **不能只靠吊销**：Bugzilla 2083449 记录显示交叉签名证书当时**仍未吊销**（10-18 时点）；必须按 SPKI 直接移除信任 |
| 客户端**不查吊销 / fail-open** | **必须更新信任库**：可被伪造证书中间人 |
| 对外服务证书由 eMudhra 签发 | **P0 业务侧**：换 CA 重签；客户可能开始报证书错误 |
| 只升了浏览器、服务器/客户端信任库未动 | **未修复**：Java/Python/Go/Rust 各自独立 |
| 移除 3 个根 | 可有效防护，但**可能打断**使用这些根下其他中间 CA 的站点（Mozilla 明确提示） |
| 用了 `gist` RubyGem `<6.1.0` | **P1**：代码里硬编码 `VERIFY_NONE`，HTTPS 一律不校验 → 可被中间人读改 GitHub API 流量、窃取 OAuth token |
| 用了 perl 版 Apache Thrift `<0.25.0` | **P1**：不安全 TLS 默认（CWE-1188 初始化不安全默认）→ 同样可被中间人 |
| 用自签/私有 CA，信任库不含这些根 | 不受影响（仍需核实是否存在交叉签名链） |

**根因（一手，Bugzilla 2083449）**：不是「签名被伪造」，而是**密钥生成流程缺陷**——8 把 P384 私钥全部是**小于 256 的整数**（除最后一个字节外几乎全零），可用 baby-step giant-step 或直接枚举「前 256 个 P384 私钥」在秒级恢复。Mozilla 在不依赖报告者方法的情况下独立复现，确认「trivial to exploit」。
注意：坊间流传的「KGC 脚本缺陷」这一具体归因，Bugzilla 原文未这样表述，**标待核**，别当成已核实结论引用。

**现状（一手）**
- 发现：2026-10-17 20:06 UTC 收到报告；eMudhra 10-18 吊销、Sectigo 10-19 吊销；
- Firefox OneCRL 在 **3 小时内**完成分发（10-17 22:59 UTC）；
- **CT 日志暂未显示这些中间 CA 签发的证书**——但这不能排除过去未上日志的证书，也不能排除未来签发；
- Mozilla 原文：「abuse of the compromised private keys is **likely in the near future**」→ 按「事故中」处理，不是「将会」。

**误报排除**

- 只看 `openssl version` 或 `firefox --version` 就下结论 → 错，要查的是**信任库内容**；
- 证书 SHA-256 不同但 SPKI 相同 → 是同一密钥（Sectigo 交叉签名），仍命中；
- 服务端证书没用 eMudhra 签发 → 你不需要重签，但**客户端信任库仍要更新**（别人可以伪造任何域名）；
- `gist` / Thrift 是**应用层自己关掉了校验**（`VERIFY_NONE` / 不安全默认），与信任库是否移除 eMudhra 根**无关**：信任库修好了它们照样被中间人——两条要单独升级；
- 不用 Ruby / 不用 perl 版 Thrift → 两条不适用，别进工单。

## 修复

顺序：**两件事分开做**——① 客户端信任库各自更新；② 自家对外证书若走 eMudhra，换 CA 重签。

### 4.1 信任库：五套分别更新

```bash
# 1) Debian ca-certificates（已确认版本：trixie 20250419+deb13u1 / unstable 20260816+nmu1；bookworm 未确认）
apt-get update && apt-get -y install --only-upgrade ca-certificates
dpkg-query -W -f='${Version}\n' ca-certificates     # trixie 期望 20250419+deb13u1；unstable 期望 20260816+nmu1
update-ca-certificates
# 回扫：应无输出
bash -c 'openssl crl2pkcs7 -nocrl -certfile /etc/ssl/certs/ca-certificates.crt | openssl pkcs7 -print_certs -noout' \
  | grep -icE 'emSign|eMudhra|AAA Certificate'

# 2) Go：升级工具链后**重新编译**（Go 的拒绝逻辑在代码里，不是换 CA 文件）
go mod edit -toolchain=go1.26.10 && go get go@1.26.10 && go mod tidy
go build ./... && go version -m "${BIN:?export BIN=二进制路径}" | head

# 3) Rust：升级依赖并重新构建
cargo update -p webpki-roots -p rustls-webpki -p webpki-root-certs
cargo build --locked

# 4) Node：升级运行时（ca-cert 随二进制走），SEA/snapshot 产物要重建
nvm install 24.22.1 && nvm use 24.22.1 && node -v

# 5) Python：安装已确认的修复版本，然后重启进程（必要时注入自定义 bundle）
python3 -m pip install 'certifi==2026.10.19'
python3 -c 'import certifi;print(certifi.__version__, certifi.where())'      # 期望 2026.10.19
python3 -m pip install 'uv==0.13.4'   # uv 若单独装（内置 CA store 需 ≥0.13.4）
uv --version

# 6) Java：**没有厂商修复版本**（一手否定）→ 手工清别名，或指向清洗后的 trustStore
#    a. 删除 3 个别名（先备份 cacerts）
cp "$JAVA_HOME/lib/security/cacerts" "/secure/change/$CHG/cacerts.bak"
for a in emsigeccrootcag3 emsignrootcag1 emsignrootcag2; do
  keytool -delete -cacerts -storepass changeit -alias "$a" 2>/dev/null && echo "deleted $a" || echo "absent $a"
done
keytool -list -cacerts -storepass changeit | grep -icE 'emsigneccrootcag3|emsignrootcag1|emsignrootcag2'   # 期望 0
#    b. 或运行期指定清洗后的 store：-Djavax.net.ssl.trustStore=/secure/cacerts-clean
#    c. **GraalVM native image**：构建期捕获宿主 TrustStore 并把 blacklisted.certs 编进二进制
#       → 必须用**清洗后 cacerts 的构建机**重编译；改运行机无效
#       native-image 需重建：./mvnw -Pnative native:compile / gradle nativeCompile
```

> **W3 收口状态**：Debian 已确认（trixie `20250419+deb13u1` / unstable `20260816+nmu1`，**bookworm 未确认**——DSA 只列 trixie）；Java **无厂商修复版本** → 手工处置（删别名 / 指定 trustStore / GraalVM 重编译）；.NET **无独立处置版本** → 随 OS/基础镜像 trust store 更新。

### 4.2 对外证书：换 CA 重签（与信任库更新无关）

```bash
: "${HOST:?export HOST=自家对外域名}"
# 1) 列出对外证书链，看签发者
openssl s_client -connect "$HOST:443" -servername "$HOST" </dev/null 2>/dev/null \
  | openssl x509 -noout -issuer -subject -dates
# 2) 若 issuer 链到 eMudhra / emSign / AAA Certificate Services → 换 CA 重新签发并替换证书链
# 3) 替换后复测（含中间证书完整性）
openssl s_client -connect "$HOST:443" -servername "$HOST" -showcerts </dev/null 2>/dev/null | grep -c 'BEGIN CERTIFICATE'
```

### 4.3 防护策略

- 客户端强制 **CRL/OCSP 检查 + fail-closed**（Mozilla 原文：可靠检查吊销并 fail-closed 的用户无需动作）；
- 对**代码签名**也适用：被攻破的 2 张 CS 中间 CA 可签恶意代码，需检查代码签名信任策略；
- 监控：出现由这些 SPKI 签发的新证书（CT 监控）即告警。

### 4.4 应用层 TLS 校验关断（gist / Thrift）

```bash
# gist RubyGem：升到 6.1.0（Gemfile 锁版本 + bundle update 单包）
#   Gemfile: gem "gist", ">= 6.1.0"
bundle update gist
bundle info gist | head -3
ruby -e 'spec=Gem::Specification.find_all_by_name("gist").first; puts(spec.version)' 2>/dev/null

# Apache Thrift perl bindings：升到 0.25.0
cpanm Thrift@0.25.0          # 或 cpan -i Thrift
perl -MThrift -e 'print "$Thrift::VERSION\n"'
```

> Thrift 这条**依据 CVE 官方记录（`assignerShortName=apache`，state PUBLISHED，即 Apache 自己提交的 CNA 记录，含 lists.apache.org 线程引用）+ NVD**；Apache 公告页正文需 JS 渲染、本次未取到，**升级目标版本以该 CVE 记录为准**。

## 验证

```bash
# 0) 回扫只认 SPKI（按 subject grep 会漏掉 Sectigo 交叉签名的同密钥证书）
[ -f /tmp/emudhra-spki.txt ] || { echo "缺 SPKI 清单：先跑「检测」第 2 节的清单写入"; exit 1; }

# 1) 系统 + Python certifi 两个 store 逐个回扫（期望 hits=0）
for z in /etc/ssl/certs/ca-certificates.crt "$(python3 -c 'import certifi;print(certifi.where())' 2>/dev/null)"; do
  [ -f "$z" ] || continue
  echo "== $z"
  openssl crl2pkcs7 -nocrl -certfile "$z" | openssl pkcs7 -print_certs -out /tmp/vb.pem
  rm -f /tmp/vb-*; csplit -sz -f /tmp/vb- /tmp/vb.pem '/-----BEGIN CERTIFICATE-----/' '{*}'
  hits=0
  for c in /tmp/vb-*; do
    spki=$(openssl x509 -in "$c" -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -r | cut -d' ' -f1)
    grep -qxF "$spki" /tmp/emudhra-spki.txt && { hits=$((hits+1)); openssl x509 -in "$c" -noout -subject; }
  done
  echo "hits=$hits"                       # 期望 0
done

# 2) Node 内置根：同样按 SPKI 命中数（期望 hits 0，不是只看数量）
node -e '
const {X509Certificate,createHash}=require("crypto");
const bad=new Set(require("fs").readFileSync("/tmp/emudhra-spki.txt","utf8").split("\n").filter(Boolean));
const hits=[];
for(const p of require("tls").rootCertificates){try{
  const c=new X509Certificate(p);
  const h=createHash("sha256").update(c.publicKey.export({type:"spki",format:"der"})).digest("hex");
  if(bad.has(h)) hits.push(c.subject);
}catch(e){}}
console.log("rootCertificates",require("tls").rootCertificates.length,"hits",hits.length,hits);'

# 2b) Java cacerts：**按别名精确查**（手工处置后必须为 0）
keytool -list -cacerts -storepass changeit 2>/dev/null \
  | grep -icE 'emsigneccrootcag3|emsignrootcag1|emsignrootcag2'   # 期望 0
#     GraalVM native image：确认二进制是用**清洗后 cacerts 的构建机**重编译的（构建日志 + 产物时间）

# 2c) Debian 包版本身份（已确认版本）
dpkg-query -W -f='${Version}\n' ca-certificates    # trixie 20250419+deb13u1 / unstable 20260816+nmu1

# 2d) .NET：无独立版本，确认它读的 OS store 已清
echo "SSL_CERT_FILE=${SSL_CERT_FILE:-<unset>} SSL_CERT_DIR=${SSL_CERT_DIR:-<unset>}"   # Linux 默认 /etc/ssl/certs
openssl crl2pkcs7 -nocrl -certfile /etc/ssl/certs/ca-certificates.crt \
  | openssl pkcs7 -print_certs -noout | grep -icE 'emSign|eMudhra|AAA Certificate'      # 期望 0

# 3) 端到端：测试主机握手应被拒
openssl s_client -connect emudhra.we-have-a-problem.com:443 -verify_return_error </dev/null 2>&1 \
  | grep -E 'Verify return code' # 期望非 0（如 2/19/20）

# 4) 业务 TLS 回归：正常站点仍可访问
curl -sS -o /dev/null -w '%{http_code}\n' "https://${PEER:?export PEER=关键依赖域名}/"

# 5) 应用层校验关断已修（gist / Thrift）
gem list gist 2>/dev/null | grep -E '\(6\.(1|[2-9])'                # 期望 6.1.0 及以上
grep -rn 'VERIFY_NONE' "$(gem which gist 2>/dev/null | xargs -r dirname)" 2>/dev/null | wc -l   # 期望 0
perl -MThrift -e 'print "$Thrift::VERSION\n"' 2>/dev/null           # 期望 0.25.0

# 6) Python 侧已确认修复版（certifi / uv）
python3 -c 'import certifi;print(certifi.__version__)'                # 期望 2026.10.19
uv --version 2>/dev/null                                              # 期望 0.13.4
```

**通过标准**

1. 五套信任库回扫均为 0 命中（系统 / Node 按 SPKI；Python certifi 按 SPKI；Java 按 keytool subject 近似；Rust 按 `cargo tree` 版本），各自留证据；
2. Go 用新工具链**重新编译**，`go version -m` 显示新版本；
3. 测试主机握手返回非 0 的 verify code；
4. 业务 TLS 全链路回归通过，无新增证书告警；
5. 对外证书已换 CA（若原链涉及 eMudhra）并有新证书链留档；
6. 代码签名策略已评估（2 张被攻破的 CS 中间 CA）；
7. Debian：`ca-certificates` 版本 = 已确认修复版（trixie `20250419+deb13u1` / unstable `20260816+nmu1`）；若在 **bookworm** 上，标注「未确认」并单独跟踪；
8. Java：`keytool` 三个别名（`emsigneccrootcag3` / `emsignrootcag1` / `emsignrootcag2`）回扫为 0；用 GraalVM native image 的，构建机 cacerts 已清洗且产物已重编译；
9. .NET：OS/基础镜像 store 回扫为 0（Linux 走 `/etc/ssl/certs` 或 `SSL_CERT_FILE`），**不找 .NET 版本号**；
10. `gist` ≥ `6.1.0` 且源码中 `VERIFY_NONE` 命中数为 0；perl `Thrift` ≥ `0.25.0`（两条与信任库无关，必须单独出证据）；
11. `certifi` = `2026.10.19`、`uv` ≥ `0.13.4`（Python 侧已确认项）；bookworm 缺口按 `index.md` 未闭环清单跟踪。

## 回退

```bash
# 0) 升级前先落基线（ca-certificates 版本 + 应用侧自定义 bundle 路径 + 各运行时版本）
#    CHG=变更单号
: "${CHG:?export CHG=变更单号}"; mkdir -p "/secure/change/$CHG"
PRE_CA=$(dpkg-query -W -f='${Version}' ca-certificates)
PRE_NODE=$(node -v 2>/dev/null | tr -d v)
PRE_CERTIFI=$(python3 -c 'import certifi;print(certifi.__version__)' 2>/dev/null)
PRE_UV=$(uv --version 2>/dev/null | awk '{print $2}')
printf '%s\n%s\n%s\n%s\n' "$PRE_CA" "$PRE_NODE" "$PRE_CERTIFI" "$PRE_UV" | tee "/secure/change/$CHG/pre-trust.txt"

# 1) 系统信任库回退（仅当移除根导致业务中断）
apt-get -y install "ca-certificates=$PRE_CA" && update-ca-certificates --fresh

# 2) 应用侧回退（各自独立，按基线值逐个回）
nvm install "$PRE_NODE" && nvm use "$PRE_NODE"        # Node 内置 CA 只能整体回退运行时
python3 -m pip install "certifi==$PRE_CERTIFI"        # 再用 4.1 第 5 条重启进程
# Node 使用自定义 bundle 时：NODE_EXTRA_CA_CERTS / --use-openssl-ca 回退到基线配置

# 3) gist / Thrift 回退（回退 = 重新关掉证书校验，必须有到期时间）
#    Gemfile.lock 里 gist 的版本行改回基线后 `bundle install --local`；perl 用 cpanm Thrift@"$BASELINE_VERSION"
```

**回退后风险**：回退信任库 = 重新接受可被伪造成任意站点的证书，等于打开中间人通道；且攻击者已知私钥，利用成本极低。回退 `gist` / Thrift = 重新关掉应用层证书校验（`VERIFY_NONE`），比信任库回退更直接。回退只允许在「升级导致关键业务不可用」的短窗口，并必须同时：限制出站目标、加证书钉扎（pinning）、给出二次处置时间点。

## 条目

> **同一 `CVE-2026-111943`，按信任库分行承载；生态级修复见 04，信任库级处置见本件。**
> （`inventory.tsv` 的「一 CVE 一行」不套用到本表：各承载物不同、处置不同，合并会丢处置差异。跨生态/跨信任库允许分行。）

| 编号 | 对象 | 影响区间 | 修复 | 来源 |
|---|---|---|---|---|
| CVE-2026-111943 | Go / Rust / Node 内置 CA（同根因跨生态，merge_key 相同） | Go `<1.26.10`/`<1.27.3`；webpki-roots `<1.0.10`（`=0.26.11` unaffected）；rustls-webpki `<0.103.16` 或 `0.104.0-alpha.1–<0.104.0-alpha.8`；webpki-root-certs `<1.0.10`；Node 22/24/26 修复线之前 | Go `1.26.10`/`1.27.3`；webpki-roots `1.0.10`；rustls-webpki `0.103.16`/`0.104.0-alpha.8`；webpki-root-certs `1.0.10`；Node `22.23.4`/`24.22.1`/`26.12.1` | S501–S508 / GO-2026-6809 |
| CVE-2026-111943（Debian 承载） | Debian `ca-certificates`（系统 trust store） | 仍含 `emSign ECC Root CA - G3` / `Comodo AAA Services root` 的旧包 | trixie `20250419+deb13u1`（DSA-6572-1）/ unstable `20260816+nmu1`；**bookworm 未确认** | tracker + DSA-6572-1 |
| CVE-2026-111943（Java 承载） | `cacerts`（JDK 内置） | **无厂商修复版本**；OpenJDK master 仍含 3 张 emSign 根 | 手工 `keytool -delete -alias` 清 `emsigeccrootcag3`/`emsignrootcag1`/`emsignrootcag2`，或指向清洗后 trustStore；GraalVM native image 重编译 | JDK-8319187 + GraalVM 文档 |
| CVE-2026-111943（.NET 承载） | .NET（无 bundle，随 OS） | Windows Cert Store / Linux OpenSSL / macOS Keychain | **无独立版本**：更新 OS/基础镜像 store | MS Learn cross-platform-crypto |
| CVE-2026-113470 | Firefox / NSS OneCRL | OneCRL 未生效或自定义设置阻断更新 | `158.0.1` / ESR `115.43.1`·`153.5.1` / Android `158.0.2` / NSS `3.131.1` | MFSA 2026-111 |
| CVE-2026-105221 | `gist` RubyGem（硬编码 `VERIFY_NONE`） | `<6.1.0` | `6.1.0` | NVD / 上游 commit |
| CVE-2026-85086 | Apache Thrift perl bindings（不安全 TLS 默认） | `<0.25.0` | `0.25.0`（**依据 CVE 记录 CNA=apache + NVD**；Apache 公告页正文需 JS 未取到） | NVD / CNA 记录 |
| GHSA-6q48-6c7w-9gw2（无 CVE 别名） | Python `certifi`（打包 emSign 根证书） | `>=2019.03.09 <2026.10.19` | `2026.10.19` | GHSA-6q48-6c7w-9gw2 |
| GHSA-hq85-5cpj-mr62（无 CVE 别名） | Python `uv` 内置 CA store | `<0.13.4` | `0.13.4` | GHSA-hq85-5cpj-mr62 |

> 与 `vuln-w1/inventory.tsv` 对应：CVE-2026-105221 = W1-068（`merge_key=ruby-gist-105221`）、CVE-2026-85086 = W1-069（`perl-thrift-85086`）。

## 来源

| 类型 | URL |
|---|---|
| 一手（Mozilla 安全团队的 oss-security 披露原文：8 张中间 CA、3 个根 SPKI、吊销时间线、CT 现状、建议） | https://www.openwall.com/lists/oss-security/2026/10/20/1 |
| 一手（Mozilla 官方博客：OneCRL 3 小时、Firefox 158.0.1 / ESR 115.43.1·153.5.1 / NSS 3.131.1 / Android 158.0.2） | https://blog.mozilla.org/security/2026/10/20/protecting-firefox-users-following-the-compromise-of-emudhra-intermediate-certificates/ |
| 一手（RUSTSEC-2026-0381，webpki-roots：patched >=1.0.10，0.26.11 unaffected，alias CVE-2026-111943） | https://raw.githubusercontent.com/rustsec/advisory-db/main/crates/webpki-roots/RUSTSEC-2026-0381.md |
| 一手（RUSTSEC-2026-0382，rustls-webpki：`<0.103.16` 或 `0.104.0-alpha.1–<0.104.0-alpha.8` → 0.103.16 / 0.104.0-alpha.8） | https://raw.githubusercontent.com/rustsec/advisory-db/main/crates/rustls-webpki/RUSTSEC-2026-0382.md |
| 一手（RUSTSEC-2026-0383，webpki-root-certs：>=1.0.10） | https://raw.githubusercontent.com/rustsec/advisory-db/main/crates/webpki-root-certs/RUSTSEC-2026-0383.md |
| 一手（OSV GO-2026-6809，Go crypto/x509：1.26.10 / 1.27.3） | https://osv.dev/vulnerability/GO-2026-6809 |
| 一手（Node.js 安全公告：ca-cert 随 22.23.4 / 24.22.1 / 26.12.1 更新） | https://nodejs.org/en/blog/vulnerability/october-2026-security-releases |
| 一手（MFSA 2026-111：CVE-2026-113470，high，Firefox 158.0.1 内更新 OneCRL 阻断列表） | https://www.mozilla.org/en-US/security/advisories/mfsa2026-111/ |
| 一手（Bugzilla 2083449：根因 = 私钥为 <256 的整数，可秒级恢复；Sectigo 交叉签当时仍未吊销） | https://bugzilla.mozilla.org/show_bug.cgi?id=2083449 |
| 一手（Debian 安全 tracker：`ca-certificates` 各发行版版本 + DSA/DLA 索引） | https://security-tracker.debian.org/tracker/ca-certificates |
| 一手（Debian Bug #1151413：eMudhra 中间 CA 被攻破 → 移除 `emSign ECC Root CA - G3` / `Comodo AAA Services root`；severity grave） | https://bugs.debian.org/1151413 |
| 一手（OpenJDK JDK-8319187：`Add three eMudhra emSign roots`——证明 Java cacerts 含这 3 张根；master 源码树仍含对应文件） | https://bugs.openjdk.org/browse/JDK-8319187 |
| 一手（GraalVM Native Image · Certificate Management：构建期捕获宿主 TrustStore、`blacklisted.certs` 构建期加载 → native image 必须重编译） | https://www.graalvm.org/latest/reference-manual/native-image/dynamic-features/CertificateManagement/ |
| 一手（MS Learn：.NET 跨平台加密 = Windows Cert Store / Linux OpenSSL / macOS Keychain，无独立 bundle） | https://learn.microsoft.com/en-us/dotnet/standard/security/cross-platform-cryptography |
| 一手（NVD：CVE-2026-105221，gist `<6.1.0` → `6.1.0`，CWE-295，CVSS 3.1 7.4 / 4.0 9.1） | https://nvd.nist.gov/vuln/detail/CVE-2026-105221 |
| 一手（上游 commit：gist 移除 `VERIFY_NONE`） | https://github.com/defunkt/gist/commit/07ccc1a6d46e9d36f0e85d0b1c5d795890ae6bcf |
| 一手（CVE 记录 CNA=apache：CVE-2026-85086，`<0.25.0` → `0.25.0`，含 lists.apache.org 线程引用） | https://lists.apache.org/thread/33otcgbqd27wf6qq810q56znzbomnhg1 |
| 一手（NVD：CVE-2026-85086，CWE-295 + CWE-1188，CVSS 4.0 6.9；**Apache 公告页正文需 JS 未取到**） | https://nvd.nist.gov/vuln/detail/CVE-2026-85086 |
| 一手（GHSA-6q48-6c7w-9gw2：certifi `>=2019.03.09 <2026.10.19` → `2026.10.19`，critical） | https://github.com/advisories/GHSA-6q48-6c7w-9gw2 |
| 一手（GHSA-hq85-5cpj-mr62：uv `<0.13.4` → `0.13.4`） | https://github.com/advisories/GHSA-hq85-5cpj-mr62 |
