---
id: "09"
title: eMudhra 中间 CA 私钥泄露 · PKI 处置与五套信任库更新
ecosystem: pki
cve: ["CVE-2026-111943", "CVE-2026-113470"]
affects: "证书链经过 3 个根（AAA Certificate Services / emSign Root TLS CA - G3 / emSign ECC Root CA - G3）的中间 CA；受影响的是**信任库**而非某个软件版本：Go <1.26.10 / <1.27.3、Rust webpki-roots <1.0.10 且 0.26.11 之前、rustls-webpki <0.103.16 且 <0.104.0-alpha.8、webpki-root-certs <1.0.10、Node 22/24/26 修复线之前；Python certifi / Java cacerts / Linux ca-certificates / .NET 处置版本**未确认**"
fixed: ["Go 1.26.10", "Go 1.27.3", "webpki-roots 1.0.10", "webpki-root-certs 1.0.10", "rustls-webpki 0.103.16", "rustls-webpki 0.104.0-alpha.8", "Node 22.23.4", "Node 24.22.1", "Node 26.12.1", "Firefox 158.0.1", "Firefox ESR 115.43.1", "Firefox ESR 153.5.1", "Firefox Android 158.0.2", "NSS 3.131.1"]
severity: "高危（伪造 HTTPS 证书做中间人；私钥已广为人知，CT 日志暂未见签发记录，但厂商明确「近期很可能被滥用」）"
status: verified
sources: ["https://www.openwall.com/lists/oss-security/2026/10/20/1", "https://blog.mozilla.org/security/2026/10/20/protecting-firefox-users-following-the-compromise-of-emudhra-intermediate-certificates/", "https://raw.githubusercontent.com/rustsec/advisory-db/main/crates/webpki-roots/RUSTSEC-2026-0381.md", "https://osv.dev/vulnerability/GO-2026-6809"]
updated: 2026-10-21
---

# eMudhra 中间 CA 私钥泄露 · PKI 处置

**一句话**：**只升浏览器/运行时修不掉系统 trust store**。Go、Rust、Node、Python、Java、Linux 各自有独立信任库，随二进制或系统发行，要**逐个更新并逐个验证**；同时「对外证书换 CA 重签」和「客户端信任库更新」是两件事，不能互相替代。

## 适用版本区间

本事件的判定不按单一软件版本，而按**信任库**：只要你的信任库仍信任这 3 个根或其交叉签名，你就可被伪造证书欺骗。

| 信任库 | 受影响条件 | 处置版本 | 来源等级 |
|---|---|---|---|
| Go crypto/x509 | `<1.26.10`、`1.27.0–<1.27.3` | `1.26.10` / `1.27.3` | 一手（OSV GO-2026-6809） |
| Rust `webpki-roots` | `<1.0.10`（`0.26.11` 不受影响） | `>=1.0.10` | 一手（RUSTSEC-2026-0381） |
| Rust `rustls-webpki` | `<0.103.16`、`0.104.0-alpha.1–<0.104.0-alpha.8` | `0.103.16` / `0.104.0-alpha.8` | 一手（RUSTSEC-2026-0382） |
| Rust `webpki-root-certs` | `<1.0.10`（`0.26.11` 不受影响） | `>=1.0.10` | 一手（RUSTSEC-2026-0383） |
| Node.js 内置 CA（ca-cert 依赖） | 22/24/26 三条线修复版之前 | `22.23.4` / `24.22.1` / `26.12.1` | 一手（Node 安全公告） |
| Firefox / NSS | OneCRL 未生效或自定义设置阻断更新 | `158.0.1` / ESR `115.43.1`·`153.5.1` / Android `158.0.2` / NSS `3.131.1`（**CVE-2026-113470**，MFSA 2026-111，high） | 一手（Mozilla 博客 + MFSA） |
| **Python certifi** | 版本未知 | **未确认** | 待核 |
| **Java cacerts** | 版本未知 | **未确认** | 待核 |
| **Linux ca-certificates** | 发行版各自 | **未确认**（按发行版 tracker） | 待核 |
| **Chrome / Android** | CRLSets 阻断 | 侦察交件；Google 原文正文未能抓取 | **待核** |
| **.NET / 其他** | 自带 trust store | **未确认** | 待核 |

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
# Python certifi（独立 bundle，不跟系统走）
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

# Java cacerts（keytool 打的是证书 SHA-256，需另备一份证书指纹清单）
keytool -list -cacerts -storepass changeit 2>/dev/null | grep -iE 'emSign|eMudhra|AAA Certificate' | head

# Rust
cargo tree -i webpki-roots 2>/dev/null; cargo tree -i rustls-webpki 2>/dev/null; cargo tree -i webpki-root-certs 2>/dev/null

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

## 影响判定

| 条件 | 判定 |
|---|---|
| 客户端**可靠检查吊销且 fail-closed**，且只走 eMudhra 原生链 | Mozilla 博客：无需动作（10-18 已吊销） |
| 客户端走 **Sectigo 交叉签名链** | **不能只靠吊销**：Bugzilla 2083449 记录显示交叉签名证书当时**仍未吊销**（10-18 时点）；必须按 SPKI 直接移除信任 |
| 客户端**不查吊销 / fail-open** | **必须更新信任库**：可被伪造证书中间人 |
| 对外服务证书由 eMudhra 签发 | **P0 业务侧**：换 CA 重签；客户可能开始报证书错误 |
| 只升了浏览器、服务器/客户端信任库未动 | **未修复**：Java/Python/Go/Rust 各自独立 |
| 移除 3 个根 | 可有效防护，但**可能打断**使用这些根下其他中间 CA 的站点（Mozilla 明确提示） |
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
- 服务端证书没用 eMudhra 签发 → 你不需要重签，但**客户端信任库仍要更新**（别人可以伪造任何域名）。

## 修复

顺序：**两件事分开做**——① 客户端信任库各自更新；② 自家对外证书若走 eMudhra，换 CA 重签。

### 4.1 信任库：五套分别更新

```bash
# 1) 系统（Debian/Ubuntu 示例）—— 先确认发行版已移除，再升级
apt-get update && apt-get -y install --only-upgrade ca-certificates
update-ca-certificates
# 回扫：应无输出
bash -c 'openssl crl2pkcs7 -nocrl -certfile /etc/ssl/certs/ca-certificates.crt | openssl pkcs7 -print_certs -noout' \
  | grep -icE 'emSign|eMudhra|AAA Certificate'

# 2) Go：升级工具链后**重新编译**（Go 的拒绝逻辑在代码里，不是换 CA 文件）
go mod edit -toolchain=go1.26.10 && go get go@1.26.10 && go mod tidy
go build ./... && go version -m ./<binary> | head

# 3) Rust：升级依赖并重新构建
cargo update -p webpki-roots -p rustls-webpki -p webpki-root-certs
cargo build --locked

# 4) Node：升级运行时（ca-cert 随二进制走），SEA/snapshot 产物要重建
nvm install 24.22.1 && nvm use 24.22.1 && node -v

# 5) Python：升级 certifi 后重启进程（必要时注入自定义 bundle）
python3 -m pip install -U certifi
python3 -c 'import certifi;print(certifi.__version__, certifi.where())'

# 6) Java：更新 cacerts（版本未确认，先按发行版/JDK 安全公告处置）
keytool -list -cacerts -storepass changeit | grep -icE 'emSign|eMudhra|AAA Certificate'
```

> **Java / .NET / Linux 发行版 / Python certifi 的精确处置版本本稿未确认**——必须按各自官方公告与发行版 tracker 定，不在这里编版本号。

### 4.2 对外证书：换 CA 重签（与信任库更新无关）

```bash
# 1) 列出对外证书链，看签发者
openssl s_client -connect <你的域名>:443 -servername <你的域名> </dev/null 2>/dev/null \
  | openssl x509 -noout -issuer -subject -dates
# 2) 若 issuer 链到 eMudhra / emSign / AAA Certificate Services → 换 CA 重新签发并替换证书链
# 3) 替换后复测（含中间证书完整性）
openssl s_client -connect <你的域名>:443 -servername <你的域名> -showcerts </dev/null 2>/dev/null | grep -c 'BEGIN CERTIFICATE'
```

### 4.3 防护策略

- 客户端强制 **CRL/OCSP 检查 + fail-closed**（Mozilla 原文：可靠检查吊销并 fail-closed 的用户无需动作）；
- 对**代码签名**也适用：被攻破的 2 张 CS 中间 CA 可签恶意代码，需检查代码签名信任策略；
- 监控：出现由这些 SPKI 签发的新证书（CT 监控）即告警。

## 验证

```bash
# 1) 信任库回扫必须为空（每个 store 分别跑）
for z in /etc/ssl/certs/ca-certificates.crt "$(python3 -c 'import certifi;print(certifi.where())' 2>/dev/null)"; do
  [ -f "$z" ] && openssl crl2pkcs7 -nocrl -certfile "$z" | openssl pkcs7 -print_certs -noout \
    | grep -icE 'emSign|eMudhra|AAA Certificate'
done

# 2) Node 内置根 SPKI 回扫（期望 hits 0）
node -e 'console.log(require("tls").rootCertificates.length)'

# 3) 端到端：测试主机握手应被拒
openssl s_client -connect emudhra.we-have-a-problem.com:443 -verify_return_error </dev/null 2>&1 \
  | grep -E 'Verify return code' # 期望非 0（如 2/19/20）

# 4) 业务 TLS 回归：正常站点仍可访问
curl -sS -o /dev/null -w '%{http_code}\n' https://<关键依赖域名>/
```

**通过标准**

1. 五套信任库回扫均为 0 命中（系统 / Node / Python / Java / Rust 各自出证据）；
2. Go 用新工具链**重新编译**，`go version -m` 显示新版本；
3. 测试主机握手返回非 0 的 verify code；
4. 业务 TLS 全链路回归通过，无新增证书告警；
5. 对外证书已换 CA（若原链涉及 eMudhra）并有新证书链留档；
6. 代码签名策略已评估（2 张被攻破的 CS 中间 CA）。

## 回退

```bash
# 信任库回退（仅当移除根导致业务中断）
apt-get -y install ca-certificates=<旧版本> && update-ca-certificates --fresh
# 应用侧回退自定义 bundle 路径（Node: --use-openssl-ca / NODE_EXTRA_CA_CERTS 视实现）
```

**回退后风险**：回退信任库 = 重新接受可被伪造成任意站点的证书，等于打开中间人通道；且攻击者已知私钥，利用成本极低。回退只允许在「移除根导致关键业务不可用」的短窗口，并必须同时：限制出站目标、加证书钉扎（pinning）、给出二次处置时间点。

## 来源

| 类型 | URL |
|---|---|
| 一手（Mozilla 安全团队的 oss-security 披露原文：8 张中间 CA、3 个根 SPKI、吊销时间线、CT 现状、建议） | https://www.openwall.com/lists/oss-security/2026/10/20/1 |
| 一手（Mozilla 官方博客：OneCRL 3 小时、Firefox 158.0.1 / ESR 115.43.1·153.5.1 / NSS 3.131.1 / Android 158.0.2） | https://blog.mozilla.org/security/2026/10/20/protecting-firefox-users-following-the-compromise-of-emudhra-intermediate-certificates/ |
| 一手（RUSTSEC-2026-0381，webpki-roots：patched >=1.0.10，0.26.11 unaffected，alias CVE-2026-111943） | https://raw.githubusercontent.com/rustsec/advisory-db/main/crates/webpki-roots/RUSTSEC-2026-0381.md |
| 一手（RUSTSEC-2026-0382，rustls-webpki：0.103.16 / 0.104.0-alpha.8） | https://raw.githubusercontent.com/rustsec/advisory-db/main/crates/rustls-webpki/RUSTSEC-2026-0382.md |
| 一手（RUSTSEC-2026-0383，webpki-root-certs：>=1.0.10） | https://raw.githubusercontent.com/rustsec/advisory-db/main/crates/webpki-root-certs/RUSTSEC-2026-0383.md |
| 一手（OSV GO-2026-6809，Go crypto/x509：1.26.10 / 1.27.3） | https://osv.dev/vulnerability/GO-2026-6809 |
| 一手（Node.js 安全公告：ca-cert 随 22.23.4 / 24.22.1 / 26.12.1 更新） | https://nodejs.org/en/blog/vulnerability/october-2026-security-releases |
| 一手（MFSA 2026-111：CVE-2026-113470，high，Firefox 158.0.1 内更新 OneCRL 阻断列表） | https://www.mozilla.org/en-US/security/advisories/mfsa2026-111/ |
| 一手（Bugzilla 2083449：根因 = 私钥为 <256 的整数，可秒级恢复；Sectigo 交叉签当时仍未吊销） | https://bugzilla.mozilla.org/show_bug.cgi?id=2083449 |
