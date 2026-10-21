---
id: "05"
title: Python / LLM 基建漏洞处置（vLLM / LMCache / Ollama / GitLab AI Gateway）
ecosystem: python-llm
cve: ["CVE-2026-90553", "CVE-2026-105192", "CVE-2026-103663", "CVE-2026-90970", "CVE-2026-105752"]
affects: "vLLM <0.28.0（loader RCE）、≤0.25.1；LMCache 0.3.9–0.5.5（含 0.5.6rc）；Ollama >=0.34.2 <0.35.0；GitLab AI Gateway 18.1.6–<19.2.4 / 19.3.0–<19.3.2 / 19.4.0–<19.4.1"
fixed: ["vLLM 0.28.0", "vLLM 0.30.0", "LMCache 0.5.6", "Ollama 0.35.0", "GitLab 19.2.4", "GitLab 19.3.2", "GitLab 19.4.1"]
severity: "严重（LMCache 9.8 未认证 RCE；GitLab AI Gateway 9.9 需认证 PR:L；Ollama 条件 CVSS 9.4 / 6.9）"
status: verified
sources: ["https://github.com/vllm-project/vllm/security/advisories/GHSA-3c86-2m5g-59q7", "https://github.com/LMCache/LMCache/security/advisories/GHSA-w5f2-9q9c-ff4h", "https://cert.pl/en/posts/2026/10/CVE-2026-103663/", "https://github.com/vllm-project/vllm/security/advisories/GHSA-935w-9g4m-p28p"]
updated: 2026-10-21
---

# Python / LLM 基建漏洞处置

**一句话**：LLM 基建的通病是「默认无认证 + 默认高权限 + 默认信远端代码」。先断端口暴露面，再升版本；`trust_remote_code=False` 不是万能挡箭牌（vLLM 那条就是 loader 绕过它）。

## 适用版本区间

| 组件 | 受影响 | 修复 |
|---|---|---|
| vLLM | `<0.28.0`（LlavaOnevision2 loader） | `0.28.0` |
| vLLM | `≤0.25.1`（Harmony 工具续轮丢 `cache_salt`） | `0.30.0` |
| vLLM | `≤0.31.0`（mamba_mixer2 越界读） | **未确认**；已降为观察项，见文末 |
| LMCache | `0.3.9–0.5.5`（含 `0.5.6rc`） | `0.5.6` |
| Ollama | `>=0.34.2 <0.35.0`（cvelistV5 `affected` 原文） | `0.35.0`（**CNA = CERT-PL**，CVE 记录 `assignerShortName` 可证；Ollama 自身 release note 静默） |
| GitLab AI Gateway（Self-Hosted） | `18.1.6–<19.2.4` / `19.3.0–<19.3.2` / `19.4.0–<19.4.1` | `19.2.4` / `19.3.2` / `19.4.1`（GitLab 官方补丁公告，一手） |

**不在区间内的判断命令**

```bash
python3 -c 'import importlib.metadata as m
for p in ("vllm","lmcache","ollama"):
    try: print(p, m.version(p))
    except Exception: print(p, "not installed")'
ollama --version 2>/dev/null || ollama -v 2>/dev/null
curl -s -m 5 http://127.0.0.1:11434/api/version
```

## 检测

```bash
# 1) 版本（进程所在环境，不是宿主 pip）
pip show vllm lmcache 2>/dev/null | grep -E '^(Name|Version)'
python3 -c 'import importlib.metadata as m;print(m.version("vllm"))'

# 2) 容器与端口暴露面（这四条漏洞的杀伤力全看暴露面）
docker ps --format '{{.Names}}\t{{.Image}}\t{{.Ports}}' | grep -Ei 'vllm|lmcache|ollama|gitlab'

# 3) 端口是否裸奔公网
ss -lntp 2>/dev/null | grep -E ':(8000|11434)\b'
curl -s -m 5 -o /dev/null -w 'ollama_api=%{http_code}\n' http://<公网IP>:11434/api/tags
curl -s -m 5 -o /dev/null -w 'vllm_api=%{http_code}\n' http://<公网IP>:8000/v1/models

# 4) 是否以 root 跑（LMCache 官方镜像默认 root，命中即放大器）
docker inspect <CONTAINER> --format '{{.Config.User}}'   # 空值 = root

# 4b) Ollama 专用：是否对 /usr/lib/ollama 有写权限（决定 CVSS 9.4 还是 6.9）
test -w /usr/lib/ollama && echo "WRITABLE -> 9.4 Critical 场景" || echo "not writable -> 6.9 Medium 场景"
docker exec <OLLAMA_CONTAINER> sh -c 'test -w /usr/lib/ollama && echo writable || echo readonly'

# 5) vLLM 是否加载远端代码 / 不受信模型
grep -RniE 'trust_remote_code' --include='*.py' --include='*.yaml' --include='*.sh' . 2>/dev/null | head -20

# 6) GitLab AI Gateway 版本
curl -s -m 5 http://<gitlab>/help | grep -oE 'GitLab (Community|Enterprise) Edition[^<]*' | head -1
```

**命中判据**：版本落在上表区间；且 8000 / 11434 / LMCache ZMQ 端口能从「不该访问的网络位置」连通。

## 影响判定

| CVE | 缺陷 | 触发前提（查这个） | 暴露面 |
|---|---|---|---|
| CVE-2026-105192 | LMCache ZMQ 未认证 pickle 反序列化 → 未认证 RCE | ZMQ 端口可达；官方镜像以 root 运行 | 端口公网可达 = P0 |
| CVE-2026-103663 | Ollama `/api/pull` 路径穿越（CWE-23）→ 重启后执行写入文件 | 11434 可达且能触发 pull；**是否 RCE 取决于进程对 `/usr/lib/ollama` 的写权限** | 默认 root 镜像 + 公网 11434 = **P0（CVSS 4.0 9.4）**；非 root/只读 = 6.9，P1。CISA-ADP SSVC `Exploitation: none`（未见在野利用） |
| CVE-2026-90553 | vLLM LlavaOnevision2 loader 无视 `trust_remote_code` → RCE | 加载攻击者可控的模型仓库（模型名/路径来自用户或外部 registry） | 多租户/开放模型上传 = P1 |
| CVE-2026-90970 | GitLab AI Gateway prompt 模板沙箱逃逸 → 命令执行（CVSS 9.9，**PR:L 需认证**） | **自建** Self-Hosted AI Gateway，且攻击者持 Duo Agent Platform 访问权 | 需认证 = P1；GitLab.com / Dedicated / GitLab-hosted gateway 不受影响 |
| CVE-2026-105752 | Harmony 工具续轮丢 `cache_salt` → 跨租户前缀缓存泄露 | 多租户共享 vLLM 前缀缓存 | 多租户 = P2 |

**误报排除**

- 只在本机跑 `ollama serve`、11434 仅 loopback → 暴露面为 0，但仍升级（同机其他进程可打）。
- vLLM 只加载自家发布的模型、不接受外部模型名 → CVE-2026-90553 风险低，但别用 `trust_remote_code=True` 当借口绕过。
- GitLab 用 SaaS 而非自建 AI Gateway → 该条不适用。

## 修复

顺序：**断暴露面 → 升版本 → 降权限 → 收紧模型来源**。

```bash
# 1) 断暴露面（分钟级）：端口只留内网
#    安全组/防火墙：8000 / 11434 / LMCache ZMQ 端口仅放行网关与调试网段
#    公网入口全部摘除；Ollama 加 OLLAMA_HOST=127.0.0.1 只监听本机
OLLAMA_HOST=127.0.0.1:11434 ollama serve

# 2) 升版本（在运行进程的同一环境里执行）
pip install -U "vllm>=0.30.0"          # 覆盖 0.28.0 / 0.30.0 两条修复线
pip install -U "lmcache==0.5.6"
ollama --version                       # 目标 0.35.0；见下方二进制升级

# 3) Ollama 二进制升级（v0.35.0 的 GitHub release 已由我一手核实存在，2026-09-28 发布）
#    release 资产是 .tar.zst 压缩包，不是裸二进制；下载后 tar 解到 /usr/local
curl -fLO https://github.com/ollama/ollama/releases/download/v0.35.0/ollama-linux-amd64.tar.zst
sudo tar -C /usr/local -xf ollama-linux-amd64.tar.zst
ollama --version                       # 期望 0.35.0

# 4) LMCache 降权限（别再 root）
#    Dockerfile: USER 10001:10001；或 docker run --user 10001:10001
docker run --user 10001:10001 <lmcache-image>

# 5) vLLM 收紧模型来源
#    只允许白名单模型仓库；禁止用户传入任意 HF repo / 本地路径
#    注意：CVE-2026-90553 的 loader 会「无视」trust_remote_code，所以不能只靠这个开关
```

GitLab AI Gateway（Omnibus）：

```bash
# 按当前所在线升级，三条线各自的目标版本
# 19.2.x → 19.2.4；19.3.x → 19.3.2；19.4.x → 19.4.1
sudo apt-get update && sudo apt-get install gitlab-ee=<目标版本>
sudo gitlab-ctl reconfigure
```

**防复发**

- LLM 服务默认不裸公网：前置网关 + 认证层（这些组件的默认状态是「无认证」）；
- 容器统一 `--user` 非 root、`--read-only`、最小能力；
- 模型来源做成白名单，CI 里禁止 `trust_remote_code=True`；
- `pip-audit` + `trivy image` 进部署门禁。

## 验证

```bash
# 1) 版本已到修复线
python3 -c 'import importlib.metadata as m;print("vllm",m.version("vllm"))'
python3 -c 'import importlib.metadata as m;print("lmcache",m.version("lmcache"))'
ollama --version
# 自建 GitLab AI Gateway 版本（三线目标：19.2.4 / 19.3.2 / 19.4.1）
curl -s -m 5 http://<gitlab>/help | grep -oE 'GitLab [0-9]+\.[0-9]+\.[0-9]+' | head -1

# 2) 暴露面已断（从公网位置跑，必须连不上）
curl -s -m 5 -o /dev/null -w '%{http_code}\n' http://<公网IP>:11434/api/tags    # 期望 000/超时
curl -s -m 5 -o /dev/null -w '%{http_code}\n' http://<公网IP>:8000/v1/models    # 期望 000/超时

# 3) Ollama 路径穿越复现探针（只在测试实例跑）
curl -s -o /dev/null -w 'pull=%{http_code}\n' http://127.0.0.1:11434/api/pull \
  -H 'Content-Type: application/json' -d '{"name":"../../tmp/poc"}'
# 修复后：拒绝/400，且 /tmp/poc 不生成

# 4) 容器非 root
docker inspect <CONTAINER> --format '{{.Config.User}}'   # 期望非空（如 10001:10001）

# 5) 功能回归：模型列表、推理、缓存命中
curl -s http://127.0.0.1:8000/v1/models -H "Authorization: Bearer $VLLM_API_KEY" | head -c 300
```

**通过标准**

1. vLLM ≥ `0.30.0`、LMCache = `0.5.6`、Ollama = `0.35.0`（或已确认的修复版本）；
2. 8000 / 11434 / ZMQ 端口从公网位置不可达；
3. 测试实例上路径穿越探针不再生成文件；
4. 容器 `User` 非空（非 root）；
5. 推理与模型列表回归正常，吞吐无明显下降；
6. 自建 GitLab AI Gateway 已到 `19.2.4` / `19.3.2` / `19.4.1` 对应线（GitLab-hosted 用户无需动作）。

## 回退

```bash
# 0) 升级前先落基线（回退点用值，不用记忆）
#    CHG=变更单号，CURRENT_IMAGE=容器当前镜像（如 lmcache/lmcache:0.5.5）
: "${CHG:?export CHG=变更单号}" "${CURRENT_IMAGE:?export CURRENT_IMAGE=容器当前镜像}"
mkdir -p "/secure/change/$CHG"
PRE_VLLM=$(python3 -c 'import importlib.metadata as m;print(m.version("vllm"))')
PRE_LMCACHE=$(python3 -c 'import importlib.metadata as m;print(m.version("lmcache"))')
PRE_OLLAMA=$(ollama --version 2>/dev/null | tail -1)
PRE_IMAGE=$(docker inspect -f '{{index .RepoDigests 0}}' "$CURRENT_IMAGE")
printf '%s\n%s\n%s\n%s\n' "$PRE_VLLM" "$PRE_LMCACHE" "$PRE_OLLAMA" "$PRE_IMAGE" | tee "/secure/change/$CHG/pre-llm.txt"
# 0b) 上一版 Ollama 安装包先留档（回退要用；不留档就没有回退路径）
PRE_OLLAMA_PKG="/secure/change/$CHG/ollama-linux-amd64.tar.zst"

# 1) 回退包版本
pip install "vllm==$PRE_VLLM" "lmcache==$PRE_LMCACHE"
python3 -c 'import importlib.metadata as m;print(m.version("vllm"), m.version("lmcache"))'

# 2) 回退镜像（认 digest）
docker pull "$(sed -n 4p "/secure/change/$CHG/pre-llm.txt")"   # RepoDigests 已是 name@sha256: 完整引用

# 2b) Ollama 二进制：升级前必须把上一版 .tar.zst 留档，否则没有回退路径
#     sudo tar -C /usr/local -xf "$PRE_OLLAMA_PKG"; ollama --version

# 3) 回退前必查：基线是否仍落在受影响区间；是则回退窗口内必须保留端口隔离与非 root
```

**回退后风险**：回退即重新暴露未认证 RCE（LMCache 9.8 / Ollama root RCE）。回退期间必须保留网络层隔离与非 root 运行；若回退到 `LMCache <0.5.6` 且端口可达，等同主动开门。

## 条目

| 编号 | 组件 | 影响区间 | 修复 | 来源 |
|---|---|---|---|---|
| CVE-2026-90553 | vLLM（LlavaOnevision2 loader） | `<0.28.0` | `0.28.0` | https://github.com/vllm-project/vllm/security/advisories/GHSA-3c86-2m5g-59q7 |
| CVE-2026-105192 | LMCache（ZMQ pickle） | `0.3.9–0.5.5`（含 `0.5.6rc`） | `0.5.6` | https://github.com/LMCache/LMCache/security/advisories/GHSA-w5f2-9q9c-ff4h |
| CVE-2026-103663 | Ollama（`/api/pull` 路径穿越，CWE-23） | `>=0.34.2 <0.35.0` | `0.35.0`（CNA = CERT-PL） | https://cert.pl/en/posts/2026/10/CVE-2026-103663/ |
| CVE-2026-90970 | GitLab AI Gateway（模板沙箱逃逸） | `18.1.6–<19.2.4` / `19.3.0–<19.3.2` / `19.4.0–<19.4.1` | `19.2.4` / `19.3.2` / `19.4.1`（官方，CVSS 9.9 `PR:L`） | https://docs.gitlab.com/releases/patches/other-patches/patch-release-gitlab-ai-gateway-19-4-1-released/ |
| CVE-2026-105752 | vLLM（跨租户缓存泄露，low） | `≤0.25.1` | `0.30.0` | https://github.com/vllm-project/vllm/security/advisories/GHSA-935w-9g4m-p28p |

**未确认（不进结论，只跟进）**：CVE-2026-114053（AutoProcessor RCE）、CVE-2026-105754（多模态传输信任调用方特征）均为二手候选，未核实到官方 GHSA。

## 来源

| 类型 | URL |
|---|---|
| 一手（vLLM GHSA，loader RCE） | https://github.com/vllm-project/vllm/security/advisories/GHSA-3c86-2m5g-59q7 |
| 一手（vLLM GHSA，缓存泄露） | https://github.com/vllm-project/vllm/security/advisories/GHSA-935w-9g4m-p28p |
| 一手（LMCache GHSA，ZMQ pickle RCE） | https://github.com/LMCache/LMCache/security/advisories/GHSA-w5f2-9q9c-ff4h |
| 一手（Ollama release v0.35.0 存在性 + 资产名，2026-09-28） | https://github.com/ollama/ollama/releases/tag/v0.35.0 |
| 一手（PyPI 版本存在性：vllm `0.28.0/0.30.0/0.31.0/0.32.0`、lmcache `0.5.6`） | https://pypi.org/pypi/vllm/json |
| 一手（CVE 官方记录 cvelistV5：CNA=CERT-PL、`>=0.34.2 <0.35.0`、两条 CVSS 4.0 场景 6.9/9.4、ADP SSVC `Exploitation: none`） | https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/103xxx/CVE-2026-103663.json |
| 一手（CERT Polska 公告原文，Ollama；0.35.0 修复） | https://cert.pl/en/posts/2026/10/CVE-2026-103663/ |
| 一手（GitLab 官方补丁发布页，CVSS 9.9 `PR:L`） | https://docs.gitlab.com/releases/patches/other-patches/patch-release-gitlab-ai-gateway-19-4-1-released/ |
| 二手（ThaiCERT 转述，仅作交叉印证） | https://www.thaicert.or.th/en/2026/10/05/gitlab-patches-critical-ai-gateway-vulnerability-that-could-allow-command-execution-on-self-hosted-gateways/ |
| 未确认（vLLM mamba_mixer2，VulDB 源） | https://github.com/advisories/GHSA-QX62-JWPF-RCPJ |

## 观察项（不进处置结论、不给升级命令）

| 编号 | 组件 | 状态 | 判定 |
|---|---|---|---|
| CVE-2026-105775 | vLLM（mamba_mixer2 越界读） | VulDB 导入的 GitHub advisory，`github_reviewed=false`；上游 issue #57266 只是崩溃 bug，**无 GHSA、无修复 commit** | 观察，不入 `cve` 列表、不给修复版本。等官方 advisory 出现再升格 |
