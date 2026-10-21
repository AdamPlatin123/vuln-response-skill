---
name: vuln-response
description: 互联网漏洞情报 → 检测 / 影响判定 / 修复 / 验证 的可执行流程。覆盖 Node/npm、Go、Python-LLM 基建与通用供应链投毒。触发：收到 CVE/GHSA/公告链接、问「版本 X 受影响吗」「要不要升级」「包是否被投毒」、发版前基线核查。
---

# 漏洞响应 Skill

## 何时用（触发条件）

命中任一条即加载：

- 用户给出 **CVE / GHSA / 厂商公告 URL**，问怎么修；
- 问「**版本 X 受不受影响**」「要不要升级」「升到哪个版本」；
- 怀疑**依赖被投毒**（postinstall 异常、锁文件漂移、陌生包名）；
- **发版/上线前基线核查**（Node/Go/Python 运行时与 LLM 网关）；
- **要动生产**（发版 / 关停 / 改库 / 轮换凭据）→ 先按 `playbooks/07-production-remediation.md` 定档位；
- 安全公告批量跟进（一次几十条，需要归并成表）。

不适用：纯情报搜集（找新漏洞）→ 那是 `漏洞侦察` 的职责；写业务功能代码 → 普通编码。

## 输入与入口

| 输入 | 第一步 |
|---|---|
| 包名 + 版本 | 直接跳到本 playbook「检测」段 |
| CVE / GHSA 编号 | 先取一手来源 → 查 `index.md` 是否已有 playbook |
| 公告 URL | 抽取 `affects` / `fixed` 区间 → 命中已有 playbook 就复用，不新建 |
| 一堆告警/表格 | 按 `index.md` 生态分组，走「归并规则」 |

## 决策树

```
输入
 │
 ├─ index.md 有对应 playbook？
 │    ├─ 有 → 执行 playbook（检测 → 判定 → 修复 → 验证）
 │    └─ 无 → 下一步
 │
 ├─ 能拿到一手来源？（NVD / GHSA / 官方公告 / 厂商博客）
 │    ├─ 能 → 按 00-TEMPLATE 新建 playbooks/NN-*.md（先 _draft/）
 │    └─ 不能 → 只输出「未确认风险」条目，禁止给修复步骤、禁止写版本号
 │
 ├─ 判定影响面：本机/仓库是否落在受影响区间？
 │    ├─ 不在 → 存证据（命令输出）→ 结束
 │    ├─ 在 + 已可利用（在野利用 / 公开 PoC）→ 紧急通道
 │    └─ 在 + 仅理论 → 常规通道（排期升级 + 验证）
 │
 └─ 产出：绝对路径 + sha256 + 一句话结论
```

## 铁律

1. **一手来源优先**：官方公告 / NVD / GHSA / 厂商博客。二手报道只能标「传闻」，不得当依据。
2. **来源分四级**：一手（官方/NVD/GHSA/厂商）> 三方公告（CERT/CNVD 自撰，影响面可用、修复版本必须厂商复核）> 公开 PoC（只证明 PoC 存在）> 二手（只能标「传闻」）。
3. **禁止编造** CVE 号、版本号、链接。查不到就写「未确认」。
4. 每条结论带来源 URL；每个修复步骤带**能直接跑**的验证命令。
5. 修复必须写**回退方案**，以及「不修的话怎么缓解」。
6. 已可利用漏洞 → 先止血，再升级，再轮换密钥，最后回查日志。顺序不可颠倒。

## 紧急通道（有在野利用 / 公开 PoC）

```bash
# 1) 止血：先断暴露面，不急着改代码
#    网关/反代层拦截，示例（nginx）
#    location /chat/completions { deny all; }
# 2) 升级到 fixed 版本（见具体 playbook）
# 3) 轮换全部可能泄露的凭据：API key / DB 口令 / provider key
# 4) 回查访问日志，找攻击痕迹（时间窗 = 披露日往前 30 天）
grep -iE 'authorization:.*(\x00|%00|union|sleep\(|pg_sleep|information_schema)' access.log
```

## 通用侦测命令（不知道从哪查时先跑这三条）

```bash
# Node/npm
node -v; npm -v; npm ls --depth=0 2>/dev/null | head -40; npm audit --json | head -c 2000
# Go
go version; go list -m all 2>/dev/null | head -40; govulncheck ./...
# Python
python3 -V; pip list --format=json 2>/dev/null | head -c 2000; pip-audit 2>/dev/null | head -40
```

> `govulncheck` / `pip-audit` 不存在时先装：`go install golang.org/x/vuln/cmd/govulncheck@latest`、`pip install pip-audit`。

## 产出规范

| 项 | 规则 |
|---|---|
| 文件位置 | `playbooks/NN-<ecosystem>-<slug>.md`，NN 两位数字 |
| 先用 `_draft/` | 起草放 `playbooks/_draft/`，验收通过才移到 `playbooks/` |
| 交件必须报 | **绝对路径 + sha256**（`sha256sum <file>`） |
| 校验 | `bin/lint-playbooks.sh` 必须 exit 0 |
| 封版 | `bin/seal.sh` 生成 `MANIFEST.sha256` |

## 常用操作

```bash
cd /path/to/vuln-response-skill
bash bin/new-playbook.sh 03 go-cve-xxxx        # 从模板起稿
bash bin/lint-playbooks.sh                     # 结构校验（交件前必跑）
bash bin/seal.sh                               # 生成 sha256 清单
```

## 已知生态与 playbook 索引

见 [index.md](index.md)；一手来源清单见 [sources.md](sources.md)。
