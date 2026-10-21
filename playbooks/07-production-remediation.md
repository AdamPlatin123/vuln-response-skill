---
id: "07"
title: 生产环境漏洞修复 Runbook（六段四门 · 动生产库的安全姿势）
ecosystem: generic
cve: []
affects: "不按软件版本判定；按「事件档位 × 修复状态 × 数据面影响」判定"
fixed: ["按具体漏洞 playbook（01–06、08、09）的 fixed 字段执行"]
severity: "流程型（P0 在野利用 / P1 公网可达 / P2 内网或需认证 / P3 计划变更）"
status: verified
sources: ["https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "https://github.com/advisories", "https://nodejs.org/en/security/"]
updated: 2026-10-21
---

# 生产环境漏洞修复 Runbook

> 面向：有变更制度、有值班、有 CMDB/CD 的团队。
> 目标：把「发现 → 修完 → 能被审计」压成一条可回退的路。
> 本文不判断漏洞真伪——判定输入来自 playbook 01–06、08、09 的已核实条目。

## 适用版本区间

不按软件版本判定，按事件档位。踩错档位，后面每一步都错。

| 档位 | 判据 | 典型动作 |
|---|---|---|
| P0 | 正在被主动利用 / 数据正被加密或外泄 / 公网无补丁可 RCE | 保全 → 围堵 → 隔离，可能停服 |
| P1 | 公网可达 + 未认证，无在野利用证据 | 摘入口 / WAF 拒绝 / 撤凭据，**不停服** |
| P2 | 仅内网 / 需认证 / 功能未启用 | 变更窗口 + 灰度 |
| P3 | 有补丁的计划内升级 | 常规变更流程 |

**角色与授权（先定人，再动手）**

| 角色 | 职责 | 硬要求 |
|---|---|---|
| IC（事件指挥） | 唯一决策人，宣布门禁通过与解除 | 姓名 + 值班电话 |
| 执行人 | 按单操作生产 | 变更单 + 双人复核 |
| 复核人 | 逐条勾 checklist，只看证据 | 不与执行人同人 |
| DBA | 数据面变更唯一执行者 | 备份可恢复性已验 |
| SRE | 灰度、回退、监控 | 回退脚本已就位 |
| 安全 | 影响面判定、证据保全、入侵排查 | 证据清单 |

**六个阶段 × 四个门**

```
G0 授权 ─ P1 取证 ─ G1 ─ P2 判定+围堵 ─ G2 ─ P3 修复 ─ G3 ─ P4 数据面 ─ P5 验证 ─ G4 ─ P6 恢复关闭
```

| 门 | 通过条件（不满足不许进下一段） |
|---|---|
| G0 | IC 已指定；影响面初判；变更单编号存在 |
| G1 | 证据已落盘并异地留档（内存/日志/连接/进程/制品 digest） |
| G2 | 受影响清单 + 暴露路径 + 数据可达性已定；围堵手段已选 |
| G3 | 新制品 digest 已核；回退点（旧制品 + 已验证备份 + 开关）可用 |
| G4 | 验证 8 项全绿；入侵排查无残留；监控窗口已排 |

**任一门不过，只能原地加强围堵，不许「先修了再说」。**

## 检测

### P1 取证（关任何东西之前，G1）

```bash
date -Ins; hostname; uname -r; head -3 /etc/os-release
ps -eo pid,ppid,lstart,user,args --sort=start_time
ss -tunap
for p in $(pgrep -f 'node|java|python|gunicorn|vllm|litellm'); do
  echo "== $p"; readlink /proc/$p/exe; ls -l /proc/$p/cwd
  tr '\0' '\n' < /proc/$p/environ | sed 's/=.*/=<redacted>/'
done
docker ps --no-trunc --format '{{.Names}} {{.Image}} {{.CreatedAt}}'
docker image inspect <img> --format '{{json .RepoDigests}}'
journalctl --since '-6h' -o short-iso > /evidence/journal.log
```

| 保全项 | 为什么 | 落哪 |
|---|---|---|
| 内存（进程环境、连接、内存马迹象） | **关机即销毁** | `/evidence/` + 异地对象存储 |
| 日志（应用/网关/DB 审计） | 停服后不再写 | 先镜像，再清理 |
| 制品 digest + 构建元数据 | 证明「跑的是哪个二进制」 | CMDB 对账 |
| DB 审计（登录、DDL、大批量导出） | 判断是否已外泄 | DBA 只读导出 |

> 反模式：先 `systemctl stop` 再找日志——连接表、内存马、TLS 会话全没了，事后无法定性「是否已泄露」。
> **内存不抓，就无法回答「凭据是否已外泄」**：进程环境里的 token、`ss` 连接表、内存中的恶意代码都不在文件系统里，`docker commit` 只保存文件系统。

### 定级所需三条证据

```bash
# 1) 受影响（用具体 playbook 的检测段，不在这里猜）
node -v; go version; pip show litellm | grep -i ^version

# 2) 是否已被利用：KEV 是「已被利用」的一手证据
CVE_ID="${1:?missing CVE id}"
curl -s https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json \
  | jq -r --arg id "$CVE_ID" '.vulnerabilities[] | select(.cveID==$id) | "\(.cveID)\t\(.dateAdded)\t\(.dueDate)"'

# 3) 暴露面：从攻击者视角实测
curl -s -m 5 -o /dev/null -w 'public=%{http_code}\n' https://prod.example.com/<受影响路径>
ss -lntp | grep -E ':(4000|8000|11434)\b'
```

## 影响判定

### 停服决策矩阵（回答「要不要先关服务」）

| 情形 | 停服？ | 先做什么 |
|---|---|---|
| 正被主动利用、无补偿控制、15 min 内围不住 | **是**（隔离/断网） | 先内存 + 日志保全 |
| 数据正在被加密 / 外泄 | **是** | 保全 + 断出站 + 吊销可达凭据 |
| 公网暴露 + 无补丁 + 可 RCE | **是**（至少摘入口 / WAF 拒绝） | 保全 + 摘流量 |
| 有补丁的计划内升级 | **否** | 蓝绿 / 金丝雀替换 |
| 仅已认证可达、漏洞在内部服务 | **否** | 撤权限 / 网关拒绝 / 关功能开关 |
| 停服会 failover 到同版本副本 | **否** | 先确认副本版本，再修 |
| 停服会断掉唯一日志或监控源 | **否** | 先镜像日志，再考虑停 |
| 值班只想「先关了再说」 | **否** | 这是流程缺陷：走紧急变更 + 摘流量 |

**降可达性 ≠ 停服**：摘入口、WAF 拒规则、撤凭据、断出站——成本低、可逆、不销毁证据。停服是最后手段，且会 failover 到同版本副本时，只是把事故复制一份。

### G2 判定清单（四问，答不全不许升级）

1. 哪些实例/版本真受影响（清单，不是估计）；
2. 攻击者从哪条路径进来（公网/内网/需认证）；
3. 这个进程能碰到什么数据面（DB 账号权限、对象存储、KMS、下游凭据）；
4. 围堵选哪种：摘入口 / WAF / 撤权限 / 断出站 / 关开关。

## 修复

### P3 修复：先分清四种状态，别混

| 动作 | 能证明 | **不能**证明 |
|---|---|---|
| 装包 | 磁盘上的制品变了 | running 进程变了 |
| 重启 | 进程加载了新制品 | 镜像/构建产物是新的 |
| 重建镜像 | 供应链干净、可复现 | 已部署 |
| 重新部署 | 运行态换了 | 数据面已收敛 |

- Node（01）：升级运行时**不是** `npm update`；SEA/snapshot 产物必须重建。
- Go（04）：必须用新工具链**重新编译**；`go version -m ./bin` 看线上二进制构建信息。
- LiteLLM（02）：`1.83.9` 不是总修复线，按 GHSA 分支核；多租户网关按 virtual key 灰度。
- 供应链（03）：被投毒环境是**重建**，不是删包；`.pth` / 启动脚本要在可信环境只读盘点。
- vLLM/Ollama（05）：按制品牌本；模型缓存目录与权限边界一起核。

```bash
# 灰度（不是一把梭）
kubectl set image deploy/<app> <container>=<image>@sha256:<digest>
kubectl rollout status deploy/<app> --timeout=300s
kubectl rollout undo deploy/<app>        # 回退触发器命中时执行
```

### P4 数据面专项（「动生产库」就是这段）

**总原则：先加后减（expand → migrate → contract），每一步都能单独回退。G3 不过不许动数据面。**

#### 4.1 密钥 / KMS 轮换

```text
1. KMS 生成新版本（旧版本保持 enabled）
2. 新写入统一切新版本
3. 双读窗口：读路径同时支持新旧版本
4. 后台批量 re-encrypt：1000 行/批，记断点，逐批校验
5. 引用计数 = 0 才禁用旧版本（禁用，不是删除）
6. 观察 7 天 → 销毁旧版本，留审计
```

- 出站凭据（调用别人）：**先建新 → 全量部署消费方 → 再吊销旧**，必须有 overlap。
- 入站凭据（别人调你）：**先支持新 → 通知调用方 → 最后禁旧**。
- 加密盐跨用途复用：轮换会动已存数据，**不许直接覆盖**，必须双读 + 回填。

#### 4.2 Schema 变更

```text
加列/加表 → 回填（幂等、可断点）→ 双写 → 切读 → 保留 N 天 → 删旧
```

禁止：一次 `ALTER` + 立刻删旧列；无逻辑备份验证就做物理备份。

```bash
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 <<'SQL'
SET lock_timeout = '3s';
SET statement_timeout = '30s';
BEGIN;
ALTER TABLE t ADD COLUMN c text;          -- 只做可空加法
COMMIT;
SQL

# 回填：按主键区间分批，断点写进 checkpoint 表，每批校验行数
for lo in $(seq 1 1000 100000); do
  hi=$((lo + 999))
  psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -c "
    WITH up AS (UPDATE t SET c = f(...) WHERE id BETWEEN $lo AND $hi AND c IS NULL RETURNING 1)
    INSERT INTO _backfill_ckpt(tbl, lo, hi, rows, at) SELECT 't', $lo, $hi, count(*), now() FROM up;"
  # 校验：本批应更新的行数 vs 实际更新行数，不一致立即停
done
```

#### 4.3 备份与回退点

- **没做过 restore 演练的备份不算回退点**（最常被当成「我有备份」的假安全感）。
- 变更前记录：`pg_dump --schema-only`、行数基线、关键表 checksum。
- 回退触发器写成**数字**，不靠现场判断：

| 指标 | 阈值 | 动作 |
|---|---|---|
| 5xx 错误率 | > 5% 持续 5 min | 回滚版本 |
| P99 延迟 | > 基线 2 倍持续 5 min | 回滚版本 |
| 数据校验不一致 | > 0 行 | 停止回填 + 不切读 |
| 旧 key 仍有成功调用 | > 0 次 | 暂停吊销，查漏 |
| 告警未在 15 min 内消除 | 任意 | 升级到 IC |

```bash
# 演练：备份能不能恢复（在独立实例做，不在生产）
createdb restore_drill && pg_restore -d restore_drill /secure/backup/pre-change.dump
psql -d restore_drill -c 'SELECT count(*) FROM t;'   # 与基线对比
```

#### 4.4 权限与留痕

- DBA 双人复核；生产 SQL 先在只读副本演练。
- 每条生产语句记录：谁、何时、变更单号、影响行数、耗时。
- 禁止共享账号执行应急变更。

## 验证

G4 八项，缺一项不许说「已修复」：

| # | 验证项 | 命令 / 证据 | 通过标准 |
|---|---|---|---|
| 1 | 制品正确 | `sha256sum <artifact>` 对比官方发布页；`docker image inspect --format '{{json .RepoDigests}}'` | 与官方 digest 一致 |
| 2 | 运行态正确 | `readlink /proc/<pid>/exe`；`ps -o lstart=` | 指向新路径且启动时间晚于发版 |
| 3 | 功能回归 | 核心链路冒烟 + 业务方签字 | 成功率回到基线 ±10% |
| 4 | 边界拒绝 | 厂商 PoC 的**只读/无害**变体，在测试实例跑 | 返回 401/403/400，无 200 |
| 5 | 凭据边界 | 旧 key 调一次 | 401/403 |
| 6 | 数据一致性 | 行数 + checksum + 抽样解密 | 与基线完全一致 |
| 7 | 入侵排查 | 异常进程/定时任务/公钥/异常出站 DNS | 无残留，或已单独立案 |
| 8 | 回退可用 | 预发演练一次回退 | 记录实际耗时，且 < 业务可接受窗口 |

```bash
# 3) 功能回归（示例：LLM 网关）
curl -s -o /dev/null -w 'health=%{http_code}\n' http://127.0.0.1:4000/health/liveliness
# 4) 边界拒绝（测试实例，别打生产）
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:4000/chat/completions \
  -H "Authorization: Bearer x' OR '1'='1" -H 'Content-Type: application/json' -d '{}'
# 7) 入侵排查
ps -eo pid,lstart,args --sort=start_time | tail -20
ls -la /etc/cron* /var/spool/cron 2>/dev/null; crontab -l 2>/dev/null
```

**通过标准**：8 项全绿 + 监控窗口已开 + IC 签字，才允许对外说「已修复」。

## 回退

```bash
# 流量层
kubectl patch ingress <ing> --type=json \
  -p='[{"op":"remove","path":"/metadata/annotations/nginx.ingress.kubernetes.io~1server-snippet"}]'
# 版本层
kubectl rollout undo deploy/<app> && kubectl rollout status deploy/<app>
# 数据层（仅当按 §4.3 有已演练的回退点）
pg_restore --clean --if-exists -d "$DATABASE_URL" /secure/<incident>/pre-change.dump
```

**回退后风险**：回退版本 = 重新暴露漏洞；回退数据 = 可能丢修复后的写入。回退必须同时满足：入口仍围堵、密钥已轮换、再升级时间点已定。**不允许「回退即收工」**。

## P6 恢复与关闭

- 解除围堵要 **IC 签字**；解除后开 24–72 h 监控窗口，指标与门禁 G4 同一套。
- 复盘只写三件事：根因、**为什么没更早发现**、流程里哪一步卡住。
- 对外口径：**制品 + 运行态 + 边界 + 凭据**四项齐了才能说「已修复」。

## 反模式（每条都真实发生过）

1. 先停服再取证 → 证据销毁。
2. 只升级依赖，不换运行时 → `npm audit` 全绿但进程里还是旧 Node。
3. 只改配置当修复（关日志/关功能）→ 漏洞还在，只是不触发。
4. 无 restore 演练的备份当回退点。
5. 单人夜里直改生产库，事后补单。
6. 全量一次推，无灰度、无回退开关。
7. 用「打了补丁」当「已排查入侵」。
8. 把 KEV dueDate 当自己的法定义务（EPSS 是概率，不是攻击证据）。

## 接口

| 段 | 引用 |
|---|---|
| 判定输入 | 01 Node.js / 02 LiteLLM / 03 npm 供应链 / 04 Go / 05 Python-LLM 基建 |
| 轮换技术段 | `06-credential-rotation.md`（通用轮换流程；本文 §4.1 只保留数据面视角） |
| 新增生态 | 08 PHP / 09 PKI-CA 的修复动作落在 P3，不重复写流程 |

## 来源

| 类型 | URL |
|---|---|
| 一手（CISA KEV，判定「已被利用」的权威表） | https://www.cisa.gov/known-exploited-vulnerabilities-catalog |
| 一手（GitHub Advisory，定版与 CVSS） | https://github.com/advisories |
| 一手（Node.js 安全发布节奏，用于定升级窗口） | https://nodejs.org/en/security/ |
