---
id: "06"
title: 凭据与密钥轮换（先加后减 · 双读窗口 · 数字触发器）
ecosystem: generic
cve: []
affects: "不按软件版本判定；按「凭据类型 × 是否可能已泄露」判定"
fixed: ["不适用（流程件）：目标状态 = 旧凭据全部禁用且引用计数为 0"]
severity: "流程型（P0 已泄露 / P1 可能泄露 / P2 例行轮换）"
status: verified
sources: ["https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html", "https://www.postgresql.org/docs/current/sql-alterrole.html"]
updated: 2026-10-21
---

# 凭据与密钥轮换

**一句话**：轮换不是「换一个值」，是**先加后减**：新凭据上线并全量生效 → 双读/双写窗口 → 旧凭据引用计数归零 → **禁用**（不是删除）→ 观察后销毁。直接覆盖旧值 = 把一次可回退操作变成不可回退。

## 适用版本区间

不按版本判定，按凭据类型 + 泄露判定档位。

| 档位 | 判据 | 时间要求 |
|---|---|---|
| P0 已泄露 | 凭据出现在：被投毒包/日志/公开仓库/攻击者可达的 DB/内存转储 | 立即，先冻结再换 |
| P1 可能泄露 | 受影响进程能读到该凭据，且进程曾暴露在不可信网络 | 24h 内 |
| P2 例行 | 到期轮换、人员离职、合规要求 | 按制度 |

| 凭据类型 | 典型 | 轮换难点 |
|---|---|---|
| 加密密钥（KMS / 数据密钥） | 云 KMS、Vault transit | 已加密数据要重加密，**双读** |
| 数据库口令 | Postgres / MySQL 应用账号 | 连接池、长连接、多实例 |
| API key / token | provider key、internal token | 消费方分散，需 overlap |
| 签名密钥 | JWT / cookie 签名 / mTLS | 旧 token 会立即失效，需双密钥验签 |
| CI/CD secret | GitHub Actions / GitLab CI | 轮换前必须冻结流水线，否则新值再泄露 |
| TLS 证书 | 服务端证书、CA | 有有效期，需提前排期 |

## 检测

```bash
# 1) 盘点：到底有哪些凭据在用（先列清单，再动手）
# 应用侧（值一律脱敏，只记名字与指纹）
tr '\0' '\n' < /proc/<pid>/environ | grep -iE 'key|token|secret|password|dsn|url' | sed 's/=.*/=<redacted>/'

# k8s secret（只看名字与创建时间，不解码内容）
kubectl get secret -A -o custom-columns='NS:.metadata.namespace,NAME:.metadata.name,AGE:.metadata.creationTimestamp'

# 云 KMS 密钥版本（AWS 示例；其他云按各自 CLI 语法）
aws kms list-keys --query 'Keys[].KeyId' --output text
aws kms list-key-policies --key-id <KEY_ID> >/dev/null && echo "可读策略"

# 2) 数据库账号与权限边界
psql "$DATABASE_URL" -c '\du'
psql "$DATABASE_URL" -c "SELECT pid, usename, application_name, state, backend_start FROM pg_stat_activity ORDER BY backend_start LIMIT 30;"

# 3) 回归检查：仓库/镜像里有没有明文
gitleaks detect --no-banner -v 2>/dev/null || trufflehog filesystem . --only-verified 2>/dev/null

# 4) CI 是否可被旧凭据触发（轮换前必须能冻结）
gh workflow list 2>/dev/null || gitlab-ci-lint < .gitlab-ci.yml
```

**命中判据**：P0 = 凭据明文出现在日志/仓库/被投毒包的窃取目标清单里，或 DB 可被注入读取；P1 = 进程可读 + 曾暴露不可信网络；P2 = 其余。

## 影响判定

| 判断 | 结论 |
|---|---|
| 攻击者能读 DB 表（含加密列） | 该列对应**数据密钥**泄漏 → 按 P0 重加密 |
| 攻击者能读进程环境 | 该进程所有凭据按 P0 处理，**一次全换**，不要分批猜 |
| 凭据在第三方侧可自助查看（如 DB 明文密码） | 视为已泄露，不等证据 |
| 旧凭据可被重放（无 expiry / 无绑定） | P0；换新时同时加上过期与绑定 |
| 只是「版本较老」 | P2 例行，不必按事故处理 |

**误报排除**

- 只读账号被读走 → 仍需轮换，但爆炸半径是「数据外泄」而非「可写入」；
- 文档里示例 key（如 `AKIA...EXAMPLE`）不是真泄露；
- TLS 证书到期 ≠ 被攻破，按到期换新即可。

## 修复

### 4.1 统一顺序（所有类型都适用）

```text
0. 冻结：冻结 CI/CD、暂停自动部署（防新值再泄露）
1. 留档：旧凭据元数据 + 引用清单（不保存明文）
2. 建新：新版本/新 key 生成，旧版本保持 enabled
3. 切写：新写入切新版本；消费方全量部署
4. 双读：读路径同时支持新旧（N 个版本）
5. 回填/重加密：批量、可断点、逐批校验
6. 归零：引用计数 = 0 → 禁用旧版本
7. 观察：7 天；期间保留旧版本可快速 re-enable
8. 销毁：删除旧版本，留审计记录
9. 解冻：恢复 CI/CD，补一次全量扫描
```

### 4.2 加密密钥（KMS / 数据密钥）

```bash
# AWS KMS 示例：新版本由轮换生成，旧版本保持 enabled
aws kms enable-key-rotation --key-id <KEY_ID>
aws kms list-key-rotations --key-id <KEY_ID>
# 双读窗口内：应用同时能解旧/新版本；回填完成后才禁用旧版本
aws kms disable-key --key-id <OLD_KEY_ID>      # 禁用，不是 schedule-delete
```

回填（应用层，按批）：

```bash
# 1000 行/批，断点入表，批内校验成功数与预期数
for lo in $(seq 1 1000 200000); do
  hi=$((lo+999))
  psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -c "
    WITH up AS (UPDATE t SET secret = reencrypt(secret) WHERE id BETWEEN $lo AND $hi AND key_version < 2 RETURNING 1),
    ck AS (INSERT INTO _reencrypt_ckpt(lo,hi,rows,at) SELECT $lo,$hi,count(*),now() FROM up)
    SELECT count(*) FROM up;"
done
```

### 4.3 数据库口令

```bash
# 1) 建新口令（应用账号），旧口令仍有效一段时间
psql "$DATABASE_URL" -c "ALTER ROLE app_user PASSWORD '<new-from-secret-manager>';"
# 2) 滚动更新应用（连接池会重连，注意 max_connections 与重连风暴）
kubectl rollout restart deploy/<app>
kubectl rollout status deploy/<app> --timeout=600s
# 3) 确认无旧连接
psql "$DATABASE_URL" -c "SELECT count(*) FROM pg_stat_activity WHERE usename='app_user';"
# 4) 旧口令不再需要时：撤销（Postgres 无「旧口令并存」，靠连接排空 + 二次改密）
```

> Postgres 同一角色只能有一个口令：所谓「双口令」要用**两个角色**实现（`app_user_v1` / `app_user_v2` + 切换授权），不要试图原地覆盖。

### 4.4 API key / token（出站与入站方向不同）

```bash
# 出站（你调用别人）：先建新 → 全量部署消费方 → 确认新 key 有调用 → 再吊销旧
# 入站（别人调你）：先支持新 → 通知调用方 → overlap 期 → 最后禁旧
# 两者都必须有 overlap 窗口；没有 overlap 的切换 = 线上故障
```

### 4.5 CI/CD secret

```bash
# 冻结 → 换 → 验证 → 解冻
gh secret set <NAME> --body "<new>"        # GitHub
gh workflow list                           # 确认流水线仍可用
# 解冻后立刻跑一次全量 secret 扫描，确认没在构建日志里回显
```

### 4.6 验证「真的换掉了」（按引用计数）

```bash
# 旧值引用计数（DB 列 / 配置项 / 文档）
grep -rn '<old-key-fingerprint>' /etc /srv /opt 2>/dev/null | wc -l
psql "$DATABASE_URL" -c "SELECT count(*) FROM t WHERE key_version < 2;"
```

## 验证

```bash
# 1) 新凭据可用
psql "$DATABASE_URL" -c 'SELECT 1;'
curl -s -o /dev/null -w 'new_key=%{http_code}\n' https://api.example.com/health \
  -H "Authorization: Bearer $NEW_KEY"

# 2) 旧凭据必须失败（这是轮换的唯一硬证据）
curl -s -o /dev/null -w 'old_key=%{http_code}\n' https://api.example.com/health \
  -H "Authorization: Bearer $OLD_KEY"        # 期望 401/403
psql "postgres://app_user_v1:<old>@db/appdb" -c 'SELECT 1;'   # 期望认证失败

# 3) 引用计数归零
psql "$DATABASE_URL" -c "SELECT count(*) FROM t WHERE key_version < 2;"    # 期望 0

# 4) 解密抽样（重加密后仍可读）
psql "$DATABASE_URL" -c "SELECT count(*) FROM t WHERE secret IS NULL;"     # 期望 0

# 5) 审计留痕
#    每条：谁、何时、变更单号、轮换了哪个版本、禁用/销毁时间
```

**通过标准**

1. 新凭据全量可用，业务 SLI 回到基线；
2. **旧凭据调用全部失败**（逐条实测，不是「应该失效了」）；
3. 加密列 `key_version` 全部 ≥ 新版本，引用计数 = 0；
4. 旧版本处于 disabled（未删除），可 re-enable；
5. 7 天观察期内无「旧凭据调用成功」告警；
6. 审计记录完整，可回答「哪个 key 在何时被谁换掉」。

## 回退

```bash
# 加密密钥：re-enable 旧版本（这就是「禁用不删除」的价值）
aws kms enable-key --key-id <OLD_KEY_ID>

# 应用凭据：回退到旧值（仅限旧值尚未销毁）
kubectl set env deploy/<app> API_KEY=<old> --record

# CI：恢复旧 secret（仅限未解冻前）
gh secret set <NAME> --body "<old>"
```

**回退后风险**：回退到旧凭据 = 重新暴露已泄露的凭据；回退到旧密钥版本 = 新写入的数据用旧版本加密，后续还要再回填一次。因此回退必须同时：确认泄露面已关闭（攻击者不再可达）、回退窗口 ≤ 24h、并在窗口内重新排期轮换。

## 来源

| 类型 | URL |
|---|---|
| 一手（CISA KEV，判定「已被利用」） | https://www.cisa.gov/known-exploited-vulnerabilities-catalog |
| 一手（AWS KMS 密钥轮换文档，双版本语义） | https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html |
| 一手（PostgreSQL `ALTER ROLE`，单角色单口令的事实） | https://www.postgresql.org/docs/current/sql-alterrole.html |
