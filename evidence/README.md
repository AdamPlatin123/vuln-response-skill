# evidence/ · 一手核实留痕

存放**可直接复核**的原始 API 响应，避免「结论对但不可查」。

| 目录 | 内容 | 抓取时间 |
|---|---|---|
| `osv-2026-10-21/` | OSV API 原始 JSON：Go 4 条 + npm tensorlake 1 条 + LiteLLM `GHSA-3cv6`（9 分支） | 2026-10-21 |
| `spki-emudhra-2026-10-21.md` | eMudhra 事件 3 根 + 8 中间 CA 的 SPKI SHA-256 检测锚点（源 = oss-security 一手） | 2026-10-21 |
| `cvelistV5-2026-10-21/` | CVE 官方记录原始 JSON（`CVE-2026-103663`，含 `assignerShortName`、条件 CVSS、SSVC） | 2026-10-21 |

## 复核方式

```bash
cd /path/to/vuln-response-skill

# 逐条重抓并与本地留痕比对（URL 见 sources.md 的 S100–S103、S205）
curl -s "https://api.osv.dev/v1/vulns/GO-2026-6610" | python3 -m json.tool | head -20
sha256sum evidence/osv-2026-10-21/*.json
```

## 已复核结论

| 文件 | aliases | fixed（与 playbook 一致） |
|---|---|---|
| `GO-2026-6610.json` | CVE-2026-78660 | stdlib `1.26.9` / `1.27.2`；`x/net 0.60.0` |
| `GO-2026-6611.json` | CVE-2026-78669 | 同上 |
| `GO-2026-6809.json` | CVE-2026-111943 | `1.26.10` / `1.27.3` |
| `GO-2026-6668.json` | CVE-2026-41510 | `coraza/v3 3.8.1` |
| `MAL-2026-17650.json` | GHSA-rqxj-g25x-4v9v | `tensorlake@0.5.144`（恶意版本，无安全版本） |

> 这 5 条 OSV 记录 `severity` 均为 `null`：**没有 CVSS 可引用**，playbook 里的「高危/严重」是定性表述。

## CVE 记录抽验（`cvelistV5-2026-10-21/CVE-2026-103663.json`）

```bash
curl -s https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/103xxx/CVE-2026-103663.json \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["cveMetadata"]["assignerShortName"])'
# → CERT-PL
```

| 字段 | 实测值 |
|---|---|
| `assignerShortName` | `CERT-PL`（orgId `4bb8329e-dd38-46c1-aafb-9bf32bcb93c6`） |
| `affected` | Ollama `>=0.34.2 <0.35.0`（semver） |
| CVSS 4.0 场景 1（无 `/usr/lib/ollama` 写权限） | **6.9** |
| CVSS 4.0 场景 2（有写权限，多数 Docker 默认 root） | **9.4** |
| CISA ADP SSVC | `Exploitation: none`，`Automatable: no` |

> `GHSA-3cv6-jpf6-8222.json`（sha256 `95e4ca63…`）用于纠正「CVE-2026-84377 只有双分支」的说法：OSV 原文 9 条 ranges。
