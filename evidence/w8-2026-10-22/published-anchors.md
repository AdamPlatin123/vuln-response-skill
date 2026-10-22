# W8 取证：近 3 天声明的日期锚点（2026-10-22 实抓）

> 文件名刻意不用 `README.md`：`bin/sync-dist.sh` 全局排除该文件名，否则本页不会进发布包。

用途：为 `SKILL.md` / `index.md` / `README.md` 的「近 3 天已确认漏洞」声明提供**可复核的 `published` 原值**。
抓取方式：`https://api.osv.dev/v1/vulns/<ID>`（OSV 聚合 RustSec / GitHub Advisory），HTTP 200。

| 条目 | `published`（实测） | 窗口判定（≥2026-10-20T00:00Z） |
|---|---|---|
| `RUSTSEC-2026-0381.json` | `2026-10-19T12:00:00Z` | **OUT**（事件日 10-17） |
| `RUSTSEC-2026-0382.json` | `2026-10-20T12:00:00Z` | IN |
| `RUSTSEC-2026-0383.json` | `2026-10-19T12:00:00Z` | **OUT**（事件日 10-17） |
| `GHSA-6q48-6c7w-9gw2.json`（certifi） | `2026-10-20T19:35:05Z` | IN |
| `GHSA-hq85-5cpj-mr62.json`（uv） | `2026-10-20T19:37:52Z` | IN |

> `12:00:00Z` 是整点值，非笔误——RustSec 的 `published` 就是该形态，已在 JSON 里逐字核对。
> 0381 / 0383 虽 10-19 发布，但同属 eMudhra 事件（事件日 10-17），**不删**，留在 `09`，不计入 26。
