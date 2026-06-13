# whois-workers

`github.com/KincaidYang/whois` 的 Cloudflare Workers 重写（TypeScript）。源 Go 服务在 `../whois`。

状态：**调研完成，待实施**。

## 文档

- [docs/feasibility.md](docs/feasibility.md) — 可行性调研：为什么不能直接搬 Go、逐组件可移植性、方案选型。
- [docs/roadmap.md](docs/roadmap.md) — MVP 实施 roadmap（M0–M5）与移植参照表。

## TL;DR

- Workers 不能跑 Go → 用 TypeScript（Hono）从零重写。
- WHOIS 走 `connect()` TCP:43，RDAP 走 `fetch`，缓存用 KV，IANA bootstrap 用 Cron Trigger。
- MVP 范围：domain/ip/asn 单条查询 + KV 缓存 + bootstrap；砍掉 batch/MCP/Prometheus/Redis/鉴权/限流。
