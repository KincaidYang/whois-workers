# whois-workers

`github.com/KincaidYang/whois` 的 Cloudflare Workers 重写（TypeScript）。

## TL;DR

- Workers 不能跑 Go → 用 TypeScript（Hono）从零重写。
- WHOIS 走 `connect()` TCP:43，RDAP 走 `fetch`，缓存用 KV，IANA bootstrap 用 Cron Trigger。
- MVP 范围：domain/ip/asn 单条查询 + KV 缓存 + bootstrap；砍掉 batch/MCP/Prometheus/Redis/鉴权/限流。
