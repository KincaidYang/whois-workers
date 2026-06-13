# whois-workers

基于 Cloudflare Workers 的 WHOIS / RDAP 查询服务，使用 TypeScript + Hono 构建。

支持域名、IP 地址、ASN 三类查询，响应格式与 [KincaidYang/whois](https://github.com/KincaidYang/whois) 保持一致。

## 功能

- **域名查询**：优先走 RDAP，回退 WHOIS TCP:43（`cloudflare:sockets`）
- **IP / CIDR 查询**：RDAP，覆盖 IPv4 / IPv6
- **ASN 查询**：RDAP
- **多 TLD 解析器**：CN / HK / TW / SO / RU / SB / MO / AU / SG / LA / JP / EU / KR，其余走通用解析器
- **KV 缓存**：正缓存 TTL 1 小时，负缓存 TTL 60 秒，命中时响应头携带 `X-Cache: HIT`
- **IANA Bootstrap**：Cron Trigger 每日拉取 IANA RDAP 数据写入 KV，查询时自动覆盖内置映射表

## 接口

```
GET /domain/:name     # 域名，支持 IDN（自动转 punycode）
GET /ip/:address      # IPv4 / IPv6 / CIDR（如 1.1.1.0/24）
GET /autnum/:asn      # ASN（AS13335 / 13335）
GET /health           # 健康检查
```

## 部署

```bash
npm install

# 创建 KV namespace
npx wrangler kv namespace create WHOIS_CACHE
# 将返回的 id 填入 wrangler.toml [[kv_namespaces]]

# 本地开发
npm run dev

# 部署
npm run deploy
```
