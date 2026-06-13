# whois-workers

[![中文文档](https://img.shields.io/badge/文档-中文版-blue)](README_ZH.md)

A WHOIS / RDAP lookup service running on Cloudflare Workers, built with TypeScript and [Hono](https://hono.dev). A Cloudflare Workers rewrite of [KincaidYang/whois](https://github.com/KincaidYang/whois).

Supports domain, IP address, and ASN queries. Results are returned as structured JSON.

## API

```
GET /domain/:name     # domain name (IDN supported, auto-converted to punycode)
GET /ip/:address      # IPv4, IPv6, or CIDR prefix (e.g. 1.1.1.0/24)
GET /autnum/:asn      # ASN in AS13335 or plain numeric form
GET /health           # health check
```

### Response examples

**Domain**

```jsonc
// GET /domain/example.com
{
  "objectClassName": "domain",
  "ldhName": "example.com",
  "registrar": "RESERVED-Internet Assigned Numbers Authority",
  "status": ["client delete prohibited", "client transfer prohibited"],
  "registrationDate": "1995-08-14T04:00:00Z",
  "expirationDate": "2025-08-13T04:00:00Z",
  "lastChangedDate": "2023-08-14T07:01:44Z",
  "nameservers": ["a.iana-servers.net", "b.iana-servers.net"],
  "secureDNS": { "delegationSigned": false }
}
```

**IP**

```jsonc
// GET /ip/1.1.1.1
{
  "objectClassName": "ip network",
  "handle": "1.1.1.0 - 1.1.1.255",
  "startAddress": "1.1.1.0",
  "endAddress": "1.1.1.255",
  "cidr": "1.1.1.0/24",
  "name": "APNIC-LABS",
  "type": "ASSIGNED PORTABLE",
  "country": "AU",
  "status": ["active"]
}
```

**ASN**

```jsonc
// GET /autnum/13335
{
  "objectClassName": "autnum",
  "handle": "AS13335",
  "name": "CLOUDFLARENET",
  "status": ["active"],
  "registrationDate": "2010-07-14T18:35:57Z"
}
```

## Caching

Query results are cached in Workers KV. Cache status is indicated by the `X-Cache` response header (`HIT` / `MISS`).

| Result | TTL |
|---|---|
| Found | 1 hour (configurable via `CACHE_TTL`) |
| Not found / error | 60 seconds (configurable via `NEGATIVE_CACHE_TTL`) |

## RDAP bootstrap

A Cron Trigger runs daily to fetch the latest IANA RDAP bootstrap data and write it to KV. This keeps the server registry up to date without redeployment.

## Supported WHOIS parsers

Dedicated parsers exist for the following TLDs; all others use a generic EPP-style parser.

`.cn` `.hk` `.tw` `.so` `.ru` `.su` `.sb` `.mo` `.au` `.sg` `.la` `.jp` `.eu` `.kr`
and their IDN equivalents (`.中国` `.香港` `.한국` etc.)

## Deployment

```bash
npm install

# Create a KV namespace and copy the returned id into wrangler.toml
npx wrangler kv namespace create WHOIS_CACHE

# Local development
npm run dev

# Deploy
npm run deploy
```

### Configuration (`wrangler.toml` vars)

| Variable | Default | Description |
|---|---|---|
| `WHOIS_TIMEOUT` | `10000` | WHOIS TCP timeout in milliseconds |
| `CACHE_TTL` | `3600` | Positive cache TTL in seconds |
| `NEGATIVE_CACHE_TTL` | `60` | Negative cache TTL in seconds |

## License

MIT
