import { Hono, Context } from "hono";
import { Env } from "./types";
import { isDomain, isIP, isCIDR, isASN, toASCII, extractTLDs, asnNumber } from "./validate";
import { queryWhois } from "./whois";
import { rdapQueryDomain, rdapQueryIP, rdapQueryASN } from "./rdap";
import { cacheGet, cacheSet } from "./cache";
import { handleScheduled } from "./bootstrap";
import { lookupWhoisServer, lookupRdapServer, lookupIPRdapServer, lookupASNRdapServer } from "./lookup";
import { parseWhoisResponse, parseRDAPDomain, parseRDAPIP, parseRDAPASN } from "./parsers/index";
import { DomainNotFoundError, ResourceNotFoundError, QueryDeniedError } from "./errors";

type AppEnv = { Bindings: Env };
const app = new Hono<AppEnv>();

const CACHE_TTL_DEFAULT = 3600;
const NEG_TTL_DEFAULT = 60;

function getCacheTTL(env: Env): number {
  return parseInt(env.CACHE_TTL, 10) || CACHE_TTL_DEFAULT;
}

function getNegTTL(env: Env): number {
  return parseInt(env.NEGATIVE_CACHE_TTL, 10) || NEG_TTL_DEFAULT;
}

function getTimeout(env: Env): number {
  return parseInt(env.WHOIS_TIMEOUT, 10) || 10000;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type C = Context<AppEnv, any>;

function errResponse(c: C, status: number, msg: string) {
  return c.json({ error: msg }, status as 400 | 404 | 403 | 429 | 500 | 502 | 503);
}

// CORS middleware
app.use("*", async (c, next) => {
  c.res.headers.set("Access-Control-Allow-Origin", "*");
  c.res.headers.set("Access-Control-Expose-Headers", "X-Cache");
  if (c.req.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
        "Access-Control-Max-Age": "86400",
      },
    });
  }
  return next();
});

async function handleDomain(c: C, input: string) {
  const ascii = toASCII(input);
  if (!isDomain(ascii || input)) return errResponse(c, 400, "Invalid domain name");

  const domain = ascii || input;
  const cacheKey = `domain:${domain}`;
  const env = c.env;

  const cached = await cacheGet(cacheKey, env.WHOIS_CACHE);
  if (cached) {
    c.header("X-Cache", "HIT");
    if (cached.negative) return errResponse(c, 404, "Domain not found");
    return c.json(cached.data);
  }

  const tlds = extractTLDs(domain);
  let result = null;

  for (const tld of tlds) {
    const rdapServer = await lookupRdapServer(tld, env.WHOIS_CACHE);
    if (rdapServer) {
      try {
        const resp = await rdapQueryDomain(domain, rdapServer);
        result = parseRDAPDomain(resp);
        break;
      } catch (err) {
        if (err instanceof ResourceNotFoundError) {
          await cacheSet(cacheKey, { data: null, negative: true }, env.WHOIS_CACHE, getNegTTL(env));
          return errResponse(c, 404, "Domain not found");
        }
        if (err instanceof QueryDeniedError) return errResponse(c, 403, "Registry denied the query");
      }
    }
  }

  if (!result) {
    for (const tld of tlds) {
      const whoisServer = await lookupWhoisServer(tld, env.WHOIS_CACHE);
      if (!whoisServer) continue;
      try {
        const raw = await queryWhois(whoisServer, domain, getTimeout(env));
        result = parseWhoisResponse(raw, domain, tld);
        break;
      } catch (err) {
        if (err instanceof DomainNotFoundError) {
          await cacheSet(cacheKey, { data: null, negative: true }, env.WHOIS_CACHE, getNegTTL(env));
          return errResponse(c, 404, "Domain not found");
        }
        const msg = err instanceof Error ? err.message : String(err);
        return errResponse(c, 502, `WHOIS query failed: ${msg}`);
      }
    }
  }

  if (!result) return errResponse(c, 404, "No WHOIS or RDAP server found for this domain");

  await cacheSet(cacheKey, { data: result }, env.WHOIS_CACHE, getCacheTTL(env));
  return c.json(result);
}

async function handleIP(c: C, resource: string) {
  if (!isIP(resource) && !isCIDR(resource)) {
    return errResponse(c, 400, "Invalid IP address or CIDR prefix");
  }

  const cacheKey = `ip:${resource}`;
  const env = c.env;

  const cached = await cacheGet(cacheKey, env.WHOIS_CACHE);
  if (cached) {
    c.header("X-Cache", "HIT");
    if (cached.negative) return errResponse(c, 404, "IP not found");
    return c.json(cached.data);
  }

  const lookupIP = resource.includes("/") ? resource.split("/")[0] : resource;
  const rdapServer = await lookupIPRdapServer(lookupIP, env.WHOIS_CACHE);
  if (!rdapServer) return errResponse(c, 404, "No RDAP server found for this IP");

  try {
    const resp = await rdapQueryIP(resource, rdapServer);
    const info = parseRDAPIP(resp);
    await cacheSet(cacheKey, { data: info }, env.WHOIS_CACHE, getCacheTTL(env));
    return c.json(info);
  } catch (err) {
    if (err instanceof ResourceNotFoundError) {
      await cacheSet(cacheKey, { data: null, negative: true }, env.WHOIS_CACHE, getNegTTL(env));
      return errResponse(c, 404, "IP not found");
    }
    if (err instanceof QueryDeniedError) return errResponse(c, 403, "Registry denied the query");
    const msg = err instanceof Error ? err.message : String(err);
    return errResponse(c, 502, `RDAP query failed: ${msg}`);
  }
}

async function handleASN(c: C, resource: string) {
  const upper = resource.toUpperCase();
  if (!isASN(upper)) return errResponse(c, 400, "Invalid ASN");

  const asn = asnNumber(upper);
  const cacheKey = `asn:${asn}`;
  const env = c.env;

  const cached = await cacheGet(cacheKey, env.WHOIS_CACHE);
  if (cached) {
    c.header("X-Cache", "HIT");
    if (cached.negative) return errResponse(c, 404, "ASN not found");
    return c.json(cached.data);
  }

  const rdapServer = await lookupASNRdapServer(asn, env.WHOIS_CACHE);
  if (!rdapServer) return errResponse(c, 404, "No RDAP server found for this ASN");

  try {
    const resp = await rdapQueryASN(String(asn), rdapServer);
    const info = parseRDAPASN(resp);
    await cacheSet(cacheKey, { data: info }, env.WHOIS_CACHE, getCacheTTL(env));
    return c.json(info);
  } catch (err) {
    if (err instanceof ResourceNotFoundError) {
      await cacheSet(cacheKey, { data: null, negative: true }, env.WHOIS_CACHE, getNegTTL(env));
      return errResponse(c, 404, "ASN not found");
    }
    if (err instanceof QueryDeniedError) return errResponse(c, 403, "Registry denied the query");
    const msg = err instanceof Error ? err.message : String(err);
    return errResponse(c, 502, `RDAP query failed: ${msg}`);
  }
}

// Health check
app.get("/health", (c) => c.json({ status: "ok" }));

// Typed paths
app.get("/domain/:resource", (c) => handleDomain(c, c.req.param("resource").toLowerCase()));
app.get("/ip/:resource{.+}", (c) => handleIP(c, c.req.param("resource").toLowerCase()));
app.get("/autnum/:resource", (c) => handleASN(c, c.req.param("resource")));

// Root auto-detect: /example.com  /1.1.1.1  /AS13335
app.get("/:resource{.+}", async (c) => {
  const resource = c.req.param("resource").toLowerCase();
  if (isIP(resource) || isCIDR(resource)) return handleIP(c, resource);
  if (isASN(resource)) return handleASN(c, resource);
  if (isDomain(toASCII(resource) || resource)) return handleDomain(c, resource);
  return errResponse(c, 400, "Invalid input. Please provide a valid domain, IP, or ASN.");
});

export default {
  fetch: app.fetch,
  async scheduled(_event: ScheduledEvent, env: Env, _ctx: ExecutionContext): Promise<void> {
    await handleScheduled(env);
  },
};
