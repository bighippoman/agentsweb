# agentsweb.org

**The web, cached as clean markdown for AI agents.**

A global shared cache backed by Cloudflare Workers + KV. Multiple independent instances contribute and verify cached content through a self-healing consensus model that prevents poisoning -- if an entry is stale or tampered with, the next reader re-fetches and overwrites it.

## API

All endpoints are served from `https://agentsweb.org`.

### `GET /?url={url}`

Read cached markdown for a URL. Returns the markdown, trust level, source, and age.

### `PUT /`

Contribute a new cache entry. Body: `{ url, markdown, source, instance_id? }`. Content is validated through security gates before acceptance.

### `POST /confirm`

Confirm an existing entry matches your local fetch, boosting its trust level. Body: `{ url, content_hash, instance_id? }`.

### `GET /stats`

Public cache statistics (total hits, writes, hit rate).

## Security

- **Content gates** -- incoming markdown is scanned for prompt injection patterns, captcha/challenge pages, login walls, malicious HTML, and suspicious encoding before it enters the cache.
- **SSRF protection** -- private/internal IP ranges and non-HTTP schemes are blocked at the URL validation layer.
- **Rate limiting** -- per-IP limits enforced via KV TTLs (600 reads/min, 10 writes/min, 60 confirms/min).
- **Trust levels** -- entries start at trust 1; independent confirmations increment trust, extending TTL and making the entry harder to overwrite.
- **Self-healing on read** -- low-trust or mismatched entries can be replaced by any client that provides fresher content.
- **Domain-aware TTLs** -- news sites expire in 1 day, documentation/reference sites persist up to 30 days.

## Client

The primary client is [intercept-mcp](https://github.com/bighippoman/intercept-mcp), an MCP server that reads from and contributes to this cache automatically.

## Stack

- Cloudflare Workers (TypeScript)
- Cloudflare KV for storage
- Custom domains: `agentsweb.org`, `api.agentsweb.org`
