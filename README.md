# agentsweb

Readable web content and a searchable public cache for AI agents. Works with [Intercept MCP](https://github.com/bighippoman/intercept-mcp).

- [Live playground](https://agentsweb.org)
- [API documentation](https://agentsweb.org/docs)
- [Install Intercept](https://agentsweb.org/integrations)

## Develop and verify

Use Node.js 22.18 or newer (CI uses 24).

```sh
npm ci
npx wrangler d1 migrations apply agentsweb-index --local
npm run dev
npm run check
```

Tests run in the Cloudflare Workers runtime with local D1, KV, and Queue bindings. Outbound requests are mocked; they never modify production.

## Architecture

`src/index.ts` handles HTTP, scheduled refresh, and Queue events. `retrieval.ts` negotiates native Markdown, extracts direct HTML, and falls back to hosted rendering. Archives require explicit opt-in. `store.ts` publishes content and index metadata atomically using D1. Immutable content bodies are delivered from KV; every ingestion path indexes passages with FTS5. `robots.ts` implements path rules. `site.ts`, `site-style.ts`, and `site-client.ts` serve the responsive playground and documentation.

A response includes its source, retrieval timestamp, completeness, content hash, and age. `verified_at` records direct origin retrieval, not proof that the source is factually correct. Quality heuristics do not make third-party content safe to follow as instructions.

Cache variants are computed from the selected document version and never overwrite the stored full document. Confirmations never reset retrieval time. Atomic D1 counters and minute rate-limit buckets avoid KV read-modify-write races. Refresh jobs use a per-URL deduplication lease and Cloudflare Queues retries.

## API compatibility

The existing `/`, `/raw`, `/fetch`, `/batch`, `/search`, `/web`, `/research`, `/ask`, `/chunks`, `/context`, `/changes`, `/stats`, `/confirm`, `/takedown`, and `/opt-out` paths remain. See the live docs for parameters.

Version 2 deliberately changes contribution semantics: `PUT /` returns **202 pending_verification** and queues a public-source retrieval. Submitted text is not immediately published. `trust_level` remains a compatibility field (2 for direct-origin retrieval, 1 for hosted retrieval); confirmations no longer inflate it. Stats count current indexed documents, not historical write volume. Counters restart with the v2 migration.

URL identity v2 preserves functional parameters, scheme, www, path case, and trailing slashes. Legacy cache keys collapsed these variants and legacy timestamps changed on confirmations. Old entries are retained for rollback but are not promoted as freshly verified v2 documents. Revalidation rebuilds the new index from original URLs.

## Preview and release

The `preview` environment has separate D1, KV, and Queue resources and no production custom-domain routes.

```sh
npm run check
npx wrangler d1 migrations apply agentsweb-preview-index --env preview --remote
npx wrangler deploy --env preview
# After preview API and responsive-browser checks:
npx wrangler d1 migrations apply agentsweb-index --remote
npm run deploy
```

Production secrets are existing `ADMIN_SECRET`, `CF_API_TOKEN`, and `CF_ACCOUNT_ID` bindings. Never commit their values. Preview can test direct/native retrieval without renderer secrets.

Before deploying, retain the previous Worker version ID. Roll back code with `wrangler rollback <version-id>`; the additive D1 migration and legacy KV entries are retained. A rollback to v1 does not remove its original cache. Review pending Queue jobs when rolling back because the old Worker has no Queue handler.

Current document metadata expires after seven days without retrieval. KV bodies expire after 30 days. Scheduled cleanup removes expired document indexes, obsolete versions, and short-lived rate-limit identifiers. Approved removals block every content-serving route and search; domain opt-outs include subdomains.
