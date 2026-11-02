import type { Env, Document } from "./types.js";
import { normalizeUrl } from "./url-identity.js";
import { publicUrl } from "./transport.js";
import { hash, passages, selectSection, contentProblem } from "./content.js";
import {
  readDocument,
  ingest,
  search,
  rateLimit,
  queueRefresh,
  count,
  removal,
  remove,
  evidence,
} from "./store.js";
import { fetchDocument, providerStatus } from "./retrieval.js";
import { webSearch } from "./search.js";
import { sitePage, siteScript, siteStyle } from "./site.js";

const headers = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, HEAD, PUT, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, If-None-Match",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "X-Frame-Options": "DENY",
  "Cache-Control": "no-store",
  "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
  "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
};
const json = (
  data: unknown,
  status = 200,
  extra: Record<string, string> = {},
) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      ...headers,
      "Content-Type": "application/json; charset=utf-8",
      ...extra,
    },
  });
const finite = (
  value: string | null,
  fallback: number,
  min: number,
  max: number,
) =>
  value === null
    ? fallback
    : Number.isFinite(Number(value))
      ? Math.min(max, Math.max(min, Math.floor(Number(value))))
      : fallback;

async function admin(request: Request, env: Env): Promise<boolean> {
  if (!env.ADMIN_SECRET) return false;
  const supplied =
    request.headers.get("Authorization")?.replace(/^Bearer /, "") ?? "";
  return (await hash(supplied)) === (await hash(env.ADMIN_SECRET));
}
async function body(request: Request): Promise<any> {
  if (Number(request.headers.get("content-length")) > 1_100_000)
    throw new Error("body too large");
  const reader = request.body?.getReader();
  if (!reader) throw new Error("body required");
  const decoder = new TextDecoder();
  let result = "",
    bytes = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    bytes += value.byteLength;
    if (bytes > 1_100_000) {
      await reader.cancel();
      throw new Error("body too large");
    }
    result += decoder.decode(value, { stream: true });
  }
  result += decoder.decode();
  return JSON.parse(result);
}
function documentResponse(
  doc: Document,
  params: URLSearchParams,
  request: Request,
  cached = true,
): Response {
  let markdown = doc.markdown;
  const toc = [...markdown.matchAll(/^#{1,6}\s+(.+)$/gm)].map((m) => m[1]);
  if (params.get("toc") === "true")
    return json({ ...evidence(doc), headings: toc, count: toc.length });
  const section = params.get("section");
  if (section) {
    const selected = selectSection(markdown, section);
    if (!selected)
      return json({ error: "section not found", available_headings: toc }, 404);
    markdown = selected;
  }
  const maxTokens = finite(params.get("max_tokens"), 0, 0, 250_000),
    totalTokens = Math.ceil(doc.markdown.length / 4);
  const truncated = maxTokens > 0 && markdown.length > maxTokens * 4;
  if (truncated) markdown = markdown.slice(0, maxTokens * 4);
  // ETags identify the representation, including partial variants.
  const etag = `"${doc.content_hash.slice(0, 24)}-${maxTokens}-${encodeURIComponent(section ?? "")}"`;
  if (request.headers.get("if-none-match") === etag)
    return new Response(null, {
      status: 304,
      headers: { ...headers, ETag: etag },
    });
  return json(
    {
      ...evidence(doc),
      markdown,
      tokens: Math.ceil(markdown.length / 4),
      total_tokens: totalTokens,
      truncated,
      completeness: truncated || section ? "partial" : doc.completeness,
      cached,
      fresh: !cached,
      stale: Date.now() - doc.retrieved_at > 3600_000,
    },
    200,
    { ETag: etag },
  );
}
async function stats(env: Env) {
  const [docs, chunks, counters] = await Promise.all([
    env.DB.prepare("SELECT COUNT(*) AS n FROM documents WHERE expires_at>?")
      .bind(Date.now())
      .first<{ n: number }>(),
    env.DB.prepare(
      "SELECT COUNT(*) AS n FROM chunks c JOIN documents d ON c.url=d.url AND c.content_hash=d.content_hash WHERE d.expires_at>?",
    )
      .bind(Date.now())
      .first<{ n: number }>(),
    env.DB.prepare("SELECT name,value FROM counters").all<{
      name: string;
      value: number;
    }>(),
  ]);
  const values = Object.fromEntries(
    counters.results.map((r) => [r.name, r.value]),
  );
  return {
    pages_cached: docs?.n ?? 0,
    passages_indexed: chunks?.n ?? 0,
    cache_hits: values.hits ?? 0,
    successful_retrievals: values.writes ?? 0,
    confirmations: values.confirms ?? 0,
    rejected: values.rejected ?? 0,
    counters_since: "2026-11-02",
    search: "D1 FTS5",
    version: "2.0.0",
  };
}

async function handle(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
): Promise<Response> {
  const started = Date.now(),
    u = new URL(request.url),
    p = u.searchParams,
    method = request.method,
    path = u.pathname;
  if (method === "OPTIONS") return new Response(null, { status: 204, headers });
  if (!["GET", "HEAD", "POST", "PUT"].includes(method))
    return json({ error: "method not allowed" }, 405);
  if (method === "HEAD") return new Response(null, { status: 200, headers });
  if (path === "/assets/site.css")
    return new Response(siteStyle, {
      headers: {
        ...headers,
        "Content-Type": "text/css",
        "Cache-Control": "public, max-age=3600",
      },
    });
  if (path === "/assets/site.js")
    return new Response(siteScript, {
      headers: {
        ...headers,
        "Content-Type": "text/javascript",
        "Cache-Control": "public, max-age=3600",
      },
    });
  if (method === "GET" && !p.has("url")) {
    const page = sitePage(path);
    if (page) return page;
  }
  if (path === "/og.svg")
    return new Response(
      `<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630"><rect width="1200" height="630" fill="#f6f4ef"/><rect x="64" y="60" width="64" height="64" rx="12" fill="#edb34f"/><text x="79" y="109" font-family="Arial,sans-serif" font-size="60" font-weight="700" fill="#20241c">a</text><text x="148" y="108" font-family="Arial,sans-serif" font-size="44" font-weight="700" fill="#20241c">agentsweb.</text><text x="64" y="295" font-family="Arial,sans-serif" font-size="100" font-weight="700" fill="#20241c">Less noise.</text><text x="64" y="405" font-family="Georgia,serif" font-size="108" font-style="italic" fill="#20241c">More source.</text><text x="64" y="535" font-family="Arial,sans-serif" font-size="28" fill="#62685b">Readable web content. Citable passages. Built for agents.</text></svg>`,
      {
        headers: {
          ...headers,
          "Content-Type": "image/svg+xml",
          "Cache-Control": "public, max-age=3600",
        },
      },
    );
  if (path === "/robots.txt")
    return new Response(
      "User-agent: *\nAllow: /\nSitemap: https://agentsweb.org/sitemap.xml\n",
      { headers: { ...headers, "Content-Type": "text/plain" } },
    );
  if (path === "/sitemap.xml")
    return new Response(
      '<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">' +
        ["", "docs", "about", "integrations", "privacy", "terms", "dmca"]
          .map((s) => `<url><loc>https://agentsweb.org/${s}</loc></url>`)
          .join("") +
        "</urlset>",
      { headers: { ...headers, "Content-Type": "application/xml" } },
    );
  if (path === "/stats") return json(await stats(env));
  if (path === "/health")
    return json({
      status: "ok",
      version: "2.0.0",
      providers: providerStatus(),
    });
  const isAdmin = await admin(request, env),
    ip = request.headers.get("CF-Connecting-IP") ?? "unknown";
  const action =
    method === "PUT" || method === "POST"
      ? "write"
      : path === "/fetch" || path === "/research"
        ? "fetch"
        : "read";
  if (!isAdmin && !(await rateLimit(env, ip, action)))
    return json(
      { error: "rate limited; retry after the current minute" },
      429,
      { "Retry-After": "60" },
    );
  const target = p.get("url");
  if (target) {
    const reason = publicUrl(target);
    if (reason) return json({ error: reason }, 400);
    const removed = await removal(env, target);
    if (removed) return json({ error: removed }, 451);
  }
  if (
    method === "GET" &&
    target &&
    ["/", "/raw", "/chunks", "/changes"].includes(path)
  ) {
    const doc = await readDocument(env, target);
    if (!doc) {
      if (path === "/") ctx.waitUntil(queueRefresh(env, target));
      return json(
        {
          status: "miss",
          error: "page not cached; use /fetch for live retrieval",
        },
        404,
      );
    }
    const maxAge = finite(p.get("max_age"), 3600, 0, 2592000);
    if ((Date.now() - doc.retrieved_at) / 1000 > maxAge) {
      ctx.waitUntil(queueRefresh(env, target));
      return json(
        {
          status: "stale",
          age_seconds: evidence(doc).age_seconds,
          revalidation: "queued",
        },
        404,
      );
    }
    ctx.waitUntil(count(env, "hits"));
    if (path === "/raw")
      return new Response(doc.markdown, {
        headers: {
          ...headers,
          "Content-Type": "text/markdown; charset=utf-8",
          "X-Content-Hash": doc.content_hash,
          "X-Source": doc.source,
          "X-Source-Kind": doc.source_kind,
          "X-Retrieved-At": new Date(doc.retrieved_at).toISOString(),
          "X-Completeness": doc.completeness,
        },
      });
    if (path === "/chunks")
      return json({
        ...evidence(doc),
        chunks: p.get("q")
          ? await search(env, p.get("q")!, 5, target)
          : passages(doc.markdown, doc.url),
      });
    if (path === "/changes") {
      const versions = await env.DB.prepare(
        "SELECT content_hash,retrieved_at FROM versions WHERE url=? ORDER BY retrieved_at DESC LIMIT 10",
      )
        .bind(normalizeUrl(target))
        .all();
      return json({
        url: doc.url,
        changed: versions.results.length > 1,
        current_hash: doc.content_hash,
        last_updated: new Date(doc.retrieved_at).toISOString(),
        versions: versions.results,
      });
    }
    return documentResponse(doc, p, request);
  }
  if (method === "GET" && path === "/fetch" && target) {
    const result = await fetchDocument(env, target, {
      maxAge:
        p.get("refresh") === "true"
          ? 0
          : finite(p.get("max_age"), 3600, 0, 2592000),
      signal: request.signal,
      allowArchive: p.get("allow_archive") === "true",
    });
    if (!result)
      return json(
        {
          error: "No readable public content was retrieved",
          completeness: "unavailable",
          timing_ms: Date.now() - started,
        },
        502,
      );
    const response = documentResponse(result.doc, p, request, result.cached);
    response.headers.set(
      "Server-Timing",
      `retrieval;dur=${Date.now() - started}`,
    );
    return response;
  }
  if (method === "GET" && path === "/batch") {
    const maxAge = finite(p.get("max_age"), 3600, 0, 2592000);
    const urls = (p.get("urls") ?? "").split(",").filter(Boolean).slice(0, 20);
    if (!urls.length) return json({ error: "urls required" }, 400);
    const pairs = await Promise.all(
      urls.map(async (url) => {
        if (publicUrl(url))
          return [url, { status: "error", error: "invalid public URL" }];
        const doc = await readDocument(env, url);
        if (
          doc &&
          (maxAge === 0 || (Date.now() - doc.retrieved_at) / 1000 > maxAge)
        ) {
          ctx.waitUntil(queueRefresh(env, url));
          return [
            url,
            {
              status: "stale",
              revalidation: "queued",
              age_seconds: evidence(doc).age_seconds,
            },
          ];
        }
        return [
          url,
          doc
            ? { status: "hit", ...evidence(doc), markdown: doc.markdown }
            : { status: "miss" },
        ];
      }),
    );
    return json({ results: Object.fromEntries(pairs) });
  }
  if (
    method === "GET" &&
    ["/ask", "/context", "/search", "/web", "/research"].includes(path)
  ) {
    const query = (p.get("q") ?? "").trim();
    if (query.length < 2 || query.length > 500)
      return json({ error: "query must be 2–500 characters" }, 400);
    const limit = finite(
      p.get("count") ?? p.get("pages"),
      path === "/research" ? 3 : 5,
      1,
      path === "/research" ? 5 : 20,
    );
    if (path === "/ask" || path === "/context") {
      const results = await search(env, query, limit);
      ctx.waitUntil(count(env, "searches"));
      const sources = [...new Set(results.map((r) => r.url))];
      return json({
        query,
        results,
        sources,
        search_source: "cached-index",
        timing_ms: Date.now() - started,
        ...(path === "/context"
          ? {
              briefing: results
                .map(
                  (r, i) =>
                    `## [${i + 1}] ${r.heading}\n${r.citation_url}\n\n${r.text}`,
                )
                .join("\n\n"),
              chunks_used: results.length,
              tokens: Math.ceil(
                results.reduce((s, r) => s + r.text.length, 0) / 4,
              ),
            }
          : {}),
      });
    }
    if (path === "/search") {
      const rows = await env.DB.prepare(
        "SELECT url FROM documents WHERE url LIKE ? AND expires_at>? LIMIT 40",
      )
        .bind(`%${query}%`, Date.now())
        .all<{ url: string }>();
      const visible = await Promise.all(
        rows.results.map(async (r) =>
          (await removal(env, r.url)) ? null : r.url,
        ),
      );
      const results = visible.filter(Boolean).slice(0, 20);
      return json({ query, results, total: results.length });
    }
    const found = await webSearch(env, query, limit, request.signal);
    if (path === "/web")
      return json({ query, ...found, timing_ms: Date.now() - started });
    const results = await Promise.all(
      found.results.map(async (r) => {
        const value = await fetchDocument(env, r.url, {
          signal: request.signal,
        });
        if (!value)
          return { ...r, markdown: null, completeness: "unavailable" };
        const selected = await search(env, query, 2, r.url);
        return {
          ...r,
          ...evidence(value.doc),
          cached: value.cached,
          markdown: value.doc.markdown.slice(0, 24000),
          truncated: value.doc.markdown.length > 24000,
          completeness:
            value.doc.markdown.length > 24000
              ? "partial"
              : value.doc.completeness,
          passages: selected,
        };
      }),
    );
    ctx.waitUntil(count(env, "researches"));
    return json({
      query,
      results,
      search_source: found.source,
      timing_ms: Date.now() - started,
    });
  }
  if (method === "PUT" && path === "/") {
    const data = await body(request);
    if (typeof data.url !== "string" || publicUrl(data.url))
      return json({ error: "valid public url required" }, 400);
    if (typeof data.markdown !== "string" || contentProblem(data.markdown)) {
      ctx.waitUntil(count(env, "rejected"));
      return json({ error: "readable markdown required" }, 422);
    }
    if (await removal(env, data.url))
      return json({ error: "content removed" }, 451);
    // Submissions are refresh hints, not authority to publish arbitrary text.
    // Neither an unverified contribution nor a confirmation extends freshness.
    const queued = await queueRefresh(env, data.url);
    return json(
      { status: "pending_verification", queued, url: normalizeUrl(data.url) },
      202,
    );
  }
  if (method === "POST" && path === "/confirm") {
    const data = await body(request);
    if (typeof data.url !== "string" || publicUrl(data.url))
      return json({ error: "valid public url required" }, 400);
    const doc = await readDocument(env, data.url);
    if (!doc) return json({ status: "miss" }, 404);
    const matches = data.content_hash === doc.content_hash;
    ctx.waitUntil(count(env, "confirms"));
    if (!matches) ctx.waitUntil(queueRefresh(env, data.url));
    return json({
      status: matches ? "confirmed" : "mismatch",
      trust_level: doc.verified_at ? 2 : 1,
      retrieved_at: new Date(doc.retrieved_at).toISOString(),
      revalidation: matches ? "not needed" : "queued",
    });
  }
  if (
    method === "POST" &&
    (path.startsWith("/admin/") || ["/takedown", "/opt-out"].includes(path))
  ) {
    if (!isAdmin)
      return json(
        {
          error:
            "admin authentication required; contact dmca@agentsweb.org for removals",
        },
        403,
      );
    const data = await body(request);
    if (path === "/takedown") {
      if (typeof data.url !== "string" || publicUrl(data.url))
        return json({ error: "valid url required" }, 400);
      const url = normalizeUrl(data.url);
      await remove(env, url, "removed at owner request");
      return json({ status: "removed", url });
    }
    if (path === "/opt-out") {
      const domain = String(data.domain ?? "")
        .toLowerCase()
        .replace(/^www\./, "");
      if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(domain))
        return json({ error: "valid domain required" }, 400);
      await remove(env, `domain:${domain}`, "domain opted out");
      return json({ status: "opted out", domain });
    }
    if (path === "/admin/clear-dmca") {
      const url = normalizeUrl(data.url);
      await env.DB.prepare("DELETE FROM removals WHERE key=?").bind(url).run();
      await env.CACHE.delete(`dmca:${await hash(url)}`);
      return json({ status: "cleared", url });
    }
    if (
      path === "/admin/rebuild-index" ||
      path === "/admin/rebuild-search-index"
    ) {
      const urls = (data.urls ?? data.entries?.map((r: any) => r.url) ?? [])
        .filter((url: unknown) => typeof url === "string" && !publicUrl(url))
        .slice(0, 100);
      await Promise.all(urls.map((url: string) => queueRefresh(env, url)));
      return json({ status: "revalidation queued", count: urls.length }, 202);
    }
    if (path === "/admin/purge-ban" || path === "/admin/purge-ban-ip") {
      await env.CACHE.delete(`abuse:${data.ip ?? ip}`);
      return json({ status: "legacy ban cleared" });
    }
  }
  return json({ error: "not found" }, 404);
}

export default {
  async fetch(
    request: Request,
    env: Env,
    ctx: ExecutionContext,
  ): Promise<Response> {
    try {
      return await handle(request, env, ctx);
    } catch (error) {
      console.error(
        "request failed",
        error instanceof Error ? error.message : "unknown",
      );
      return json({ error: "request could not be completed" }, 500);
    }
  },
  async queue(batch: MessageBatch<{ url: string }>, env: Env): Promise<void> {
    for (const message of batch.messages) {
      try {
        const url = message.body.url;
        if (publicUrl(url) || (await removal(env, url))) {
          message.ack();
          await env.DB.prepare("DELETE FROM jobs WHERE url=?").bind(url).run();
          continue;
        }
        const result = await fetchDocument(env, url, { maxAge: 0 });
        if (!result) throw new Error("origin unavailable");
        await env.DB.prepare("DELETE FROM jobs WHERE url=?")
          .bind(normalizeUrl(url))
          .run();
        message.ack();
      } catch {
        await count(env, "revalidation_failures");
        message.retry({ delaySeconds: 120 });
      }
    }
  },
  async scheduled(_event: ScheduledEvent, env: Env): Promise<void> {
    const rows = await env.DB.prepare(
      "SELECT url FROM documents WHERE retrieved_at<? ORDER BY COALESCE(last_refresh_attempt,retrieved_at) LIMIT 20",
    )
      .bind(Date.now() - 3600_000)
      .all<{ url: string }>();
    await Promise.all(rows.results.map((r) => queueRefresh(env, r.url)));
    await env.DB.batch([
      env.DB.prepare("DELETE FROM limits WHERE expires_at<?").bind(Date.now()),
      env.DB.prepare("DELETE FROM jobs WHERE queued_at<?").bind(
        Date.now() - 86400_000,
      ),
      env.DB.prepare(
        "DELETE FROM chunks WHERE url IN (SELECT url FROM documents WHERE expires_at<?)",
      ).bind(Date.now()),
      env.DB.prepare("DELETE FROM versions WHERE retrieved_at<?").bind(
        Date.now() - 30 * 86400_000,
      ),
      env.DB.prepare(
        "DELETE FROM chunks WHERE NOT EXISTS (SELECT 1 FROM versions v WHERE v.url=chunks.url AND v.content_hash=chunks.content_hash)",
      ),
      env.DB.prepare("DELETE FROM documents WHERE expires_at<?").bind(
        Date.now(),
      ),
    ]);
  },
};
