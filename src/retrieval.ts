import { safeFetch, publicUrl } from "./transport.js";
import { robotsAllows } from "./robots.js";
import { convertHtmlToMarkdown } from "./html-to-md.js";
import { contentProblem, cleanMarkdown, hash } from "./content.js";
import { ingest, readDocument, removal } from "./store.js";
import { normalizeUrl } from "./url-identity.js";
import type { Env, Document } from "./types.js";

interface LiveResult {
  markdown: string;
  source: string;
  source_kind: "live" | "archive";
  archived_at?: string;
}
const health = new Map<string, { failures: number; retryAt: number }>();

async function provider(
  name: string,
  run: () => Promise<LiveResult | null>,
): Promise<LiveResult> {
  if ((health.get(name)?.retryAt ?? 0) > Date.now())
    throw new Error("provider cooling down");
  try {
    const result = await run();
    if (!result || contentProblem(result.markdown))
      throw new Error("no readable content");
    health.delete(name);
    return result;
  } catch (error) {
    const failures = (health.get(name)?.failures ?? 0) + 1;
    if (health.size > 1000) health.clear();
    health.set(name, {
      failures,
      retryAt: failures >= 3 ? Date.now() + 30_000 : 0,
    });
    throw error;
  }
}

export async function retrieve(
  env: Env,
  raw: string,
  options: { signal?: AbortSignal; allowArchive?: boolean } = {},
): Promise<LiveResult | null> {
  const url = normalizeUrl(raw);
  if (publicUrl(url) || (await removal(env, url))) return null;
  const cancel = new AbortController();
  const signal = AbortSignal.any([
    AbortSignal.timeout(25_000),
    cancel.signal,
    ...(options.signal ? [options.signal] : []),
  ]);
  try {
    if (!(await robotsAllows(url, env.CACHE, signal))) return null;
    // One request negotiates native Markdown, with HTML as the fallback.
    try {
      const direct = await provider(`origin:${new URL(url).host}`, async () => {
        const response = await safeFetch(url, {
          headers: {
            Accept: "text/markdown, text/html;q=0.9",
            "User-Agent": "agentsweb/2.0 (+https://agentsweb.org/about)",
          },
          signal: AbortSignal.any([signal, AbortSignal.timeout(6000)]),
        });
        if (!response.ok) return null;
        const ct = response.headers.get("content-type") ?? "";
        if (!/text\/(html|markdown|plain)|application\/xhtml\+xml/i.test(ct))
          return null;
        const text = await response.text();
        const markdown = /html/i.test(ct)
          ? convertHtmlToMarkdown(text, response.url)
          : cleanMarkdown(text, url);
        return {
          markdown,
          source: /markdown/i.test(ct) ? "native-markdown" : "origin",
          source_kind: "live",
        };
      });
      return direct;
    } catch {
      if (signal.aborted) return null;
    }
    // Hosted retrieval runs only when the origin did not yield readable text.
    const hosted = [
      provider("jina", async () => {
        const response = await safeFetch(`https://r.jina.ai/${url}`, {
          headers: { Accept: "text/markdown" },
          signal,
        });
        return response.ok
          ? {
              markdown: await response.text(),
              source: "jina",
              source_kind: "live",
            }
          : null;
      }),
    ];
    if (env.CF_API_TOKEN && env.CF_ACCOUNT_ID)
      hosted.push(
        provider("browser-run", async () => {
          const response = await safeFetch(
            `https://api.cloudflare.com/client/v4/accounts/${env.CF_ACCOUNT_ID}/browser-rendering/markdown`,
            {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
                Authorization: `Bearer ${env.CF_API_TOKEN}`,
              },
              body: JSON.stringify({ url }),
              signal,
            },
          );
          if (!response.ok) return null;
          const data = await response.json<{
            success: boolean;
            result: string;
          }>();
          return data.success && typeof data.result === "string"
            ? {
                markdown: data.result,
                source: "browser-run",
                source_kind: "live",
              }
            : null;
        }),
      );
    try {
      return await Promise.any(hosted);
    } catch {
      if (signal.aborted || !options.allowArchive) return null;
    }
    // Historical sources are opt-in and are never allowed to outrun live ones.
    try {
      return await provider("wayback", async () => {
        const response = await safeFetch(
          `https://archive.org/wayback/available?url=${encodeURIComponent(url)}`,
          { signal },
        );
        if (!response.ok) return null;
        const data = await response.json<{
          archived_snapshots?: {
            closest?: { available: boolean; url: string; timestamp: string };
          };
        }>();
        const snap = data.archived_snapshots?.closest;
        if (!snap?.available || !/^\d{14}$/.test(snap.timestamp)) return null;
        const replay = new URL(snap.url);
        if (replay.hostname !== "web.archive.org") return null;
        replay.protocol = "https:";
        replay.pathname = replay.pathname.replace(
          /\/web\/(\d+)\//,
          "/web/$1id_/",
        );
        const page = await safeFetch(replay.href, { signal });
        if (!page.ok) return null;
        const ts = snap.timestamp;
        return {
          markdown: convertHtmlToMarkdown(await page.text(), url),
          source: "wayback",
          source_kind: "archive",
          archived_at: `${ts.slice(0, 4)}-${ts.slice(4, 6)}-${ts.slice(6, 8)}T${ts.slice(8, 10)}:${ts.slice(10, 12)}:${ts.slice(12, 14)}Z`,
        };
      });
    } catch {
      return null;
    }
  } finally {
    cancel.abort();
  }
}

export async function fetchDocument(
  env: Env,
  url: string,
  options: {
    maxAge?: number;
    signal?: AbortSignal;
    allowArchive?: boolean;
  } = {},
): Promise<{ doc: Document; cached: boolean } | null> {
  const cached = await readDocument(env, url),
    maxAge = options.maxAge ?? 3600;
  if (
    cached &&
    maxAge > 0 &&
    (Date.now() - cached.retrieved_at) / 1000 <= maxAge &&
    (cached.source_kind !== "archive" || options.allowArchive)
  )
    return { doc: cached, cached: true };
  const started = Date.now();
  const result = await retrieve(env, url, options);
  if (!result) return null;
  // Historical fallback is specific to this opt-in request. It must not
  // replace live content or appear on subsequent default cache-only reads.
  if (result.source_kind === "archive") {
    return {
      cached: false,
      doc: {
        ...result,
        url: normalizeUrl(url),
        completeness: "complete",
        retrieved_at: started,
        verified_at: null,
        content_hash: await hash(result.markdown),
        expires_at: started,
        title:
          result.markdown.match(/^#\s+(.+)/m)?.[1]?.slice(0, 250) ||
          new URL(url).hostname,
      },
    };
  }
  const doc = await ingest(env, {
    url,
    markdown: result.markdown,
    source: result.source,
    source_kind: result.source_kind,
    completeness: "complete",
    retrieved_at: started,
    verified_at:
      result.source === "origin" || result.source === "native-markdown"
        ? started
        : null,
    archived_at: result.archived_at,
  });
  return { doc, cached: false };
}

export function providerStatus() {
  return Object.fromEntries(
    [...health].map(([key, value]) => [
      key,
      { failures: value.failures, cooling_down: value.retryAt > Date.now() },
    ]),
  );
}
