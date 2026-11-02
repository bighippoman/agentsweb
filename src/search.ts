import { parseHTML } from "linkedom";
import { safeFetch, publicUrl } from "./transport.js";
import { search, removal } from "./store.js";
import type { Env } from "./types.js";

export interface SearchResult {
  title: string;
  url: string;
  snippet: string;
}
export async function webSearch(
  env: Env,
  query: string,
  count: number,
  signal?: AbortSignal,
): Promise<{ results: SearchResult[]; source: string }> {
  const controller = new AbortController();
  const combined = AbortSignal.any([
    controller.signal,
    AbortSignal.timeout(8000),
    ...(signal ? [signal] : []),
  ]);
  try {
    const sources = [
      "https://search.sapti.me",
      "https://searx.be",
      "https://search.ononoki.org",
    ].map(async (base) => {
      const response = await safeFetch(
        `${base}/search?q=${encodeURIComponent(query)}&format=json&categories=general`,
        { signal: combined },
      );
      if (!response.ok) throw new Error("search unavailable");
      const data = await response.json<{
        results?: Array<{ url: string; title: string; content: string }>;
      }>();
      const results = (data.results ?? [])
        .filter((r) => !publicUrl(r.url))
        .slice(0, count)
        .map((r) => ({ url: r.url, title: r.title, snippet: r.content ?? "" }));
      if (!results.length) throw new Error("empty results");
      return { results, source: new URL(base).hostname };
    });
    sources.push(
      (async () => {
        const response = await safeFetch(
          `https://html.duckduckgo.com/html/?q=${encodeURIComponent(query)}`,
          { headers: { "User-Agent": "Mozilla/5.0" }, signal: combined },
        );
        if (!response.ok) throw new Error("search unavailable");
        const { document } = parseHTML(await response.text());
        const results: SearchResult[] = [];
        for (const item of document.querySelectorAll(".result")) {
          const a = item.querySelector("a.result__a");
          if (!a) continue;
          try {
            const link = new URL(
              a.getAttribute("href")!,
              "https://duckduckgo.com",
            );
            const url = link.searchParams.get("uddg") ?? link.href;
            if (publicUrl(url)) continue;
            results.push({
              url,
              title: a.textContent ?? url,
              snippet:
                item.querySelector(".result__snippet")?.textContent ?? "",
            });
            if (results.length >= count) break;
          } catch {}
        }
        if (!results.length) throw new Error("empty results");
        return { results, source: "duckduckgo" };
      })(),
    );
    try {
      const found = await Promise.any(sources);
      const visible = await Promise.all(
        found.results.map(async (r) =>
          (await removal(env, r.url)) ? null : r,
        ),
      );
      return {
        ...found,
        results: visible.filter((r): r is SearchResult => r !== null),
      };
    } catch {
      const found = await search(env, query, count * 2),
        seen = new Set<string>();
      return {
        source: "cached-index",
        results: found
          .filter((r) => {
            if (seen.has(r.url)) return false;
            seen.add(r.url);
            return true;
          })
          .slice(0, count)
          .map((r) => ({
            url: r.url,
            title: r.title,
            snippet: r.text.slice(0, 500),
          })),
      };
    }
  } finally {
    controller.abort();
  }
}
