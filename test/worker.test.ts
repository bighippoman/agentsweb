import {
  env,
  createExecutionContext,
  waitOnExecutionContext,
} from "cloudflare:test";
import { beforeEach, afterEach, describe, expect, it, vi } from "vitest";
import worker from "../src/index";
import {
  ingest,
  readDocument,
  search,
  remove,
  queueRefresh,
} from "../src/store";
import { normalizeUrl } from "../src/url-identity";
import { convertHtmlToMarkdown } from "../src/html-to-md";
import { robotsPathAllowed } from "../src/robots";
import { contentProblem, passages } from "../src/content";
import { fetchDocument } from "../src/retrieval";
import { safeFetch } from "../src/transport";

const markdown =
  "# React state guide\n\n" +
  Array.from(
    { length: 15 },
    (_, i) =>
      `## Lesson ${i + 1}\n\nThe useState Hook declares a state variable for a React component. Updating state schedules a render. Each render sees a snapshot. Use functional updates to calculate the next value from the previous value. Example ${i + 1} explains how event handlers and batched updates work together.\n\n`,
  ).join("");
let seq = 0;
const unique = () => `https://example.org/guide-${++seq}`;
async function seed(url = unique(), text = markdown, time = Date.now()) {
  return ingest(env, {
    url,
    markdown: text,
    source: "origin",
    source_kind: "live",
    completeness: "complete",
    retrieved_at: time,
    verified_at: time,
  });
}
async function request(path: string, init?: RequestInit) {
  const ctx = createExecutionContext();
  const response = await worker.fetch(
    new Request("https://agentsweb.org" + path, init),
    env,
    ctx,
  );
  await waitOnExecutionContext(ctx);
  return response;
}
beforeEach(() => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => {
      throw new Error("unmocked outbound fetch");
    }),
  );
});
afterEach(() => {
  vi.unstubAllGlobals();
});

describe("public API and transactional index", () => {
  it("does not let a partial response poison full content or its ETag", async () => {
    const doc = await seed();
    const partial = await request(
      "/?url=" + encodeURIComponent(doc.url) + "&max_tokens=200",
    );
    const p = await partial.json<any>();
    expect(p.truncated).toBe(true);
    expect(p.completeness).toBe("partial");
    expect(p.markdown.length).toBeLessThan(markdown.length);
    const full = await request("/?url=" + encodeURIComponent(doc.url));
    const f = await full.json<any>();
    expect(f.markdown).toBe(markdown);
    expect(f.completeness).toBe("complete");
    expect(full.headers.get("etag")).not.toBe(partial.headers.get("etag"));
  });
  it("indexes text deep beyond the old snippet and page sample", async () => {
    const url = unique();
    await seed(
      url,
      markdown +
        "\n## Rare detail\n\nThe cobaltquartz protocol synchronizes distant observatories without losing the event sequence.",
    );
    const matches = await search(env, "cobaltquartz protocol");
    expect(matches.some((r) => r.url === url)).toBe(true);
    expect(matches[0].citation_url).toContain("#:~:text=");
    expect(matches[0].content_hash).toHaveLength(64);
  });
  it("updates searchable content and retains version history without stale chunks", async () => {
    const url = unique();
    await seed(url, markdown + "\nolduniqueword details", Date.now() - 1000);
    await seed(url, markdown + "\nnewuniqueword details");
    expect(await search(env, "olduniqueword", 5, url)).toHaveLength(0);
    expect(await search(env, "newuniqueword", 5, url)).toHaveLength(1);
    const changes = await (
      await request("/changes?url=" + encodeURIComponent(url))
    ).json<any>();
    expect(changes.changed).toBe(true);
  });
  it("an older finishing retrieval cannot overwrite a newer version", async () => {
    const url = unique(),
      now = Date.now();
    await seed(url, markdown + "\nnewerversion detail", now);
    await seed(url, markdown + "\nolderversion detail", now - 1000);
    expect((await readDocument(env, url))?.markdown).toContain("newerversion");
    expect(await search(env, "olderversion", 5, url)).toHaveLength(0);
  });
  it("confirmations cannot make stale content fresh", async () => {
    const doc = await seed(unique(), markdown, Date.now() - 7200_000);
    const response = await request("/confirm", {
      method: "POST",
      body: JSON.stringify({ url: doc.url, content_hash: doc.content_hash }),
    });
    expect(response.status).toBe(200);
    expect((await readDocument(env, doc.url))?.retrieved_at).toBe(
      doc.retrieved_at,
    );
    const stale = await request(
      "/?url=" + encodeURIComponent(doc.url) + "&max_age=60",
    );
    expect(stale.status).toBe(404);
  });
  it("contributions queue origin verification instead of publishing submitted text", async () => {
    const url = unique();
    const response = await request("/", {
      method: "PUT",
      body: JSON.stringify({ url, markdown, source: "test" }),
    });
    expect(response.status).toBe(202);
    expect(await readDocument(env, url)).toBeNull();
    expect(await queueRefresh(env, url)).toBe(false);
  });
  it("removal blocks raw reads, chunks, search, batch, and live fetching", async () => {
    const doc = await seed(unique(), markdown + "\nremovaluniqueword detail");
    await remove(env, doc.url, "owner removal");
    for (const path of ["/", "/raw", "/chunks", "/fetch", "/changes"])
      expect(
        (await request(path + "?url=" + encodeURIComponent(doc.url))).status,
      ).toBe(451);
    expect(await search(env, "removaluniqueword")).toHaveLength(0);
    const batch = await (
      await request("/batch?urls=" + encodeURIComponent(doc.url))
    ).json<any>();
    expect(batch.results[doc.url].status).toBe("miss");
  });
  it("counts unique current documents rather than writes", async () => {
    const before = await (await request("/stats")).json<any>();
    const url = unique();
    await seed(url);
    await seed(url, markdown + "\nOne more observation.");
    const after = await (await request("/stats")).json<any>();
    expect(after.pages_cached - before.pages_cached).toBe(1);
    expect(after.successful_retrievals - before.successful_retrievals).toBe(2);
  });
  it("keeps functional URL identities distinct", () => {
    expect(
      normalizeUrl("http://www.example.org/A/?ref=one&utm_source=ad"),
    ).toBe("http://www.example.org/A/?ref=one");
    expect(
      normalizeUrl("https://example.org/a?token=secret&utm_source=ad"),
    ).toContain("utm_source");
  });
  it("rejects private and signed URLs before contacting providers", async () => {
    for (const url of [
      "http://127.0.0.1/",
      "https://example.org/?token=secret",
      "http://[::1]/",
    ])
      expect(
        (await request("/fetch?url=" + encodeURIComponent(url))).status,
      ).toBe(400);
  });
  it("retains nested main content, tables, code, and absolute links", () => {
    const result = convertHtmlToMarkdown(
      '<html><head><title>Guide</title></head><body><nav>Noise</nav><main><h1>Guide</h1><div>First<div>Nested</div>Last</div><p>Final paragraph</p><a href="/next">Next</a><pre><code>const a = 1;</code></pre><table><tr><th>A</th></tr><tr><td>B</td></tr></table></main></body></html>',
      "https://example.org/",
    );
    expect(result).toContain("Final paragraph");
    expect(result).toContain("Last");
    expect(result).not.toContain("Noise");
    expect(result).toContain("https://example.org/next");
    expect(result).toContain("const a = 1;");
    expect(result).toContain("| A |");
  });
  it("does not reject a legitimate article mentioning CAPTCHA", () =>
    expect(
      contentProblem("# CAPTCHA accessibility\n\n" + markdown),
    ).toBeNull());
  it("respects robots path precedence", () => {
    expect(
      robotsPathAllowed(
        "User-agent: *\nDisallow: /private\nAllow: /private/public",
        "/private/public",
      ),
    ).toBe(true);
    expect(
      robotsPathAllowed("User-agent: agentsweb\nDisallow: /", "/guide"),
    ).toBe(false);
  });
  it("uses native markdown before hosted services and indexes that ingestion", async () => {
    const host = "https://native.example.org";
    vi.mocked(fetch).mockImplementation(async (url) =>
      String(url).endsWith("/robots.txt")
        ? new Response("User-agent: *\nAllow: /")
        : new Response(markdown + "\nnativetestword evidence", {
            headers: { "Content-Type": "text/markdown" },
          }),
    );
    const result = await fetchDocument(env, host + "/guide");
    expect(result?.doc.source).toBe("native-markdown");
    expect(await search(env, "nativetestword")).toHaveLength(1);
  });
  it("validates redirect destinations", async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response(null, {
        status: 302,
        headers: { location: "http://127.0.0.1/" },
      }),
    );
    await expect(safeFetch("https://redirect.example.org/")).rejects.toThrow(
      "private",
    );
  });
  it("serves a working playground shell and documented endpoints", async () => {
    const home = await request("/");
    expect(home.status).toBe(200);
    expect(await home.text()).toContain('id="request-form"');
    const docs = await request("/docs");
    expect(await docs.text()).toContain("pending_verification");
    expect((await request("/assets/site.js")).headers.get("content-type")).toBe(
      "text/javascript",
    );
  });
});

it("batch reads honor the same freshness budget as individual reads", async () => {
  const doc = await seed(unique(), markdown, Date.now() - 7200_000);
  const response = await request("/batch?urls=" + encodeURIComponent(doc.url));
  const data = await response.json<any>();
  expect(data.results[doc.url].status).toBe("stale");
  expect(data.results[doc.url].markdown).toBeUndefined();
});

it("an opt-in archive fallback never replaces the live indexed version", async () => {
  const url = "https://archive-regression.example.org/article";
  const previous = await seed(url, markdown, Date.now() - 7200_000);
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string | URL | Request) => {
      const target = String(input);
      if (target.startsWith("https://archive.org/wayback/available"))
        return Response.json({
          archived_snapshots: {
            closest: {
              available: true,
              timestamp: "20200101000000",
              url: "https://web.archive.org/web/20200101000000/https://archive-regression.example.org/article",
            },
          },
        });
      if (target.startsWith("https://web.archive.org/"))
        return new Response(
          "<article><h1>Historical article</h1><p>" +
            markdown +
            "</p></article>",
          { headers: { "content-type": "text/html" } },
        );
      return new Response("unavailable", { status: 404 });
    }),
  );
  const result = await fetchDocument(env, url, {
    maxAge: 0,
    allowArchive: true,
  });
  expect(result?.doc.source_kind).toBe("archive");
  expect(result?.doc.archived_at).toBe("2020-01-01T00:00:00Z");
  expect((await readDocument(env, url))?.content_hash).toBe(
    previous.content_hash,
  );
});

it("passage offsets identify exact verbatim text after whitespace trimming", () => {
  const source = "\n  # Unicode evidence 🌍\n\n" + markdown.repeat(3) + "\n  ";
  const chunks = passages(source, "https://example.org/evidence");
  expect(chunks.length).toBeGreaterThan(1);
  for (const passage of chunks)
    expect(source.slice(passage.start, passage.end)).toBe(passage.text);
});
