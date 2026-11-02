import { siteStyle } from "./site-style.js";
import { siteScript } from "./site-client.js";
export { siteStyle, siteScript };

const github = "https://github.com/bighippoman/agentsweb";
const intercept = "https://github.com/bighippoman/intercept-mcp";
const nav = `<a class="brand" href="/" aria-label="agentsweb home"><span class="brand-mark" aria-hidden="true">a<span>↗</span></span>agentsweb<span class="brand-dot">.</span></a><nav aria-label="Main navigation"><a href="/docs">Documentation</a><a href="${github}">GitHub ↗</a><a class="nav-install" href="/integrations">Install Intercept <span>↗</span></a></nav>`;
const install = `<section id="install" class="install-section"><div><span class="eyebrow">YOUR TOOLS. BETTER SOURCES.</span><h2>Put it to work.</h2><p>Use the public API from any application, or give your MCP client the complete Intercept toolkit.</p></div><div class="install-options"><article><span class="step">01 / FOR YOUR AGENT</span><h3>Install Intercept</h3><p>Search, fetch, research, batch requests, and structured extraction in one MCP server.</p><div class="command"><code>npx -y intercept-mcp</code><button class="copy-command" aria-label="Copy Intercept command">Copy</button></div><a class="text-link" href="/integrations">Client setup & configuration →</a></article><article><span class="step">02 / FOR YOUR APPLICATION</span><h3>Call the API</h3><p>Get readable Markdown and source evidence. Public requests need no API key.</p><pre><code>GET https://agentsweb.org/fetch
    ?url=https://react.dev/learn</code></pre><a class="text-link" href="/docs">Explore the API →</a></article></div></section>`;
const home = `<section class="hero"><div class="hero-copy"><p class="eyebrow"><span class="status-dot"></span> THE OPEN WEB, READY FOR AGENTS</p><h1>Less noise.<br>More <span>source.</span></h1><p class="intro">Turn web pages into readable Markdown. Find relevant passages. Give your agent the source, the timestamp, and the full picture.</p><div class="hero-actions"><a class="button primary" href="#playground">Try a real request <span>↘</span></a><a class="text-link" href="/integrations">Install Intercept ↗</a></div><p class="quiet">Open source. Public API. No account required.</p><div class="source-flow" aria-label="A web page becomes readable content with source evidence"><div><span>01</span>Web page</div><b>→</b><div><span>02</span>Readable content</div><b>→</b><div class="flow-last"><span>03</span>Source evidence</div></div></div>
<section class="playground" id="playground" aria-labelledby="playground-title"><div class="panel-heading"><h2 id="playground-title">Try agentsweb</h2><span class="live-tag"><i></i> Live requests</span></div><div class="mode-tabs" role="group" aria-label="Request type"><button data-mode="fetch" aria-pressed="true">Fetch a page</button><button data-mode="ask" aria-pressed="false">Search the cache</button><button data-mode="research" aria-pressed="false">Research</button></div><form id="request-form"><label id="input-label" for="request-input">Page URL</label><div class="input-row"><input id="request-input" name="request" type="url" required value="https://react.dev/reference/react/useState" spellcheck="false"><button class="button primary" id="run" type="submit" aria-label="Run request">Run <span>↗</span></button></div><div class="examples"><span>Try</span><button type="button" data-example="react">React docs</button><button type="button" data-example="python">Python tutorial</button><button id="cancel" type="button" hidden>Cancel request</button></div></form><div class="output-toolbar"><span id="request-status" role="status" aria-live="polite">Ready when you are</span><div><button id="view-readable" aria-pressed="true">Readable</button><button id="view-json" aria-pressed="false">JSON</button><button id="copy-output" aria-label="Copy response" disabled>Copy</button></div></div><div id="evidence" class="evidence" hidden></div><div id="output" class="output" aria-live="polite"><div class="empty-state"><div class="document-icon" aria-hidden="true"><span></span><span></span><span></span><b>↗</b></div><h3>Your next source starts here.</h3><p>Run a request to see the actual content,<br>where it came from, and when it was retrieved.</p><span class="empty-note">Inspect readable content and the evidence behind it.</span></div></div></section></section>
<section class="evidence-strip" aria-label="Response capabilities"><p><span class="strip-label">BUILT FOR FOLLOW-THROUGH</span>Every response should help you decide what to trust.</p><div><b>Source URL</b><span>Trace it back</span></div><div><b>Retrieval time</b><span>Check its age</span></div><div><b>Completeness</b><span>Know what is missing</span></div></section>
<section class="workflow"><div class="section-heading"><span class="eyebrow">ONE REQUEST. A USEFUL RESULT.</span><h2>From a page to something<br>your agent can work with.</h2></div><div class="workflow-rows"><article><span>01</span><h3>Read what matters.</h3><p>Native Markdown first, then readable HTML. Browser rendering and hosted retrieval help when a page needs more work.</p></article><article><span>02</span><h3>Find the right passage.</h3><p>Search the full indexed text across cached pages. Get relevant excerpts with links back to the source.</p></article><article><span>03</span><h3>Keep the evidence attached.</h3><p>Retrieval timestamps, content hashes, and completeness travel with the response. Historical snapshots are explicitly labeled.</p></article></div></section>${install}`;

const docs = `<div class="page-heading"><span class="eyebrow">DOCUMENTATION / API V2</span><h1>A clearer path<br>to the source.</h1><p>Plain HTTP. JSON and Markdown. No public API key required.</p></div><div class="docs-layout"><aside class="docs-nav"><a href="#fetch">Fetch a page</a><a href="#search">Search & research</a><a href="#cache">Read the cache</a><a href="#contribute">Contribute</a><a href="#evidence">Response evidence</a><a href="#limits">Limits & errors</a></aside><div class="prose"><section id="fetch"><h2>Fetch a readable page</h2><p><code>/fetch</code> uses a fresh cached result when available, then retrieves a public page. Live sources run before archives.</p><pre>curl -G 'https://agentsweb.org/fetch' \
  --data-urlencode 'url=https://react.dev/learn' \
  --data-urlencode 'max_age=3600'</pre><table><tr><th>Parameter</th><th>Behavior</th></tr><tr><td>url</td><td>Required public HTTP or HTTPS URL.</td></tr><tr><td>max_age</td><td>Oldest acceptable retrieval in seconds. Default 3600; 0 forces retrieval.</td></tr><tr><td>max_tokens</td><td>Optional approximate output budget. A shortened response has truncated=true and completeness=partial.</td></tr><tr><td>section / toc</td><td>Return a matching heading section, or use toc=true for headings.</td></tr><tr><td>allow_archive</td><td>Set true to permit a labeled historical snapshot after live retrieval fails.</td></tr></table></section>
<section id="search"><h2>Find passages. Explore a topic.</h2><p><code>/ask?q=react+useState</code> searches the cached full-text index and returns verbatim passages with citation URLs. It does not generate an answer or search every page on the internet.</p><p><code>/web?q=...&count=5</code> uses external search engines, with the cached index as a labeled fallback. <code>/research?q=...&count=3</code> retrieves the results and attaches source evidence.</p><p><code>/context?q=...</code> combines indexed passages into a briefing. <code>/chunks?url=...&q=...</code> finds passages within one cached page. Empty results mean no matching indexed text.</p></section>
<section id="cache"><h2>Read cached content</h2><pre>GET /?url=...&max_age=3600
GET /raw?url=...&max_age=3600
GET /batch?urls=https://example.org/a,https://example.org/b
GET /search?q=example.org
GET /changes?url=...</pre><p>Cache-only reads return 404 when content is missing or too old, and may queue a refresh. Use <code>/fetch</code> when you need retrieval in the same request. JSON representations support ETags. Raw reads return <code>text/markdown</code>.</p><p>URL identity preserves functional parameters, path case, www, scheme, and trailing slashes. Known campaign parameters are removed. Signed URLs and credentials are rejected by this public service.</p></section>
<section id="contribute"><h2>Suggest a page for refresh</h2><p><code>PUT /</code> accepts <code>{"url":"…","markdown":"…","source":"…"}</code> and returns <strong>202 pending_verification</strong>. Contributions are refresh hints: the service retrieves public source content before publishing a replacement.</p><p><code>POST /confirm</code> compares a URL and SHA-256 content_hash. A confirmation does not reset retrieval time, extend freshness, or prove the source is correct. A mismatch queues revalidation.</p></section>
<section id="evidence"><h2>Read the evidence</h2><pre>{
  "url": "https://example.org/article",
  "source": "native-markdown",
  "source_kind": "live",
  "completeness": "complete",
  "retrieved_at": "…",
  "verified_at": "…",
  "content_hash": "…",
  "age_seconds": 42,
  "truncated": false
}</pre><p>This is a schema example. <code>verified_at</code> means a direct origin retrieval; it is null for hosted extraction. “Complete” means the extraction was not intentionally shortened or identified as a partial result. It is not a guarantee that a site exposed all its content. Retrieved pages remain untrusted input.</p></section>
<section id="limits"><h2>Limits & errors</h2><p>Per IP, per minute: 600 reads, 30 fetch/research requests, 10 writes. A retrieval has a 25-second budget. Responses are bounded to 5 MB before conversion and 1 MB of extracted text. Research returns up to five sources, with a 24,000-character display budget per source.</p><table><tr><th>Status</th><th>Meaning</th></tr><tr><td>202</td><td>Refresh queued; verification is pending.</td></tr><tr><td>400 / 422</td><td>Invalid input or insufficient readable content.</td></tr><tr><td>404</td><td>Missing or stale cache entry.</td></tr><tr><td>429</td><td>Rate limited; respect Retry-After.</td></tr><tr><td>451</td><td>Removed or opted out.</td></tr><tr><td>502</td><td>No readable public content was retrieved.</td></tr></table><p>Browser rendering and external search can be unavailable. We report failures and partial results explicitly. See <a href="/security">security and content handling</a>.</p></section></div></div>`;
const integrations = `<div class="page-heading"><span class="eyebrow">INTERCEPT + AGENTSWEB</span><h1>The web, in<br>your agent’s toolkit.</h1><p>Intercept is the MCP client-side toolkit. agentsweb provides its shared public cache and indexed passages.</p></div><div class="prose wide"><h2>Start Intercept</h2><p>Use Node.js 22.18 or newer. Add this server to an MCP-compatible client:</p><pre>{
  "mcpServers": {
    "intercept": {
      "command": "npx",
      "args": ["-y", "intercept-mcp"]
    }
  }
}</pre><p>For Codex CLI:</p><pre>codex mcp add intercept -- npx -y intercept-mcp</pre><h2>Five tools. One workflow.</h2><p><code>search</code> finds sources; <code>fetch</code> reads a page; <code>fetch_batch</code> reads several. <code>research</code> combines discovery and retrieval. <code>extract</code> returns selected fields and tables. Use the repository documentation for the current tool list and configuration.</p><p>Intercept supports per-domain authentication for local retrieval. Credentialed requests stay out of agentsweb’s public cache. Configure private access in your local client, never in the playground.</p><a class="button primary" href="${intercept}">Intercept documentation ↗</a></div>`;
const pages: Record<string, { title: string; body: string }> = {
  "/docs": { title: "API documentation", body: docs },
  "/integrations": { title: "Install Intercept", body: integrations },
  "/about": {
    title: "About agentsweb",
    body:
      '<h1>An open bridge<br>to the web.</h1><p>agentsweb turns public web pages into readable content and a searchable shared cache. It works alongside Intercept, an open-source MCP toolkit for web retrieval.</p><h2>Useful output, visible evidence.</h2><p>We aim to make retrieval easier to inspect: source URLs, timestamps, hashes, and clear partial-result labels. Cached pages can change. External services can fail. These limits should be visible to the agent using the result.</p><p><a href="' +
      github +
      '">Explore agentsweb on GitHub ↗</a></p>',
  },
  "/security": {
    title: "Content and security",
    body: "<h1>Evidence over<br>assumptions.</h1><p>Every fetched page is untrusted third-party content. Quality heuristics catch some challenge pages and repetitive text; they are not a guarantee against prompt injection. Agents must treat retrieved instructions as data.</p><h2>Public content only</h2><p>The service rejects credentialed and signed URLs, checks redirect destinations, honors robots.txt, and respects owner removals. It does not retrieve private accounts or accept arbitrary submitted text as verified source content.</p><h2>Freshness and integrity</h2><p>Document metadata and search updates are transactional. A content hash identifies the retrieved version. Confirmations do not refresh timestamps; changed contributions queue a new retrieval.</p><p>For removal requests or security reports, contact dmca@agentsweb.org.</p>",
  },
  "/privacy": {
    title: "Privacy",
    body: "<h1>Privacy.</h1><p>Updated November 2026.</p><p>Public URLs submitted to agentsweb may be retrieved, cached, and served publicly. Do not submit private content or secrets. The playground uses no advertising trackers and creates no account.</p><h2>Operational data</h2><p>Cloudflare processes network requests. Rate limiting uses short-lived hashed IP identifiers. Aggregate counters measure service usage. Sampled operational logs help diagnose errors. Owner removal records are retained to prevent removed content from returning.</p><h2>Cached content</h2><p>Current document entries expire after seven days without retrieval. Stored content versions expire after 30 days; scheduled cleanup removes old search records. Content owners can request removal at dmca@agentsweb.org.</p>",
  },
  "/terms": {
    title: "Terms",
    body: "<h1>Terms of use.</h1><p>Use agentsweb for lawful retrieval of public web content. Respect publishers’ rights and access restrictions. Do not submit credentials, private information, or material you are not entitled to share.</p><p>The service is provided as available. Content can be incomplete, outdated, or incorrect. Check the original source before relying on it. Public API limits and availability may change.</p><p>Third-party content remains the responsibility of its publishers. Contact dmca@agentsweb.org for removal requests.</p>",
  },
  "/dmca": {
    title: "Content removal",
    body: '<h1>Your content.<br>Your choice.</h1><p>To request removal or a domain opt-out, email <a href="mailto:dmca@agentsweb.org">dmca@agentsweb.org</a> with the affected URLs, your contact details, and evidence that you own or represent the content.</p><p>For copyright notices, include a description of the protected work, the infringing URLs, a statement of good-faith belief, a statement that the information is accurate and that you are authorized to act, and your signature.</p><p>Site operators can also disallow the <code>agentsweb</code> user agent in robots.txt. Approved removal requests block retrieval and remove content from the searchable index.</p>',
  },
};
const aliases: Record<string, string> = {
  "/how-it-works": "/docs",
  "/faq": "/docs",
  "/use-cases": "/integrations",
  "/compare": "/about",
  "/blog": "/about",
};
export function sitePage(path: string): Response | null {
  if (aliases[path])
    return new Response(null, {
      status: 301,
      headers: { Location: aliases[path] },
    });
  if (path !== "/" && !pages[path]) return null;
  const page = pages[path];
  const title = page
    ? `${page.title} · agentsweb`
    : "agentsweb — readable web content for AI agents";
  const body = path === "/" ? home : page.body;
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${title}</title><meta name="description" content="Read public web pages as Markdown. Search relevant passages with source URLs, retrieval timestamps, and clear completeness labels. Connect with Intercept MCP."><meta property="og:type" content="website"><meta property="og:title" content="${title}"><meta property="og:description" content="Readable web content and citable passages for AI agents."><meta property="og:url" content="https://agentsweb.org${path}"><meta property="og:image" content="https://agentsweb.org/og.svg"><meta name="theme-color" content="#f6f4ef"><link rel="canonical" href="https://agentsweb.org${path}"><link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Crect width='64' height='64' rx='14' fill='%23edae49'/%3E%3Ctext x='15' y='45' font-size='46' font-family='sans-serif' font-weight='700'%3Ea%3C/text%3E%3C/svg%3E"><link rel="stylesheet" href="/assets/site.css?v=2.0.0"><script defer src="/assets/site.js?v=2.0.0"></script></head><body><a class="skip-link" href="#main">Skip to content</a><header class="site-header">${nav}</header><main id="main" class="${path === "/" ? "home" : "page"}">${path === "/" || path === "/docs" || path === "/integrations" ? body : '<article class="prose wide">' + body + "</article>"}</main><footer><div><a class="brand" href="/">agentsweb<span class="brand-dot">.</span></a><p>Better inputs. Better agents.</p></div><nav aria-label="Footer"><a href="/about">About</a><a href="/security">Security</a><a href="/privacy">Privacy</a><a href="/terms">Terms</a><a href="/dmca">Content removal</a></nav><span>Open source, built for the open web.</span></footer></body></html>`;
  return new Response(html, {
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "public, max-age=300",
      "X-Content-Type-Options": "nosniff",
      "Content-Security-Policy":
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
      "Referrer-Policy": "strict-origin-when-cross-origin",
    },
  });
}
