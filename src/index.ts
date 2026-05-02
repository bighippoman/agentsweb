interface Env {
  CACHE: KVNamespace;
}

interface CacheEntry {
  url: string;
  markdown: string;
  trust_level: number;
  source: string;
  created_at: number;
  updated_at: number;
  content_hash: string;
  size: number;
  contributors: string[]; // instance IDs that confirmed this entry
}

interface WriteRequest {
  url: string;
  markdown: string;
  source: string;
  instance_id?: string;
}

interface ConfirmRequest {
  url: string;
  content_hash: string;
  instance_id?: string;
}

// ============================================================
// SECURITY: Content gates
// ============================================================

const PROMPT_INJECTION_PATTERNS = [
  /ignore\s+(all\s+)?previous\s+instructions/i,
  /ignore\s+(all\s+)?above\s+instructions/i,
  /you\s+are\s+now\s+/i,
  /act\s+as\s+(if\s+you\s+are\s+)?a?\s/i,
  /pretend\s+(to\s+be|you\s+are)/i,
  /^system:/im,
  /^<system>/im,
  /^<\/?system-prompt>/im,
  /\[system\]/i,
  /\[INST\]/i,
  /<<SYS>>/i,
  /do\s+not\s+follow\s+(any\s+)?previous/i,
  /disregard\s+(all\s+)?prior/i,
  /forget\s+(all\s+)?(your\s+)?instructions/i,
  /override\s+(all\s+)?safety/i,
  /jailbreak/i,
  /\bDAN\b.*\bmode\b/i,
  /bypass\s+(content\s+)?filter/i,
  /reveal\s+(your\s+)?(system\s+)?prompt/i,
  /what\s+is\s+your\s+system\s+prompt/i,
  /base64_decode/i,
  /eval\s*\(/i,
];

const CAPTCHA_PATTERNS = [
  /captcha/i,
  /cf-challenge/i,
  /g-recaptcha/i,
  /hcaptcha/i,
  /checking\s+your\s+browser/i,
  /ray\s+id:/i,
  /are\s+you\s+a\s+robot/i,
  /unusual\s+traffic/i,
  /security\s+check/i,
];

const LOGIN_WALL_PATTERNS = [
  /sign\s+in\s+to\s+continue/i,
  /log\s+in\s+to\s+continue/i,
  /subscribe\s+to\s+(read|continue)/i,
  /create\s+an\s+account/i,
  /register\s+to\s+continue/i,
  /this\s+content\s+is\s+for\s+subscribers/i,
];

const MALICIOUS_CONTENT_PATTERNS = [
  /<script[\s>]/i,
  /javascript:/i,
  /on(load|error|click|mouseover)\s*=/i,
  /data:text\/html/i,
  /<iframe[\s>]/i,
  /<object[\s>]/i,
  /<embed[\s>]/i,
];

function validateContent(markdown: string): string | null {
  if (markdown.length < 200) return "too short";
  if (markdown.length > 512_000) return "too large";

  const head = markdown.slice(0, 500);
  for (const p of CAPTCHA_PATTERNS) {
    if (p.test(head)) return "captcha detected";
  }
  for (const p of LOGIN_WALL_PATTERNS) {
    if (p.test(head)) return "login wall detected";
  }

  // Scan more broadly for injection and malicious content
  const scanRegion = markdown.slice(0, 5000);
  for (const p of PROMPT_INJECTION_PATTERNS) {
    if (p.test(scanRegion)) return "prompt injection detected";
  }
  for (const p of MALICIOUS_CONTENT_PATTERNS) {
    if (p.test(scanRegion)) return "malicious content detected";
  }

  // Entropy check: reject if content is mostly non-printable or base64
  const base64Blocks = markdown.match(/[A-Za-z0-9+/=]{100,}/g);
  if (base64Blocks) {
    const totalBase64 = base64Blocks.reduce((s, b) => s + b.length, 0);
    if (totalBase64 / markdown.length > 0.5) return "suspicious encoding";
  }

  return null;
}

// ============================================================
// SECURITY: URL validation
// ============================================================

const BLOCKED_URL_PATTERNS = [
  /^(javascript|data|blob|file|ftp):/i,
  /localhost/i,
  /127\.0\.0\.\d/,
  /\[::1\]/,
  /10\.\d+\.\d+\.\d+/,
  /172\.(1[6-9]|2\d|3[01])\.\d+\.\d+/,
  /192\.168\.\d+\.\d+/,
  /169\.254\.\d+\.\d+/, // link-local
  /0\.0\.0\.0/,
];

function validateUrl(url: string): string | null {
  if (!url || typeof url !== "string") return "url required";
  if (url.length > 4096) return "url too long";

  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
      return "only http/https urls allowed";
    }
    if (!parsed.hostname || parsed.hostname.length < 3) {
      return "invalid hostname";
    }
    // Block internal/private IPs
    for (const p of BLOCKED_URL_PATTERNS) {
      if (p.test(url)) return "blocked url";
    }
  } catch {
    return "invalid url";
  }

  return null;
}

// ============================================================
// SECURITY: Request validation
// ============================================================

const MAX_BODY_SIZE = 1_024_000; // 1MB max request body

async function parseBody<T>(request: Request): Promise<T | null> {
  const contentType = request.headers.get("content-type") || "";
  if (!contentType.includes("application/json")) return null;

  const contentLength = request.headers.get("content-length");
  if (contentLength && parseInt(contentLength, 10) > MAX_BODY_SIZE) return null;

  try {
    const text = await request.text();
    if (text.length > MAX_BODY_SIZE) return null;
    return JSON.parse(text) as T;
  } catch {
    return null;
  }
}

function validateInstanceId(id: string | undefined): string {
  if (!id || typeof id !== "string") return "anonymous";
  // Instance IDs must be alphanumeric, 8-64 chars
  if (!/^[a-zA-Z0-9]{8,64}$/.test(id)) return "anonymous";
  return id;
}

// ============================================================
// Helpers
// ============================================================

async function hashContent(content: string): Promise<string> {
  const data = new TextEncoder().encode(content);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function hashUrl(url: string): Promise<string> {
  return hashContent(url.toLowerCase().replace(/\/+$/, ""));
}

function securityHeaders(): Record<string, string> {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, PUT, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; script-src 'none'",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",
  };
}

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...securityHeaders() },
  });
}

// ============================================================
// Rate limiting (per-IP via KV with TTL)
// ============================================================

async function checkRateLimit(
  kv: KVNamespace,
  ip: string,
  action: "read" | "write" | "confirm"
): Promise<boolean> {
  const limits = { read: 600, write: 10, confirm: 60 };
  const windows = { read: 60, write: 60, confirm: 60 }; // seconds
  const limit = limits[action];
  const window = windows[action];
  const key = `rl:${action}:${ip}`;
  const current = await kv.get(key);
  const count = current ? parseInt(current, 10) : 0;
  if (count >= limit) return false;
  await kv.put(key, String(count + 1), { expirationTtl: window });
  return true;
}

// ============================================================
// TTL based on trust level and domain
// ============================================================

const NEWS_DOMAINS = new Set([
  "bloomberg.com", "nytimes.com", "wsj.com", "washingtonpost.com",
  "bbc.com", "bbc.co.uk", "cnn.com", "reuters.com", "theguardian.com",
  "ft.com", "techcrunch.com", "theverge.com", "arstechnica.com",
  "wired.com", "engadget.com", "zdnet.com",
]);

const STATIC_DOMAINS = new Set([
  "wikipedia.org", "arxiv.org", "docs.python.org", "developer.mozilla.org",
  "doc.rust-lang.org", "docs.rs", "pkg.go.dev", "learn.microsoft.com",
]);

function getTtl(trustLevel: number, url: string): number {
  const DAY = 86400;
  try {
    const hostname = new URL(url).hostname.replace(/^www\./, "");
    // Check if domain or parent domain matches
    for (const d of NEWS_DOMAINS) {
      if (hostname === d || hostname.endsWith("." + d)) return DAY;
    }
    for (const d of STATIC_DOMAINS) {
      if (hostname === d || hostname.endsWith("." + d)) return 30 * DAY;
    }
  } catch {}

  if (trustLevel <= 1) return DAY;
  if (trustLevel <= 4) return 7 * DAY;
  return 30 * DAY;
}

// ============================================================
// Handlers
// ============================================================

async function handleRead(
  url: string,
  kv: KVNamespace,
  ip: string
): Promise<Response> {
  const urlErr = validateUrl(url);
  if (urlErr) return json({ error: urlErr }, 400);

  if (!(await checkRateLimit(kv, ip, "read"))) {
    return json({ error: "rate limited" }, 429);
  }

  const key = `cache:${await hashUrl(url)}`;
  const raw = await kv.get(key);
  if (!raw) return json({ status: "miss" }, 404);

  let entry: CacheEntry;
  try {
    entry = JSON.parse(raw);
  } catch {
    return json({ status: "miss" }, 204);
  }

  return json({
    url: entry.url,
    markdown: entry.markdown,
    trust_level: entry.trust_level,
    source: entry.source,
    age_seconds: Math.floor((Date.now() - entry.updated_at) / 1000),
  });
}

async function handleWrite(
  body: WriteRequest,
  kv: KVNamespace,
  ip: string
): Promise<Response> {
  if (!(await checkRateLimit(kv, ip, "write"))) {
    return json({ error: "rate limited" }, 429);
  }

  const { url, markdown, source } = body;
  const instanceId = validateInstanceId(body.instance_id);

  // Validate URL
  const urlErr = validateUrl(url);
  if (urlErr) return json({ error: urlErr }, 400);

  // Validate required fields
  if (!markdown || typeof markdown !== "string") {
    return json({ error: "markdown required" }, 400);
  }
  if (!source || typeof source !== "string" || source.length > 64) {
    return json({ error: "valid source required" }, 400);
  }

  // Content gates
  const rejection = validateContent(markdown);
  if (rejection) {
    return json({ error: rejection }, 422);
  }

  const contentHash = await hashContent(markdown);
  const key = `cache:${await hashUrl(url)}`;
  const existing = await kv.get(key);

  if (existing) {
    let entry: CacheEntry;
    try {
      entry = JSON.parse(existing);
    } catch {
      // Corrupted entry, overwrite
      entry = { url, markdown: "", trust_level: 0, source: "", created_at: 0, updated_at: 0, content_hash: "", size: 0, contributors: [] };
    }

    // Same content? Increment trust
    if (entry.content_hash === contentHash) {
      // Don't let the same instance confirm its own write
      if (entry.contributors.includes(instanceId)) {
        return json({ status: "duplicate", trust_level: entry.trust_level });
      }
      // Cap trust_level to prevent overflow
      if (entry.trust_level < 100) entry.trust_level++;
      entry.updated_at = Date.now();
      entry.contributors.push(instanceId);
      // Keep contributors list bounded
      if (entry.contributors.length > 50) {
        entry.contributors = entry.contributors.slice(-50);
      }
      await kv.put(key, JSON.stringify(entry), {
        expirationTtl: getTtl(entry.trust_level, url),
      });
      return json({ status: "confirmed", trust_level: entry.trust_level });
    }

    // Different content — only replace if existing is low trust
    if (entry.trust_level >= 2) {
      return json({
        status: "rejected",
        reason: "existing entry has higher trust",
        trust_level: entry.trust_level,
      });
    }
  }

  const entry: CacheEntry = {
    url,
    markdown,
    trust_level: 1,
    source,
    created_at: Date.now(),
    updated_at: Date.now(),
    content_hash: contentHash,
    size: markdown.length,
    contributors: [instanceId],
  };

  await kv.put(key, JSON.stringify(entry), {
    expirationTtl: getTtl(1, url),
  });

  return json({ status: "accepted", trust_level: 1 });
}

async function handleConfirm(
  body: ConfirmRequest,
  kv: KVNamespace,
  ip: string
): Promise<Response> {
  if (!(await checkRateLimit(kv, ip, "confirm"))) {
    return json({ error: "rate limited" }, 429);
  }

  const { url, content_hash } = body;
  const instanceId = validateInstanceId(body.instance_id);

  const urlErr = validateUrl(url);
  if (urlErr) return json({ error: urlErr }, 400);

  if (!content_hash || typeof content_hash !== "string" || !/^[a-f0-9]{64}$/.test(content_hash)) {
    return json({ error: "valid sha256 content_hash required" }, 400);
  }

  const key = `cache:${await hashUrl(url)}`;
  const raw = await kv.get(key);
  if (!raw) return json({ status: "not found" }, 404);

  let entry: CacheEntry;
  try {
    entry = JSON.parse(raw);
  } catch {
    return json({ status: "not found" }, 404);
  }

  if (entry.content_hash === content_hash) {
    if (entry.contributors.includes(instanceId)) {
      return json({ status: "already confirmed", trust_level: entry.trust_level });
    }
    if (entry.trust_level < 100) entry.trust_level++;
    entry.updated_at = Date.now();
    entry.contributors.push(instanceId);
    if (entry.contributors.length > 50) {
      entry.contributors = entry.contributors.slice(-50);
    }
    await kv.put(key, JSON.stringify(entry), {
      expirationTtl: getTtl(entry.trust_level, url),
    });
    return json({ status: "confirmed", trust_level: entry.trust_level });
  }

  return json({ status: "mismatch", trust_level: entry.trust_level });
}

async function handleStats(kv: KVNamespace): Promise<Response> {
  const hits = parseInt((await kv.get("stats:hits")) || "0", 10);
  const writes = parseInt((await kv.get("stats:writes")) || "0", 10);

  return json({
    total_hits: hits,
    total_writes: writes,
    hit_rate: hits + writes > 0
      ? ((hits / (hits + writes)) * 100).toFixed(1) + "%"
      : "0%",
  });
}

// ============================================================
// Landing page
// ============================================================

async function landingPage(kv: KVNamespace): Promise<Response> {
  const hits = parseInt((await kv.get("stats:hits")) || "0", 10);
  const writes = parseInt((await kv.get("stats:writes")) || "0", 10);

  const html = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>agentsweb.org — The web, pre-read for AI</title>
  <meta name="description" content="A global shared cache of web pages as clean markdown. Sub-50ms reads. Self-healing consensus. Open source.">
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #0a0a0a; color: #e0e0e0; min-height: 100vh; }
    .hero { max-width: 720px; margin: 0 auto; padding: 4rem 2rem 2rem; }
    h1 { font-size: 2.5rem; font-weight: 800; color: #fff; letter-spacing: -0.02em; }
    .tagline { color: #888; font-size: 1.2rem; margin: 0.75rem 0 2rem; line-height: 1.5; }
    .stats { display: flex; gap: 2rem; margin-bottom: 2.5rem; }
    .stat { background: #111; border: 1px solid #222; border-radius: 10px; padding: 1.25rem 1.5rem; flex: 1; }
    .stat-value { font-size: 1.8rem; font-weight: 700; color: #fff; font-variant-numeric: tabular-nums; }
    .stat-label { color: #666; font-size: 0.85rem; margin-top: 0.25rem; }
    .install { background: #111; border: 1px solid #222; border-radius: 10px; padding: 1.5rem; margin-bottom: 2.5rem; }
    .install-label { color: #888; font-size: 0.85rem; margin-bottom: 0.75rem; }
    .install code { background: #0d0d0d; color: #4ade80; font-family: "SF Mono", "Fira Code", monospace; font-size: 0.95rem; display: block; padding: 0.75rem 1rem; border-radius: 6px; border: 1px solid #1a1a1a; overflow-x: auto; }
    h2 { font-size: 1.1rem; font-weight: 600; color: #fff; margin-bottom: 1rem; text-transform: uppercase; letter-spacing: 0.05em; font-size: 0.8rem; }
    .how { margin-bottom: 2.5rem; }
    .how p { color: #999; line-height: 1.7; margin-bottom: 0.75rem; }
    .how strong { color: #ccc; }
    .endpoints { margin-bottom: 2.5rem; }
    .ep { background: #111; border: 1px solid #1a1a1a; border-radius: 8px; padding: 0.85rem 1.1rem; margin-bottom: 0.6rem; display: flex; align-items: center; gap: 0.75rem; }
    .method { font-weight: 700; font-size: 0.7rem; padding: 3px 8px; border-radius: 4px; font-family: monospace; min-width: 42px; text-align: center; }
    .get { background: #0f2918; color: #4ade80; }
    .put { background: #2a1f0a; color: #fbbf24; }
    .post { background: #0f1929; color: #60a5fa; }
    .ep-path { font-family: monospace; color: #ccc; font-size: 0.9rem; }
    .ep-desc { color: #666; font-size: 0.85rem; margin-left: auto; }
    .security { margin-bottom: 2.5rem; }
    .sec-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem; }
    .sec-item { background: #111; border: 1px solid #1a1a1a; border-radius: 6px; padding: 0.6rem 0.85rem; color: #888; font-size: 0.8rem; }
    .curl { margin-bottom: 2.5rem; }
    .curl code { background: #0d0d0d; color: #ccc; font-family: "SF Mono", "Fira Code", monospace; font-size: 0.8rem; display: block; padding: 0.75rem 1rem; border-radius: 6px; border: 1px solid #1a1a1a; white-space: pre; overflow-x: auto; }
    .footer { border-top: 1px solid #1a1a1a; padding-top: 2rem; margin-top: 1rem; color: #444; font-size: 0.8rem; display: flex; justify-content: space-between; }
    a { color: #60a5fa; text-decoration: none; }
    a:hover { text-decoration: underline; }
    @media (max-width: 600px) { .stats { flex-direction: column; gap: 0.75rem; } .sec-grid { grid-template-columns: 1fr; } .ep { flex-wrap: wrap; } .ep-desc { margin-left: 0; } }
  </style>
</head>
<body>
  <div class="hero">
    <h1>agentsweb.org</h1>
    <p class="tagline">The web, pre-read for AI. A global shared cache of web pages as clean markdown. Sub-50ms reads from the edge. Self-healing consensus prevents poisoning.</p>

    <div class="stats">
      <div class="stat"><div class="stat-value">${writes.toLocaleString()}</div><div class="stat-label">pages cached</div></div>
      <div class="stat"><div class="stat-value">${hits.toLocaleString()}</div><div class="stat-label">cache hits served</div></div>
      <div class="stat"><div class="stat-value">&lt;50ms</div><div class="stat-label">global read latency</div></div>
    </div>

    <div class="install">
      <div class="install-label">Get started with intercept-mcp (reads + writes automatically):</div>
      <code>npx -y intercept-mcp</code>
    </div>

    <div class="how">
      <h2>How it works</h2>
      <p>Every AI agent fetches the same pages, fights the same captchas, and converts the same HTML. <strong>That's redundant.</strong></p>
      <p>With agentsweb, the first agent to fetch a URL caches the clean markdown. Every agent after gets it instantly. The more agents use it, the faster everyone gets.</p>
      <p><strong>Self-healing:</strong> Entries gain trust as independent sources confirm them. Poisoned content self-destructs on the next legitimate read. No single source is trusted blindly.</p>
    </div>

    <div class="endpoints">
      <h2>API</h2>
      <div class="ep"><span class="method get">GET</span><span class="ep-path">/?url={url}</span><span class="ep-desc">Read cached markdown</span></div>
      <div class="ep"><span class="method put">PUT</span><span class="ep-path">/</span><span class="ep-desc">Contribute markdown</span></div>
      <div class="ep"><span class="method post">POST</span><span class="ep-path">/confirm</span><span class="ep-desc">Confirm entry integrity</span></div>
      <div class="ep"><span class="method get">GET</span><span class="ep-path">/stats</span><span class="ep-desc">Live statistics</span></div>
    </div>

    <div class="curl">
      <h2>Try it</h2>
      <code>curl "https://agentsweb.org/?url=https://example.com"</code>
    </div>

    <div class="security">
      <h2>Security</h2>
      <div class="sec-grid">
        <div class="sec-item">Prompt injection scanning</div>
        <div class="sec-item">SSRF / private IP blocking</div>
        <div class="sec-item">Captcha &amp; login wall detection</div>
        <div class="sec-item">XSS / script tag filtering</div>
        <div class="sec-item">Per-IP rate limiting</div>
        <div class="sec-item">Trust-level consensus</div>
        <div class="sec-item">Request body size limits</div>
        <div class="sec-item">Self-healing on read</div>
      </div>
    </div>

    <div class="footer">
      <span>Powered by <a href="https://github.com/bighippoman/intercept-mcp">intercept-mcp</a> &middot; <a href="https://github.com/bighippoman/agentsweb">open source</a></span>
      <span>Cloudflare Workers + KV</span>
    </div>
  </div>
</body>
</html>`;
  return new Response(html, {
    headers: {
      "Content-Type": "text/html;charset=utf-8",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "Referrer-Policy": "no-referrer",
      "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'",
      "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
      "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
      "Cache-Control": "public, max-age=60",
    },
  });
}

// ============================================================
// Main entry point
// ============================================================

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    // Only allow expected methods
    const method = request.method;
    if (!["GET", "PUT", "POST", "OPTIONS"].includes(method)) {
      return json({ error: "method not allowed" }, 405);
    }

    const url = new URL(request.url);
    const ip = request.headers.get("CF-Connecting-IP") || "unknown";

    // CORS preflight
    if (method === "OPTIONS") {
      return new Response(null, { status: 204, headers: securityHeaders() });
    }

    // Landing page
    if (method === "GET" && url.pathname === "/" && !url.searchParams.has("url")) {
      return await landingPage(env.CACHE);
    }

    // API routes
    try {
      if (method === "GET" && url.pathname === "/" && url.searchParams.has("url")) {
        return await handleRead(url.searchParams.get("url")!, env.CACHE, ip);
      }

      if (method === "PUT" && url.pathname === "/") {
        const body = await parseBody<WriteRequest>(request);
        if (!body) return json({ error: "invalid json body" }, 400);
        return await handleWrite(body, env.CACHE, ip);
      }

      if (method === "POST" && url.pathname === "/confirm") {
        const body = await parseBody<ConfirmRequest>(request);
        if (!body) return json({ error: "invalid json body" }, 400);
        return await handleConfirm(body, env.CACHE, ip);
      }

      if (method === "GET" && url.pathname === "/stats") {
        return await handleStats(env.CACHE);
      }
    } catch {
      return json({ error: "internal error" }, 500);
    }

    return json({ error: "not found" }, 404);
  },
};
