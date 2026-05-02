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

function landingPage(): Response {
  const html = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>agentsweb.org</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #0a0a0a; color: #e0e0e0; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
    .container { max-width: 640px; padding: 2rem; }
    h1 { font-size: 2rem; font-weight: 700; margin-bottom: 0.5rem; color: #fff; }
    .subtitle { color: #888; margin-bottom: 2rem; font-size: 1.1rem; }
    .endpoint { background: #161616; border: 1px solid #2a2a2a; border-radius: 8px; padding: 1rem 1.25rem; margin-bottom: 1rem; }
    .method { font-weight: 700; font-size: 0.8rem; display: inline-block; padding: 2px 8px; border-radius: 4px; margin-right: 8px; }
    .get { background: #1a3a2a; color: #4ade80; }
    .put { background: #3a2a1a; color: #fbbf24; }
    .post { background: #1a2a3a; color: #60a5fa; }
    .path { font-family: monospace; color: #ccc; }
    .desc { color: #888; font-size: 0.9rem; margin-top: 0.5rem; }
    a { color: #60a5fa; text-decoration: none; }
    a:hover { text-decoration: underline; }
    .footer { margin-top: 2rem; color: #555; font-size: 0.85rem; }
  </style>
</head>
<body>
  <div class="container">
    <h1>agentsweb.org</h1>
    <p class="subtitle">The web, cached as clean markdown for AI agents.</p>
    <div class="endpoint">
      <span class="method get">GET</span>
      <span class="path">/?url={url}</span>
      <p class="desc">Read cached markdown for a URL.</p>
    </div>
    <div class="endpoint">
      <span class="method put">PUT</span>
      <span class="path">/</span>
      <p class="desc">Contribute cached markdown. Body: { url, markdown, source }</p>
    </div>
    <div class="endpoint">
      <span class="method post">POST</span>
      <span class="path">/confirm</span>
      <p class="desc">Confirm a cached entry matches your local fetch. Body: { url, content_hash }</p>
    </div>
    <div class="endpoint">
      <span class="method get">GET</span>
      <span class="path">/stats</span>
      <p class="desc">Public cache statistics.</p>
    </div>
    <p class="footer">Powered by <a href="https://github.com/bighippoman/intercept-mcp">intercept-mcp</a>. Self-healing consensus cache.</p>
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
      return landingPage();
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
