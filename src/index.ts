interface Env {
  CACHE: KVNamespace;
  ADMIN_SECRET: string;
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
  contributors: string[];
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
// SECURITY: Prompt injection detection (deep scan)
// ============================================================

const PROMPT_INJECTION_PATTERNS = [
  // Direct instruction override
  /ignore\s+(all\s+)?previous\s+instructions/i,
  /ignore\s+(all\s+)?above\s+instructions/i,
  /ignore\s+(all\s+)?prior\s+instructions/i,
  /do\s+not\s+follow\s+(any\s+)?previous/i,
  /disregard\s+(all\s+)?(prior|previous)/i,
  /forget\s+(all\s+)?(your\s+)?instructions/i,
  /override\s+(all\s+)?(safety|instructions|rules)/i,
  /new\s+instructions?\s*:/i,

  // Role manipulation
  /you\s+are\s+now\s+/i,
  /act\s+as\s+(if\s+you\s+are\s+)?a?\s/i,
  /pretend\s+(to\s+be|you\s+are)/i,
  /roleplay\s+as/i,
  /simulate\s+being/i,
  /you\s+have\s+been\s+reprogrammed/i,

  // System prompt extraction
  /reveal\s+(your\s+)?(system\s+)?prompt/i,
  /what\s+(is|are)\s+your\s+(system\s+)?prompt/i,
  /show\s+(me\s+)?(your\s+)?(system\s+)?(prompt|instructions)/i,
  /repeat\s+(your\s+)?(system\s+)?(prompt|instructions)/i,
  /print\s+(your\s+)?(system\s+)?(prompt|instructions)/i,

  // Template/format tokens
  /^system:/im,
  /^<\/?system>/im,
  /^<\/?system-prompt>/im,
  /^<\/?system_message>/im,
  /\[system\]/i,
  /\[INST\]/i,
  /<<SYS>>/i,
  /\|\|system\|\|/i,
  /###\s*system/i,
  /```system/i,
  /<\|im_start\|>/i,
  /\[\/INST\]/i,

  // Jailbreak patterns
  /jailbreak/i,
  /\bDAN\b.*\b(mode|prompt)\b/i,
  /bypass\s+(content\s+)?filter/i,
  /bypass\s+(safety|security)/i,
  /developer\s+mode\s+(enabled|activated|on)/i,
  /god\s+mode/i,
  /unrestricted\s+mode/i,

  // Code execution
  /base64_decode/i,
  /eval\s*\(/i,
  /exec\s*\(/i,
  /import\s+os\b/i,
  /subprocess\./i,
  /__import__/i,
  /require\s*\(\s*['"]child_process/i,
];

// ============================================================
// SECURITY: Content validation
// ============================================================

const CAPTCHA_PATTERNS = [
  /captcha/i,
  /cf-challenge/i,
  /g-recaptcha/i,
  /hcaptcha/i,
  /checking\s+your\s+browser/i,
  /ray\s+id:/i,
  /are\s+you\s+a\s+robot/i,
  /unusual\s+traffic/i,
  /security\s+check\s+to\s+access/i,
  /please\s+verify\s+you\s+are\s+human/i,
];

const LOGIN_WALL_PATTERNS = [
  /sign\s+in\s+to\s+continue/i,
  /log\s+in\s+to\s+continue/i,
  /subscribe\s+to\s+(read|continue)/i,
  /create\s+an\s+account\s+to/i,
  /register\s+to\s+continue/i,
  /this\s+(content|article)\s+is\s+for\s+subscribers/i,
  /please\s+(log|sign)\s+in/i,
];

const MALICIOUS_CONTENT_PATTERNS = [
  /<script[\s>]/i,
  /javascript\s*:/i,
  /on(load|error|click|mouseover|mouseenter|focus|blur)\s*=/i,
  /data\s*:\s*text\/html/i,
  /<iframe[\s>]/i,
  /<object[\s>]/i,
  /<embed[\s>]/i,
  /<form[\s>].*action\s*=/i,
  /document\.(cookie|location|write)/i,
  /window\.(location|open)/i,
  /\.innerHTML\s*=/i,
  /fetch\s*\(\s*['"]https?:\/\//i,
];

// Unicode steganography — invisible characters used to hide payloads
const INVISIBLE_CHAR_REGEX = /[\u200B\u200C\u200D\u200E\u200F\u2060\u2061\u2062\u2063\u2064\uFEFF\u00AD]{3,}/;
const ZERO_WIDTH_DENSITY_THRESHOLD = 0.01; // >1% zero-width chars = suspicious

function validateContent(markdown: string): string | null {
  if (markdown.length < 200) return "too short";
  if (markdown.length > 512_000) return "too large";

  // Check for invisible character attacks
  if (INVISIBLE_CHAR_REGEX.test(markdown)) return "hidden characters detected";
  const invisibleCount = (markdown.match(/[\u200B-\u200F\u2060-\u2064\uFEFF]/g) || []).length;
  if (invisibleCount / markdown.length > ZERO_WIDTH_DENSITY_THRESHOLD) return "suspicious unicode";

  const head = markdown.slice(0, 500);
  for (const p of CAPTCHA_PATTERNS) {
    if (p.test(head)) return "captcha detected";
  }
  for (const p of LOGIN_WALL_PATTERNS) {
    if (p.test(head)) return "login wall detected";
  }

  // Scan broadly for injection and malicious content
  // Check first 10KB for injection (attackers might pad)
  const scanRegion = markdown.slice(0, 10_000);
  for (const p of PROMPT_INJECTION_PATTERNS) {
    if (p.test(scanRegion)) return "prompt injection detected";
  }

  // Also scan LAST 5KB (injection at end of content)
  const tail = markdown.slice(-5_000);
  for (const p of PROMPT_INJECTION_PATTERNS) {
    if (p.test(tail)) return "prompt injection detected (tail)";
  }

  for (const p of MALICIOUS_CONTENT_PATTERNS) {
    if (p.test(scanRegion)) return "malicious content detected";
  }

  // Entropy check: reject if content is mostly base64
  const base64Blocks = markdown.match(/[A-Za-z0-9+/=]{100,}/g);
  if (base64Blocks) {
    const totalBase64 = base64Blocks.reduce((s, b) => s + b.length, 0);
    if (totalBase64 / markdown.length > 0.4) return "suspicious encoding";
  }

  // Repetition check: reject if same line repeated many times (padding attack)
  const lines = markdown.split("\n").filter((l) => l.trim().length > 10);
  if (lines.length > 20) {
    const counts = new Map<string, number>();
    for (const line of lines) {
      counts.set(line, (counts.get(line) || 0) + 1);
    }
    const maxRepeat = Math.max(...counts.values());
    if (maxRepeat > lines.length * 0.5) return "repetitive content";
  }

  return null;
}

// ============================================================
// SECURITY: URL validation (SSRF prevention)
// ============================================================

const BLOCKED_URL_PATTERNS = [
  /^(javascript|data|blob|file|ftp|gopher|telnet|ldap):/i,
  /localhost/i,
  /127\.\d+\.\d+\.\d+/,
  /\[::1\]/,
  /\[::\]/,
  /10\.\d+\.\d+\.\d+/,
  /172\.(1[6-9]|2\d|3[01])\.\d+\.\d+/,
  /192\.168\.\d+\.\d+/,
  /169\.254\.\d+\.\d+/,
  /0\.0\.0\.0/,
  /fc00:/i, // IPv6 private
  /fd[0-9a-f]{2}:/i, // IPv6 ULA
  /fe80:/i, // IPv6 link-local
  /\.local$/i, // mDNS
  /\.internal$/i,
  /\.corp$/i,
  /\.home$/i,
  /metadata\.google/i, // Cloud metadata endpoints
  /169\.254\.169\.254/, // AWS/GCP metadata
  /metadata\.azure/i,
];

function validateUrl(url: string): string | null {
  if (!url || typeof url !== "string") return "url required";
  if (url.length > 4096) return "url too long";

  // Block null bytes and control characters
  if (/[\x00-\x1f\x7f]/.test(url)) return "invalid characters in url";

  // Block URLs with credentials
  if (/@/.test(url.split("?")[0])) return "credentials in url not allowed";

  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
      return "only http/https urls allowed";
    }
    if (!parsed.hostname || parsed.hostname.length < 3) {
      return "invalid hostname";
    }
    if (parsed.hostname.length > 253) return "hostname too long";

    // Must have a TLD
    if (!parsed.hostname.includes(".")) return "invalid hostname";

    // Block numeric-only hostnames (IP addresses)
    if (/^\d+\.\d+\.\d+\.\d+$/.test(parsed.hostname)) return "ip addresses not allowed";
    if (parsed.hostname.startsWith("[")) return "ip addresses not allowed";

    // Block internal/private IPs in URL
    for (const p of BLOCKED_URL_PATTERNS) {
      if (p.test(url)) return "blocked url";
    }

    // Block double-encoding attacks
    const decoded = decodeURIComponent(url);
    for (const p of BLOCKED_URL_PATTERNS) {
      if (p.test(decoded)) return "blocked url";
    }

    // Block port scanning (only allow 80, 443, or no port)
    if (parsed.port && parsed.port !== "80" && parsed.port !== "443") {
      return "non-standard port not allowed";
    }
  } catch {
    return "invalid url";
  }

  return null;
}

// ============================================================
// SECURITY: Request validation
// ============================================================

const MAX_BODY_SIZE = 1_024_000;

async function parseBody<T>(request: Request): Promise<T | null> {
  const contentType = request.headers.get("content-type") || "";
  if (!contentType.includes("application/json")) return null;

  const contentLength = request.headers.get("content-length");
  if (contentLength && parseInt(contentLength, 10) > MAX_BODY_SIZE) return null;

  try {
    const text = await request.text();
    if (text.length > MAX_BODY_SIZE) return null;

    // Block JSON with excessive nesting (bomb attack)
    let depth = 0;
    let maxDepth = 0;
    for (const char of text) {
      if (char === "{" || char === "[") { depth++; maxDepth = Math.max(maxDepth, depth); }
      if (char === "}" || char === "]") depth--;
      if (maxDepth > 10) return null;
    }

    return JSON.parse(text) as T;
  } catch {
    return null;
  }
}

function validateInstanceId(id: string | undefined): string {
  if (!id || typeof id !== "string") return "anonymous";
  if (!/^[a-zA-Z0-9]{8,64}$/.test(id)) return "anonymous";
  return id;
}

function validateSource(source: string | undefined): string | null {
  if (!source || typeof source !== "string") return "source required";
  if (source.length > 64) return "source too long";
  if (!/^[a-zA-Z0-9_-]+$/.test(source)) return "source must be alphanumeric";
  return null;
}

// ============================================================
// SECURITY: Abuse tracking & auto-ban
// ============================================================

async function trackAbuse(kv: KVNamespace, ip: string): Promise<void> {
  const key = `abuse:${ip}`;
  const current = parseInt((await kv.get(key)) || "0", 10);
  await kv.put(key, String(current + 1), { expirationTtl: 3600 }); // 1hr window
}

async function isAbuseBanned(kv: KVNamespace, ip: string): Promise<boolean> {
  const strikes = parseInt((await kv.get(`abuse:${ip}`)) || "0", 10);
  return strikes >= 5;
}

function isAdmin(request: Request, env: Env): boolean {
  if (!env.ADMIN_SECRET) return false;
  const auth = request.headers.get("Authorization") || "";
  return auth === `Bearer ${env.ADMIN_SECRET}`;
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

function normalizeUrlForCache(url: string): string {
  let u = url.toLowerCase().replace(/\/+$/, "");
  // Normalize protocol to https
  u = u.replace(/^http:\/\//, "https://");
  // Strip www
  u = u.replace(/^(https:\/\/)www\./, "$1");
  // Strip common tracking params
  try {
    const parsed = new URL(u);
    for (const key of [...parsed.searchParams.keys()]) {
      if (/^(utm_|fbclid|gclid|ref|mc_|_ga|msclkid)/.test(key)) {
        parsed.searchParams.delete(key);
      }
    }
    // Remove empty query string
    u = parsed.toString().replace(/\?$/, "");
  } catch {}
  return u;
}

async function hashUrl(url: string): Promise<string> {
  return hashContent(normalizeUrlForCache(url));
}

function securityHeaders(): Record<string, string> {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, PUT, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; script-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), interest-cohort=()",
    "Cache-Control": "no-store, no-cache, must-revalidate",
    "X-DNS-Prefetch-Control": "off",
    "X-Download-Options": "noopen",
    "X-Permitted-Cross-Domain-Policies": "none",
    "Cross-Origin-Embedder-Policy": "require-corp",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "cross-origin",
  };
}

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", ...securityHeaders() },
  });
}

// ============================================================
// Rate limiting (sliding window per-IP)
// ============================================================

async function checkRateLimit(
  kv: KVNamespace,
  ip: string,
  action: "read" | "write" | "confirm"
): Promise<boolean> {
  const limits = { read: 600, write: 10, confirm: 60 };
  const windows = { read: 60, write: 60, confirm: 60 };
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
// Stats (via waitUntil to survive after response)
// ============================================================

let _ctx: ExecutionContext | null = null;

function incrementStat(kv: KVNamespace, stat: string): void {
  const p = kv.get(`stats:${stat}`).then((v) => {
    const n = parseInt(v || "0", 10) + 1;
    return kv.put(`stats:${stat}`, String(n));
  }).catch(() => {});
  _ctx?.waitUntil(p);
}

// ============================================================
// Handlers
// ============================================================

async function handleRead(url: string, kv: KVNamespace, ip: string): Promise<Response> {
  const urlErr = validateUrl(url);
  if (urlErr) return json({ error: urlErr }, 400);

  if (!(await checkRateLimit(kv, ip, "read"))) {
    return json({ error: "rate limited" }, 429);
  }

  const urlHash = await hashUrl(url);

  // Check DMCA flag before serving
  const dmcaFlag = await kv.get(`dmca:${urlHash}`);
  if (dmcaFlag) return json({ error: "removed per DMCA notice" }, 451);

  const key = `cache:${urlHash}`;
  const raw = await kv.get(key);
  if (!raw) return json({ status: "miss" }, 404);

  let entry: CacheEntry;
  try {
    entry = JSON.parse(raw);
  } catch {
    await kv.delete(key);
    return json({ status: "miss" }, 404);
  }

  incrementStat(kv, "hits");

  return json({
    url: entry.url,
    markdown: entry.markdown,
    trust_level: entry.trust_level,
    source: entry.source,
    age_seconds: Math.floor((Date.now() - entry.updated_at) / 1000),
  });
}

async function handleWrite(body: WriteRequest, kv: KVNamespace, ip: string, admin = false): Promise<Response> {
  if (!admin && await isAbuseBanned(kv, ip)) {
    return json({ error: "temporarily banned" }, 403);
  }

  if (!(await checkRateLimit(kv, ip, "write"))) {
    return json({ error: "rate limited" }, 429);
  }

  const { url, markdown, source } = body;
  const instanceId = validateInstanceId(body.instance_id);

  const urlErr = validateUrl(url);
  if (urlErr) return json({ error: urlErr }, 400);

  if (!markdown || typeof markdown !== "string") {
    return json({ error: "markdown required" }, 400);
  }

  const sourceErr = validateSource(source);
  if (sourceErr) {
    return json({ error: sourceErr }, 400);
  }

  // Content gates
  const rejection = validateContent(markdown);
  if (rejection) {
    await trackAbuse(kv, ip); // track the offender
    incrementStat(kv, "rejected");
    return json({ error: rejection }, 422);
  }

  // Check domain blocklist + DMCA takedowns
  try {
    const hostname = new URL(url).hostname.replace(/^www\./, "");
    const blocked = await kv.get(`block:${hostname}`);
    if (blocked) return json({ error: "domain opted out of caching" }, 403);
  } catch {}

  // Check if this specific URL has been DMCA'd
  const urlHash = await hashUrl(url);
  const dmcaFlag = await kv.get(`dmca:${urlHash}`);
  if (dmcaFlag) return json({ error: "removed per DMCA notice" }, 451);

  const contentHash = await hashContent(markdown);
  const key = `cache:${await hashUrl(url)}`;
  const existing = await kv.get(key);

  if (existing) {
    let entry: CacheEntry;
    try {
      entry = JSON.parse(existing);
    } catch {
      entry = { url, markdown: "", trust_level: 0, source: "", created_at: 0, updated_at: 0, content_hash: "", size: 0, contributors: [] };
    }

    if (entry.content_hash === contentHash) {
      if (entry.contributors.includes(instanceId)) {
        return json({ status: "duplicate", trust_level: entry.trust_level });
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

  incrementStat(kv, "writes");
  return json({ status: "accepted", trust_level: 1 });
}

async function handleConfirm(body: ConfirmRequest, kv: KVNamespace, ip: string, admin = false): Promise<Response> {
  if (!admin && await isAbuseBanned(kv, ip)) {
    return json({ error: "temporarily banned" }, 403);
  }

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
    incrementStat(kv, "confirms");
    return json({ status: "confirmed", trust_level: entry.trust_level });
  }

  return json({ status: "mismatch", trust_level: entry.trust_level });
}

async function handleStats(kv: KVNamespace): Promise<Response> {
  const [hits, writes, confirms, rejected] = await Promise.all([
    kv.get("stats:hits").then((v) => parseInt(v || "0", 10)),
    kv.get("stats:writes").then((v) => parseInt(v || "0", 10)),
    kv.get("stats:confirms").then((v) => parseInt(v || "0", 10)),
    kv.get("stats:rejected").then((v) => parseInt(v || "0", 10)),
  ]);

  return json({
    pages_cached: writes,
    cache_hits: hits,
    confirmations: confirms,
    rejected: rejected,
    hit_rate: hits + writes > 0 ? ((hits / (hits + writes)) * 100).toFixed(1) + "%" : "0%",
  });
}

// ============================================================
// Landing page
// ============================================================

async function landingPage(kv: KVNamespace): Promise<Response> {
  const [hits, writes, rejected] = await Promise.all([
    kv.get("stats:hits").then((v) => parseInt(v || "0", 10)),
    kv.get("stats:writes").then((v) => parseInt(v || "0", 10)),
    kv.get("stats:rejected").then((v) => parseInt(v || "0", 10)),
  ]);

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>agentsweb.org - The web, pre-read for AI</title>
  <meta name="description" content="A global shared cache of web pages as clean markdown. Sub-50ms reads. Self-healing consensus. Open source.">
  <meta name="robots" content="index, follow">
  <link rel="canonical" href="https://agentsweb.org">
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #0a0a0a; color: #e0e0e0; min-height: 100vh; }
    .hero { max-width: 720px; margin: 0 auto; padding: 4rem 2rem 2rem; }
    h1 { font-size: 2.5rem; font-weight: 800; color: #fff; letter-spacing: -0.02em; }
    .tagline { color: #888; font-size: 1.2rem; margin: 0.75rem 0 2rem; line-height: 1.5; }
    .stats { display: flex; gap: 1.25rem; margin-bottom: 2.5rem; }
    .stat { background: #111; border: 1px solid #222; border-radius: 10px; padding: 1.25rem 1.5rem; flex: 1; }
    .stat-value { font-size: 1.8rem; font-weight: 700; color: #fff; font-variant-numeric: tabular-nums; }
    .stat-label { color: #666; font-size: 0.8rem; margin-top: 0.25rem; }
    .install { background: #111; border: 1px solid #222; border-radius: 10px; padding: 1.5rem; margin-bottom: 2.5rem; }
    .install-label { color: #888; font-size: 0.85rem; margin-bottom: 0.75rem; }
    .install code { background: #0d0d0d; color: #4ade80; font-family: "SF Mono", "Fira Code", monospace; font-size: 0.95rem; display: block; padding: 0.75rem 1rem; border-radius: 6px; border: 1px solid #1a1a1a; overflow-x: auto; }
    h2 { font-weight: 600; color: #fff; text-transform: uppercase; letter-spacing: 0.05em; font-size: 0.8rem; margin-bottom: 1rem; }
    .section { margin-bottom: 2.5rem; }
    .section p { color: #999; line-height: 1.7; margin-bottom: 0.75rem; }
    .section strong { color: #ccc; }
    .ep { background: #111; border: 1px solid #1a1a1a; border-radius: 8px; padding: 0.85rem 1.1rem; margin-bottom: 0.6rem; display: flex; align-items: center; gap: 0.75rem; }
    .m { font-weight: 700; font-size: 0.7rem; padding: 3px 8px; border-radius: 4px; font-family: monospace; min-width: 42px; text-align: center; }
    .mg { background: #0f2918; color: #4ade80; }
    .mp { background: #2a1f0a; color: #fbbf24; }
    .mb { background: #0f1929; color: #60a5fa; }
    .ep-p { font-family: monospace; color: #ccc; font-size: 0.9rem; }
    .ep-d { color: #666; font-size: 0.85rem; margin-left: auto; }
    .sec-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem; }
    .sec-item { background: #111; border: 1px solid #1a1a1a; border-radius: 6px; padding: 0.6rem 0.85rem; color: #888; font-size: 0.8rem; }
    .curl code { background: #0d0d0d; color: #ccc; font-family: "SF Mono", "Fira Code", monospace; font-size: 0.8rem; display: block; padding: 0.75rem 1rem; border-radius: 6px; border: 1px solid #1a1a1a; white-space: pre; overflow-x: auto; }
    .footer { border-top: 1px solid #1a1a1a; padding-top: 2rem; margin-top: 1rem; color: #444; font-size: 0.8rem; display: flex; justify-content: space-between; }
    a { color: #60a5fa; text-decoration: none; }
    a:hover { text-decoration: underline; }
    @media (max-width: 600px) { .stats { flex-direction: column; gap: 0.75rem; } .sec-grid { grid-template-columns: 1fr; } .ep { flex-wrap: wrap; } .ep-d { margin-left: 0; } h1 { font-size: 2rem; } }
  </style>
</head>
<body>
  <div class="hero">
    <h1>agentsweb.org</h1>
    <p class="tagline">The web, pre-read for AI. A global shared cache of web pages as clean markdown. Sub-50ms reads from the edge. Self-healing consensus prevents poisoning.</p>

    <div class="stats">
      <div class="stat"><div class="stat-value">${writes.toLocaleString()}</div><div class="stat-label">pages cached</div></div>
      <div class="stat"><div class="stat-value">${hits.toLocaleString()}</div><div class="stat-label">cache hits</div></div>
      <div class="stat"><div class="stat-value">${rejected.toLocaleString()}</div><div class="stat-label">attacks blocked</div></div>
      <div class="stat"><div class="stat-value">&lt;50ms</div><div class="stat-label">edge latency</div></div>
    </div>

    <div class="install">
      <div class="install-label">Get started with intercept-mcp (reads + writes automatically):</div>
      <code>npx -y intercept-mcp</code>
    </div>

    <div class="section">
      <h2>How it works</h2>
      <p>Every AI agent fetches the same pages, fights the same captchas, and converts the same HTML. <strong>That's redundant.</strong></p>
      <p>With agentsweb, the first agent to fetch a URL caches the clean markdown globally. Every agent after gets it instantly. The more agents use it, the faster everyone gets.</p>
      <p><strong>Self-healing:</strong> Entries gain trust as independent sources confirm them. Poisoned content self-destructs on the next legitimate read. No single source is trusted blindly.</p>
    </div>

    <div class="section">
      <h2>API</h2>
      <div class="ep"><span class="m mg">GET</span><span class="ep-p">/?url={url}</span><span class="ep-d">Read cached markdown</span></div>
      <div class="ep"><span class="m mp">PUT</span><span class="ep-p">/</span><span class="ep-d">Contribute markdown</span></div>
      <div class="ep"><span class="m mb">POST</span><span class="ep-p">/confirm</span><span class="ep-d">Confirm entry integrity</span></div>
      <div class="ep"><span class="m mg">GET</span><span class="ep-p">/stats</span><span class="ep-d">Live statistics</span></div>
    </div>

    <div class="section curl">
      <h2>Try it</h2>
      <code>curl "https://agentsweb.org/?url=https://example.com"</code>
    </div>

    <div class="section">
      <h2>Security</h2>
      <div class="sec-grid">
        <div class="sec-item">Prompt injection scanning (head + tail)</div>
        <div class="sec-item">SSRF / private IP / metadata blocking</div>
        <div class="sec-item">Captcha &amp; login wall detection</div>
        <div class="sec-item">XSS / script / event handler filtering</div>
        <div class="sec-item">Unicode steganography detection</div>
        <div class="sec-item">Auto-ban on repeated abuse</div>
        <div class="sec-item">JSON depth limiting</div>
        <div class="sec-item">Repetition / padding attack detection</div>
        <div class="sec-item">Trust-level consensus</div>
        <div class="sec-item">Self-healing on read</div>
        <div class="sec-item">Domain blocklist</div>
        <div class="sec-item">Credential &amp; port scanning prevention</div>
      </div>
    </div>

    <div class="footer">
      <span><a href="https://github.com/bighippoman/intercept-mcp">intercept-mcp</a> &middot; <a href="https://github.com/bighippoman/agentsweb">source</a> &middot; <a href="/dmca">DMCA</a> &middot; <a href="/terms">Terms</a></span>
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
      "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
      "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
      "Permissions-Policy": "camera=(), microphone=(), geolocation=(), interest-cohort=()",
      "Cache-Control": "public, max-age=60",
      "X-DNS-Prefetch-Control": "off",
      "Cross-Origin-Opener-Policy": "same-origin",
    },
  });
}

// ============================================================
// DMCA takedown handler
// ============================================================

async function handleTakedown(request: Request, kv: KVNamespace, ip: string): Promise<Response> {
  if (!(await checkRateLimit(kv, ip, "write"))) {
    return json({ error: "rate limited" }, 429);
  }

  const body = await parseBody<{ url: string; email: string; reason?: string }>(request);
  if (!body || !body.url || !body.email) {
    return json({ error: "url and email required" }, 400);
  }

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(body.email)) {
    return json({ error: "valid email required" }, 400);
  }

  const urlErr = validateUrl(body.url);
  if (urlErr) return json({ error: urlErr }, 400);

  const urlHash = await hashUrl(body.url);

  // Flag the URL as DMCA'd (permanent until manually reviewed)
  await kv.put(`dmca:${urlHash}`, JSON.stringify({
    url: body.url,
    email: body.email,
    reason: body.reason || "DMCA takedown request",
    timestamp: Date.now(),
    ip,
  }));

  // Delete the cached entry
  const key = `cache:${urlHash}`;
  await kv.delete(key);

  incrementStat(kv, "takedowns");

  return json({ status: "removed", url: body.url });
}

// ============================================================
// Domain opt-out handler
// ============================================================

async function handleOptOut(request: Request, kv: KVNamespace, ip: string): Promise<Response> {
  if (!(await checkRateLimit(kv, ip, "write"))) {
    return json({ error: "rate limited" }, 429);
  }

  const body = await parseBody<{ domain: string; email: string }>(request);
  if (!body || !body.domain || !body.email) {
    return json({ error: "domain and email required" }, 400);
  }

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(body.email)) {
    return json({ error: "valid email required" }, 400);
  }

  const domain = body.domain.replace(/^www\./, "").toLowerCase();
  if (domain.length < 3 || !domain.includes(".")) {
    return json({ error: "invalid domain" }, 400);
  }

  await kv.put(`block:${domain}`, JSON.stringify({
    email: body.email,
    timestamp: Date.now(),
    ip,
  }));

  return json({ status: "opted out", domain });
}

// ============================================================
// Legal pages
// ============================================================

function dmcaPage(): Response {
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>DMCA Policy - agentsweb.org</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #0a0a0a; color: #e0e0e0; min-height: 100vh; }
    .page { max-width: 720px; margin: 0 auto; padding: 4rem 2rem; }
    h1 { font-size: 1.8rem; font-weight: 700; color: #fff; margin-bottom: 1.5rem; }
    h2 { font-size: 1.1rem; color: #fff; margin: 1.5rem 0 0.75rem; }
    p, li { color: #999; line-height: 1.7; margin-bottom: 0.75rem; }
    ul { padding-left: 1.5rem; }
    code { background: #161616; padding: 0.15rem 0.4rem; border-radius: 3px; font-size: 0.9rem; color: #ccc; }
    a { color: #60a5fa; text-decoration: none; }
    .back { margin-top: 2rem; }
  </style>
</head>
<body>
  <div class="page">
    <h1>DMCA &amp; Takedown Policy</h1>

    <h2>What agentsweb.org is</h2>
    <p>agentsweb.org is an automated system cache operating under DMCA 512(b) (system caching safe harbor). It temporarily caches markdown representations of publicly accessible web pages to reduce redundant network requests by AI agents. All cached content is ephemeral — entries expire automatically based on TTL policies.</p>

    <h2>Automated cache, not a hosting service</h2>
    <p>We do not host, curate, or editorially select content. Content enters the cache only through automated processes initiated by third-party AI agent instances. We do not modify, edit, or control what content is cached beyond automated quality and security filtering.</p>

    <h2>Transformative purpose</h2>
    <p>Cached content is stored as markdown — a structural transformation from the original HTML — for the purpose of machine processing by AI agents. This is a fundamentally different use from the original publication purpose, analogous to how search engine caches transform and index content for information retrieval.</p>

    <h2>Content removal</h2>
    <p>Content owners can remove any cached content instantly:</p>
    <ul>
      <li><strong>Single URL takedown:</strong> <code>POST /takedown</code> with <code>{"url": "...", "email": "..."}</code></li>
      <li><strong>Entire domain opt-out:</strong> <code>POST /opt-out</code> with <code>{"domain": "...", "email": "..."}</code></li>
    </ul>
    <p>Takedowns are processed immediately and automatically. No human review delay. The URL is permanently flagged and cannot be re-cached.</p>

    <h2>DMCA notices</h2>
    <p>For formal DMCA takedown notices, email <strong>dmca@agentsweb.org</strong> with:</p>
    <ul>
      <li>The URL(s) of the cached content</li>
      <li>The original URL(s) of your copyrighted work</li>
      <li>A statement of good faith belief that the use is not authorized</li>
      <li>Your contact information</li>
    </ul>
    <p>We respond to all valid DMCA notices within 24 hours.</p>

    <h2>robots.txt</h2>
    <p>Website owners can prevent their content from being cached by adding <code>User-agent: agentsweb</code> with <code>Disallow: /</code> to their robots.txt file, or by using the domain opt-out API.</p>

    <p class="back"><a href="/">Back to agentsweb.org</a></p>
  </div>
</body>
</html>`;
  return new Response(html, {
    headers: {
      "Content-Type": "text/html;charset=utf-8",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    },
  });
}

function termsPage(): Response {
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Terms of Service - agentsweb.org</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #0a0a0a; color: #e0e0e0; min-height: 100vh; }
    .page { max-width: 720px; margin: 0 auto; padding: 4rem 2rem; }
    h1 { font-size: 1.8rem; font-weight: 700; color: #fff; margin-bottom: 1.5rem; }
    h2 { font-size: 1.1rem; color: #fff; margin: 1.5rem 0 0.75rem; }
    p { color: #999; line-height: 1.7; margin-bottom: 0.75rem; }
    a { color: #60a5fa; text-decoration: none; }
    .back { margin-top: 2rem; }
  </style>
</head>
<body>
  <div class="page">
    <h1>Terms of Service</h1>

    <h2>Service description</h2>
    <p>agentsweb.org provides an automated system cache for AI agent infrastructure. It stores temporary markdown representations of publicly accessible web pages.</p>

    <h2>No warranty</h2>
    <p>The service is provided "as is" without warranty. Cached content may be incomplete, outdated, or incorrect. Content accuracy depends on third-party submissions and is not guaranteed.</p>

    <h2>Acceptable use</h2>
    <p>You may not: submit content containing malware, prompt injections, or other malicious payloads; attempt to poison the cache; use the service for DDoS amplification; exceed rate limits through automated means.</p>

    <h2>Content responsibility</h2>
    <p>Contributors are responsible for ensuring they have the right to submit content. agentsweb.org operates as a passive cache and does not verify the copyright status of cached content.</p>

    <h2>Abuse</h2>
    <p>IPs that repeatedly submit rejected content are automatically banned. Persistent abuse may result in permanent blocking.</p>

    <h2>Content removal</h2>
    <p>Content owners may request immediate removal via the <a href="/dmca">DMCA &amp; Takedown</a> page.</p>

    <p class="back"><a href="/">Back to agentsweb.org</a></p>
  </div>
</body>
</html>`;
  return new Response(html, {
    headers: {
      "Content-Type": "text/html;charset=utf-8",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    },
  });
}

// ============================================================
// Main entry point
// ============================================================

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    _ctx = ctx;
    const admin = isAdmin(request, env);
    const method = request.method;
    if (!["GET", "PUT", "POST", "OPTIONS", "HEAD"].includes(method)) {
      return json({ error: "method not allowed" }, 405);
    }

    const url = new URL(request.url);
    const ip = request.headers.get("CF-Connecting-IP") || "unknown";

    // CORS preflight
    if (method === "OPTIONS") {
      return new Response(null, { status: 204, headers: securityHeaders() });
    }

    // HEAD support (health checks)
    if (method === "HEAD") {
      return new Response(null, { status: 200, headers: securityHeaders() });
    }

    // Landing page
    if (method === "GET" && url.pathname === "/" && !url.searchParams.has("url")) {
      return await landingPage(env.CACHE);
    }

    // Admin: purge ban
    if (method === "POST" && url.pathname === "/admin/purge-ban" && admin) {
      await env.CACHE.delete(`abuse:${ip}`);
      return json({ status: "ban cleared", ip });
    }

    // Admin: clear all bans for a specific IP
    if (method === "POST" && url.pathname === "/admin/purge-ban-ip" && admin) {
      const body = await parseBody<{ ip: string }>(request);
      if (body?.ip) {
        await env.CACHE.delete(`abuse:${body.ip}`);
        return json({ status: "ban cleared", ip: body.ip });
      }
      return json({ error: "ip required" }, 400);
    }

    // API routes
    try {
      if (method === "GET" && url.pathname === "/" && url.searchParams.has("url")) {
        return await handleRead(url.searchParams.get("url")!, env.CACHE, ip);
      }

      if (method === "PUT" && url.pathname === "/") {
        const body = await parseBody<WriteRequest>(request);
        if (!body) return json({ error: "invalid json body" }, 400);
        return await handleWrite(body, env.CACHE, ip, admin);
      }

      if (method === "POST" && url.pathname === "/confirm") {
        const body = await parseBody<ConfirmRequest>(request);
        if (!body) return json({ error: "invalid json body" }, 400);
        return await handleConfirm(body, env.CACHE, ip, admin);
      }

      if (method === "GET" && url.pathname === "/stats") {
        return await handleStats(env.CACHE);
      }

      if (method === "POST" && url.pathname === "/takedown") {
        return await handleTakedown(request, env.CACHE, ip);
      }

      if (method === "POST" && url.pathname === "/opt-out") {
        return await handleOptOut(request, env.CACHE, ip);
      }
    } catch {
      return json({ error: "internal error" }, 500);
    }

    // Static pages
    if (method === "GET" && url.pathname === "/dmca") return dmcaPage();
    if (method === "GET" && url.pathname === "/terms") return termsPage();

    return json({ error: "not found" }, 404);
  },
};
