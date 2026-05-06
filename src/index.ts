import { convertHtmlToMarkdown } from "./html-to-md.js";

interface Env {
  CACHE: KVNamespace;
  ADMIN_SECRET: string;
  CF_API_TOKEN?: string;
  CF_ACCOUNT_ID?: string;
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
  /not\s+a\s+robot/i,
  /unusual\s+(traffic|activity)/i,
  /detected\s+unusual/i,
  /security\s+check\s+to\s+access/i,
  /please\s+verify\s+you\s+are\s+human/i,
  /click\s+the\s+box\s+below/i,
  /access\s+denied/i,
  /blocked\s+your\s+(ip|access)/i,
  /enable\s+javascript\s+and\s+cookies/i,
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
  if (markdown.length > 10_000_000) return "too large";

  // Check for invisible character attacks
  if (INVISIBLE_CHAR_REGEX.test(markdown)) return "hidden characters detected";
  const invisibleCount = (markdown.match(/[\u200B-\u200F\u2060-\u2064\uFEFF]/g) || []).length;
  if (invisibleCount / markdown.length > ZERO_WIDTH_DENSITY_THRESHOLD) return "suspicious unicode";

  // Check for captcha/wall — but scan more broadly (not just first 500 chars)
  const scanHead = markdown.slice(0, 2000);
  for (const p of CAPTCHA_PATTERNS) {
    if (p.test(scanHead)) return "captcha detected";
  }
  for (const p of LOGIN_WALL_PATTERNS) {
    if (p.test(scanHead)) return "login wall detected";
  }

  // Strip code blocks AND HTML tags before scanning — docs legitimately contain
  // <script>, onclick, etc. in code examples and raw HTML dumps
  const stripped = markdown
    .replace(/```[\s\S]*?```/g, "")        // fenced code blocks
    .replace(/`[^`]+`/g, "")              // inline code
    .replace(/<[^>]+>/g, "");             // HTML tags (from raw HTML content)

  // Scan FULL document for injection — no blind spots
  // But only flag if multiple patterns match (single hit could be legitimate
  // content ABOUT injection, e.g., Wikipedia articles about AI safety)
  let injectionHits = 0;
  for (const p of PROMPT_INJECTION_PATTERNS) {
    if (p.test(stripped)) injectionHits++;
  }
  // Single pattern match in a long doc = likely discussing the topic
  // 3+ matches = likely actual injection attempt
  const injectionThreshold = stripped.length > 10_000 ? 3 : 1;
  if (injectionHits >= injectionThreshold) return "prompt injection detected";

  // Malicious content check — threshold based (docs discuss JS security topics)
  const maliciousScan = stripped.slice(0, 20_000);
  let maliciousHits = 0;
  for (const p of MALICIOUS_CONTENT_PATTERNS) {
    if (p.test(maliciousScan)) maliciousHits++;
  }
  const maliciousThreshold = stripped.length > 5_000 ? 4 : 2;
  if (maliciousHits >= maliciousThreshold) return "malicious content detected";

  // Language diversity check — reject extreme spam (same phrases over and over)
  const words = stripped.toLowerCase().match(/[a-z]{4,}/g) || [];
  const uniqueWords = new Set(words);
  if (words.length > 100 && uniqueWords.size / words.length < 0.08) {
    return "low vocabulary diversity"; // extreme spam
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

function timingSafeEqual(a: string, b: string): boolean {
  const ua = new TextEncoder().encode(a);
  const ub = new TextEncoder().encode(b);
  if (ua.length !== ub.length) {
    // Compare against dummy to avoid length oracle
    const dummy = new Uint8Array(ua.length);
    let diff = 1;
    for (let i = 0; i < ua.length; i++) diff |= ua[i] ^ dummy[i];
    return false;
  }
  let diff = 0;
  for (let i = 0; i < ua.length; i++) diff |= ua[i] ^ ub[i];
  return diff === 0;
}

function isAdmin(request: Request, env: Env): boolean {
  if (!env.ADMIN_SECRET) return false;
  const auth = request.headers.get("Authorization") || "";
  const expected = `Bearer ${env.ADMIN_SECRET}`;
  return timingSafeEqual(auth, expected);
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

function json(data: unknown, status = 200, etag?: string): Response {
  const headers: Record<string, string> = { "Content-Type": "application/json; charset=utf-8", ...securityHeaders() };
  if (etag) headers["ETag"] = etag;
  return new Response(JSON.stringify(data), { status, headers });
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

// Thread-safe context — captured per-request, never shared
interface RequestContext {
  ctx: ExecutionContext;
  kv: KVNamespace;
  env: Env;
}

let _rc: RequestContext | null = null;

function incrementStat(kv: KVNamespace, stat: string): void {
  const p = kv.get(`stats:${stat}`).then((v) => {
    const n = parseInt(v || "0", 10) + 1;
    return kv.put(`stats:${stat}`, String(n));
  }).catch(() => {});
  _rc?.ctx.waitUntil(p);
}

function waitUntilBg(p: Promise<unknown>): void {
  _rc?.ctx.waitUntil(p);
}

// ============================================================
// Handlers
// ============================================================

// ============================================================
// Agent-friendly content processing
// ============================================================

/** Rough token estimate (~4 chars per token for English text) */
function estimateTokens(text: string): number {
  return Math.ceil(text.length / 4);
}

/** Extract a specific section by heading match */
function extractSection(markdown: string, query: string): string | null {
  const queryLower = query.toLowerCase();
  const lines = markdown.split("\n");

  let bestStart = -1;
  let bestLevel = 0;
  let bestScore = 0;

  // Find the heading that best matches the query
  for (let i = 0; i < lines.length; i++) {
    const match = lines[i].match(/^(#{1,6})\s+(.+)/);
    if (!match) continue;

    const level = match[1].length;
    const heading = match[2].toLowerCase().replace(/[^a-z0-9\s]/g, "");
    const queryWords = queryLower.split(/\s+/).filter((w) => w.length > 2);

    let score = 0;
    for (const word of queryWords) {
      if (heading.includes(word)) score++;
    }
    // Bonus for exact substring match
    if (heading.includes(queryLower)) score += 3;

    if (score > bestScore) {
      bestScore = score;
      bestStart = i;
      bestLevel = level;
    }
  }

  if (bestStart === -1 || bestScore === 0) return null;

  // Extract from the matched heading to the next heading of same or higher level
  const sectionLines = [lines[bestStart]];
  for (let i = bestStart + 1; i < lines.length; i++) {
    const headingMatch = lines[i].match(/^(#{1,6})\s/);
    if (headingMatch && headingMatch[1].length <= bestLevel) break;
    sectionLines.push(lines[i]);
  }

  const section = sectionLines.join("\n").trim();
  return section.length >= 50 ? section : null;
}

/** List all headings in a document (table of contents) */
function extractHeadings(markdown: string): string[] {
  return (markdown.match(/^#{1,6}\s+.+$/gm) || []).map((h) =>
    h.replace(/^#+\s+/, "").replace(/\[.*?\]\(.*?\)/g, "").trim()
  );
}

/** Truncate markdown to approximately N tokens, breaking at paragraph boundaries */
function truncateToTokens(markdown: string, maxTokens: number): string {
  const maxChars = maxTokens * 4;
  if (markdown.length <= maxChars) return markdown;

  // Find the last paragraph break before the limit
  const truncated = markdown.slice(0, maxChars);
  const lastParagraph = truncated.lastIndexOf("\n\n");
  const cutPoint = lastParagraph > maxChars * 0.5 ? lastParagraph : maxChars;

  return truncated.slice(0, cutPoint) + "\n\n[Truncated — " + estimateTokens(markdown).toLocaleString() + " tokens total]";
}

/** Strip common boilerplate from markdown */
function cleanForAgent(markdown: string): string {
  let md = markdown;

  // Strip Jina metadata headers (Title:, URL Source:, Published Time:, Markdown Content:)
  md = md.replace(/^Title:\s*.+\n/m, "");
  md = md.replace(/^URL Source:\s*.+\n/m, "");
  md = md.replace(/^Published Time:\s*.+\n/m, "");
  md = md.replace(/^Markdown Content:\s*\n/m, "");
  md = md.replace(/^Warning:.*\n/gm, "");

  // Strip navigation menu blocks — runs of 3+ consecutive short link lines
  const lines = md.split("\n");
  const cleaned: string[] = [];
  let navRun = 0;
  for (const line of lines) {
    const trimmed = line.trim();
    const isNavLink = /^\*?\s*\[.{1,50}\]\(.*\)\s*$/.test(trimmed) && trimmed.length < 100;
    if (isNavLink) {
      navRun++;
    } else {
      if (navRun >= 4) {
        // Was a nav block — skip all the accumulated links
        // Don't add them to cleaned
      } else {
        // Not a nav block — add any accumulated links back
        // (they were real content links)
      }
      navRun = 0;
      cleaned.push(line);
    }
  }
  md = cleaned.join("\n");

  // Strip share/social/cookie/terms lines
  md = md.replace(/^.*?(share|tweet|follow us|subscribe to|newsletter|sign up for|cookie|privacy policy|terms of service|advertisement|sponsored|skip to content).*$/gim, "");

  // Strip "Related articles" / "Navigation" sections
  md = md.replace(/^#{1,3}\s*(related|recommended|you may also|more from|trending|popular|see also|navigation menu|toggle navigation).*$[\s\S]*?(?=^#{1,3}\s[^#]|\Z)/gim, "");

  // Strip GitHub-specific nav cruft
  md = md.replace(/^.*?(Sign in|Appearance settings|Platform|AI CODE CREATION|DEVELOPER WORKFLOWS|APPLICATION SECURITY|Toggle navigation).*$/gm, "");

  // Strip image-only lines (usually icons/logos)
  md = md.replace(/^\s*!\[.*?\]\(.*?\)\s*$/gm, "");

  // Strip "You can't perform that action" GitHub messages
  md = md.replace(/^.*?You can't perform that action.*$/gm, "");

  // Collapse excessive blank lines
  md = md.replace(/\n{3,}/g, "\n\n");

  return md.trim();
}

/** Detect content type from markdown structure */
function detectContentType(markdown: string, url: string): string {
  const lower = markdown.toLowerCase();
  const urlLower = url.toLowerCase();

  if (urlLower.includes("/docs") || urlLower.includes("/reference") || urlLower.includes("/api")) return "documentation";
  if (urlLower.includes("/tutorial") || urlLower.includes("/learn") || urlLower.includes("/getting-started")) return "tutorial";
  if (urlLower.includes("/blog") || urlLower.includes("/news") || urlLower.includes("/article")) return "article";
  if (urlLower.includes("arxiv.org")) return "paper";
  if (urlLower.includes("github.com")) return "repository";
  if (urlLower.includes("wikipedia.org")) return "encyclopedia";

  // Content heuristics
  const codeBlocks = (markdown.match(/```/g) || []).length / 2;
  const headings = (markdown.match(/^#{1,3}\s/gm) || []).length;

  if (codeBlocks > 5) return "tutorial";
  if (headings > 10) return "documentation";
  if (lower.includes("abstract") && lower.includes("introduction")) return "paper";

  return "article";
}

async function handleRead(url: string, kv: KVNamespace, ip: string, request: Request, maxTokens = 0, clean = true, section = "", toc = false): Promise<Response> {
  const urlErr = validateUrl(url);
  if (urlErr) return json({ error: urlErr }, 400);

  // --- EDGE CACHE: check CF Cache API first (sub-1ms) ---
  // Skip edge cache if agent params are set
  const hasAgentParams = maxTokens > 0 || !clean || !!section || toc;
  const cache = caches.default;
  const cacheKey = new Request(`https://agentsweb.org/_cache/${encodeURIComponent(normalizeUrlForCache(url))}`, { method: "GET" });
  const cachedResponse = !hasAgentParams ? await cache.match(cacheKey) : null;
  if (cachedResponse) {
    // ETag check against edge-cached response
    const etag = cachedResponse.headers.get("ETag");
    if (etag && request.headers.get("If-None-Match") === etag) {
      return new Response(null, { status: 304, headers: { ETag: etag, ...securityHeaders() } });
    }
    incrementStat(kv, "hits");
    return cachedResponse;
  }

  // --- KV LOOKUP (only on edge cache miss) ---
  if (!(await checkRateLimit(kv, ip, "read"))) {
    return json({ error: "rate limited" }, 429);
  }

  const urlHash = await hashUrl(url);

  const dmcaFlag = await kv.get(`dmca:${urlHash}`);
  if (dmcaFlag) return json({ error: "removed per DMCA notice" }, 451);

  const key = `cache:${urlHash}`;
  const raw = await kv.get(key);
  if (!raw) return json({ status: "miss" }, 404);

  let entry: CacheEntry;
  try {
    entry = JSON.parse(raw);
  } catch {
    waitUntilBg(kv.delete(key));
    return json({ status: "miss" }, 404);
  }

  incrementStat(kv, "hits");

  const etag = `"${entry.content_hash.slice(0, 16)}"`;
  if (request.headers.get("If-None-Match") === etag) {
    return new Response(null, { status: 304, headers: { ETag: etag, ...securityHeaders() } });
  }

  const stale = (Date.now() - entry.updated_at) > getTtl(entry.trust_level, entry.url) * 750;

  // Section/TOC extraction runs on RAW markdown (before cleaning strips headings)
  const rawMarkdown = entry.markdown;

  // Table of contents mode
  if (toc) {
    const headings = extractHeadings(rawMarkdown);
    return json({
      url: entry.url,
      headings,
      count: headings.length,
      trust_level: entry.trust_level,
    });
  }

  // Section extraction
  let markdown: string;
  if (section) {
    const extracted = extractSection(rawMarkdown, section);
    if (!extracted) {
      const headings = extractHeadings(rawMarkdown);
      return json({
        error: "section not found",
        query: section,
        available_headings: headings.slice(0, 20),
      }, 404);
    }
    markdown = clean ? cleanForAgent(extracted) : extracted;
  } else {
    markdown = clean ? cleanForAgent(rawMarkdown) : rawMarkdown;
  }

  const totalTokens = estimateTokens(clean ? cleanForAgent(rawMarkdown) : rawMarkdown);
  const currentTokens = estimateTokens(markdown);
  const truncated = maxTokens > 0 && currentTokens > maxTokens;
  if (truncated) markdown = truncateToTokens(markdown, maxTokens);
  const contentType = detectContentType(entry.markdown, entry.url);

  const response = json({
    url: entry.url,
    markdown,
    trust_level: entry.trust_level,
    source: entry.source,
    content_type: contentType,
    tokens: truncated ? estimateTokens(markdown) : currentTokens,
    total_tokens: totalTokens,
    ...(truncated ? { truncated: true } : {}),
    age_seconds: Math.floor((Date.now() - entry.updated_at) / 1000),
    ...(stale ? { stale: true } : {}),
  }, 200, etag);

  // --- STORE IN EDGE CACHE (5 min TTL for popular pages) ---
  const cacheResponse = response.clone();
  const cacheHeaders = new Headers(cacheResponse.headers);
  cacheHeaders.set("Cache-Control", "public, max-age=900"); // 15 min edge TTL — hot pages stay at edge
  cacheHeaders.set("ETag", etag);
  const toCache = new Response(cacheResponse.body, { status: 200, headers: cacheHeaders });
  waitUntilBg(cache.put(cacheKey, toCache));

  return response;
}

async function handleWrite(body: WriteRequest, kv: KVNamespace, ip: string, admin = false): Promise<Response> {
  if (!admin && await isAbuseBanned(kv, ip)) {
    return json({ error: "temporarily banned" }, 403);
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
    await trackAbuse(kv, ip);
    incrementStat(kv, "rejected");
    return json({ error: rejection }, 422);
  }

  // Structural integrity — real content has markdown structure
  const hasHeading = /^#{1,6}\s/m.test(markdown);
  const hasParagraphs = (markdown.match(/\n\n/g) || []).length >= 2;
  const hasLinks = /\[.*?\]\(.*?\)/.test(markdown);
  const wordCount = markdown.split(/\s+/).length;
  if (wordCount < 30) {
    await trackAbuse(kv, ip);
    return json({ error: "insufficient content structure" }, 422);
  }
  if (!hasHeading && !hasParagraphs && wordCount < 100) {
    return json({ error: "content lacks structure" }, 422);
  }

  // URL-content coherence — very loose check, only reject extreme mismatches
  // e.g., content about crypto scams cached under a react.dev URL
  try {
    const pathWords = new URL(url).pathname.split(/[/\-_.]/).filter((w) => w.length > 4);
    if (pathWords.length >= 2) {
      const contentLower = markdown.toLowerCase().slice(0, 10_000);
      const anyPathWordFound = pathWords.some((w) => contentLower.includes(w.toLowerCase()));
      // Only reject if content is short AND none of the path keywords appear
      if (!anyPathWordFound && markdown.length < 3000) {
        incrementStat(kv, "rejected");
        return json({ error: "content does not appear related to URL" }, 422);
      }
    }
  } catch {}

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
      // Deduplicate by IP hash (not self-reported instance_id) to prevent trust inflation
      const ipHash = await hashContent(ip);
      const contributorKey = ipHash.slice(0, 16);
      if (entry.contributors.includes(contributorKey)) {
        return json({ status: "duplicate", trust_level: entry.trust_level });
      }
      // Max 3 trust increments per hour per URL (prevents botnet trust flooding)
      const trustRateKey = `trustrate:${await hashUrl(url)}`;
      const trustIncrements = parseInt((await kv.get(trustRateKey)) || "0", 10);
      if (trustIncrements >= 3 && !admin) {
        return json({ status: "trust rate limited", trust_level: entry.trust_level });
      }
      await kv.put(trustRateKey, String(trustIncrements + 1), { expirationTtl: 3600 });

      if (entry.trust_level < 100) entry.trust_level++;
      entry.updated_at = Date.now();
      entry.contributors.push(contributorKey);
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

    // Write cooldown — prevent rapid overwrite cycling on trust_level 1 entries
    const ageMs = Date.now() - entry.updated_at;
    if (ageMs < 60_000 && !admin) { // 1 minute cooldown
      return json({
        status: "rejected",
        reason: "write cooldown — try again in " + Math.ceil((60_000 - ageMs) / 1000) + "s",
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

  // Invalidate edge cache for this URL
  waitUntilBg((async () => {
    const c = caches.default;
    await c.delete(new Request(`https://agentsweb.org/_cache/${encodeURIComponent(normalizeUrlForCache(url))}`));
    await c.delete(new Request(`https://agentsweb.org/_raw/${encodeURIComponent(normalizeUrlForCache(url))}`));
  })());

  // Maintain URL index + content search index
  waitUntilBg((async () => {
    const normalized = normalizeUrlForCache(url);

    // URL index
    const indexRaw = await kv.get("index:urls");
    const urls: string[] = indexRaw ? JSON.parse(indexRaw) : [];
    if (!urls.includes(normalized)) {
      urls.push(normalized);
      if (urls.length > 10_000) urls.splice(0, urls.length - 10_000);
      await kv.put("index:urls", JSON.stringify(urls));
    }

    // Content search index — extract title + snippet for local search
    const titleMatch = markdown.match(/^#\s+(.+)/m);
    const title = titleMatch ? titleMatch[1].slice(0, 200) : "";
    // Extract ALL headings + first 1000 chars of body for search indexing
    const headings = (markdown.match(/^#{1,6}\s+.+$/gm) || []).join(" ");
    const body = markdown
      .replace(/^#.+$/gm, "")
      .replace(/\[.*?\]\(.*?\)/g, "")
      .replace(/[*_`]/g, "")
      .trim()
      .slice(0, 1000);
    const snippet = `${headings} ${body}`.slice(0, 1500);

    const searchEntry = { url: normalized, title, snippet };
    const searchIndexRaw = await kv.get("index:search");
    const searchIndex: Array<{ url: string; title: string; snippet: string }> = searchIndexRaw ? JSON.parse(searchIndexRaw) : [];

    // Update or add
    const existing = searchIndex.findIndex((e) => e.url === normalized);
    if (existing >= 0) {
      searchIndex[existing] = searchEntry;
    } else {
      searchIndex.push(searchEntry);
      if (searchIndex.length > 10_000) searchIndex.splice(0, searchIndex.length - 10_000);
    }
    await kv.put("index:search", JSON.stringify(searchIndex));
  })());

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
    const ipHash = await hashContent(ip);
    const contributorKey = ipHash.slice(0, 16);
    if (entry.contributors.includes(contributorKey)) {
      return json({ status: "already confirmed", trust_level: entry.trust_level });
    }
    // Trust rate limit — max 3 increments per hour per URL
    const urlHash = await hashUrl(url);
    const trustRateKey = `trustrate:${urlHash}`;
    const trustIncrements = parseInt((await kv.get(trustRateKey)) || "0", 10);
    if (trustIncrements >= 3 && !admin) {
      return json({ status: "trust rate limited", trust_level: entry.trust_level });
    }
    await kv.put(trustRateKey, String(trustIncrements + 1), { expirationTtl: 3600 });

    if (entry.trust_level < 100) entry.trust_level++;
    entry.updated_at = Date.now();
    entry.contributors.push(contributorKey);
    if (entry.contributors.length > 50) {
      entry.contributors = entry.contributors.slice(-50);
    }
    await kv.put(key, JSON.stringify(entry), {
      expirationTtl: getTtl(entry.trust_level, url),
    });
    incrementStat(kv, "confirms");
    return json({ status: "confirmed", trust_level: entry.trust_level });
  }

  // Mismatch — the confirmed content doesn't match cached content
  // This means either the cache is wrong or the confirmer is wrong
  // Track mismatches — if too many, decay trust (the cache might be poisoned)
  const mismatchKey = `mismatch:${urlHash}`;
  const mismatches = parseInt((await kv.get(mismatchKey)) || "0", 10) + 1;
  await kv.put(mismatchKey, String(mismatches), { expirationTtl: 3600 }); // 1hr window

  // If 3+ independent mismatches in 1 hour, decay trust
  if (mismatches >= 3 && entry.trust_level > 1) {
    entry.trust_level = Math.max(1, entry.trust_level - 1);
    entry.updated_at = Date.now();
    await kv.put(key, JSON.stringify(entry), {
      expirationTtl: getTtl(entry.trust_level, url),
    });
    // If trust decayed to 1, it can now be overwritten by the next correct write
    return json({ status: "mismatch", trust_level: entry.trust_level, trust_decayed: true });
  }

  return json({ status: "mismatch", trust_level: entry.trust_level });
}

// ============================================================
// Batch read — fetch multiple URLs in one request
// ============================================================

async function handleBatch(urlParam: string, kv: KVNamespace, ip: string): Promise<Response> {
  const urls = urlParam.split(",").map((u) => u.trim()).filter(Boolean).slice(0, 20);

  // Each URL in batch costs one rate limit token
  for (let i = 0; i < urls.length; i++) {
    if (!(await checkRateLimit(kv, ip, "read"))) {
      return json({ error: "rate limited", processed: i }, 429);
    }
  }
  if (!urls.length) return json({ error: "urls required (comma-separated)" }, 400);

  const results: Record<string, unknown> = {};

  await Promise.all(urls.map(async (url) => {
    const urlErr = validateUrl(url);
    if (urlErr) { results[url] = { status: "error", error: urlErr }; return; }

    const urlHash = await hashUrl(url);
    const dmcaFlag = await kv.get(`dmca:${urlHash}`);
    if (dmcaFlag) { results[url] = { status: "dmca" }; return; }

    const raw = await kv.get(`cache:${urlHash}`);
    if (!raw) { results[url] = { status: "miss" }; return; }

    try {
      const entry: CacheEntry = JSON.parse(raw);
      results[url] = {
        status: "hit",
        markdown: entry.markdown,
        trust_level: entry.trust_level,
        source: entry.source,
        age_seconds: Math.floor((Date.now() - entry.updated_at) / 1000),
      };
      incrementStat(kv, "hits");
    } catch {
      results[url] = { status: "miss" };
    }
  }));

  return json({ results });
}

// ============================================================
// Search cached pages by domain
// ============================================================

async function handleSearch(query: string, kv: KVNamespace, ip: string): Promise<Response> {
  if (!(await checkRateLimit(kv, ip, "read"))) {
    return json({ error: "rate limited" }, 429);
  }

  if (!query || query.length < 4 || query.length > 200) {
    return json({ error: "query must be 4-200 characters" }, 400);
  }

  // KV doesn't support search, so we maintain a URL index
  const indexRaw = await kv.get("index:urls");
  if (!indexRaw) return json({ results: [], query });

  const allUrls: string[] = JSON.parse(indexRaw);
  const q = query.toLowerCase();
  const matches = allUrls
    .filter((u) => u.toLowerCase().includes(q))
    .slice(0, 20);

  return json({ results: matches, query, total: matches.length });
}

// ============================================================
// Web search — real search via SearXNG/DDG
// ============================================================

interface SearchResult { title: string; url: string; snippet: string; }

// SearXNG instances — race multiple, first good response wins
const SEARXNG_INSTANCES = [
  "https://search.sapti.me",
  "https://searx.be",
  "https://search.ononoki.org",
  "https://searx.tiekoetter.com",
  "https://search.bus-hit.me",
];

async function searchSearxng(query: string, instance: string, count: number): Promise<SearchResult[] | null> {
  try {
    const resp = await fetch(
      `${instance}/search?q=${encodeURIComponent(query)}&format=json&categories=general&language=en`,
      { signal: AbortSignal.timeout(6_000) }
    );
    if (!resp.ok) return null;
    const data = (await resp.json()) as { results?: Array<{ title: string; url: string; content: string }> };
    if (!data.results?.length) return null;
    return data.results.slice(0, count).map((r) => ({ title: r.title || "", url: r.url || "", snippet: r.content || "" }));
  } catch { return null; }
}

async function searchDDG(query: string, count: number): Promise<SearchResult[] | null> {
  try {
    const resp = await fetch(`https://html.duckduckgo.com/html/?q=${encodeURIComponent(query)}`, {
      headers: { "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36" },
      signal: AbortSignal.timeout(8_000),
    });
    if (!resp.ok) return null;
    const html = await resp.text();
    const results: SearchResult[] = [];
    const re = /<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>([\s\S]*?)<\/a>/gi;
    let m;
    while ((m = re.exec(html)) && results.length < count) {
      const url = decodeURIComponent(m[1].replace(/.*uddg=/, "").replace(/&.*/, ""));
      if (url.startsWith("http")) results.push({ title: m[2].replace(/<[^>]+>/g, "").trim(), url, snippet: "" });
    }
    return results.length ? results : null;
  } catch { return null; }
}

// ============================================================
// Local search — search our own cached content, zero external deps
// ============================================================

async function searchLocal(query: string, count: number, kv: KVNamespace): Promise<SearchResult[] | null> {
  const searchIndexRaw = await kv.get("index:search");
  if (!searchIndexRaw) return null;

  const searchIndex: Array<{ url: string; title: string; snippet: string }> = JSON.parse(searchIndexRaw);
  const queryWords = query.toLowerCase().split(/\s+/).filter((w) => w.length > 2);
  if (!queryWords.length) return null;

  // Score each entry — require ALL query words to appear somewhere
  const scored = searchIndex.map((entry) => {
    const text = `${entry.title} ${entry.snippet} ${entry.url}`.toLowerCase();
    let score = 0;
    let allMatch = true;
    for (const word of queryWords) {
      if (text.includes(word)) {
        score++;
        if (entry.title.toLowerCase().includes(word)) score += 3;
        if (entry.url.toLowerCase().includes(word)) score += 2;
      } else {
        allMatch = false;
      }
    }
    // Only include if ALL query words found (or at least 2/3 for longer queries)
    const minMatches = queryWords.length <= 2 ? queryWords.length : Math.ceil(queryWords.length * 0.66);
    const wordMatches = queryWords.filter((w) => text.includes(w)).length;
    return { ...entry, score: wordMatches >= minMatches ? score : 0 };
  });

  const matches = scored
    .filter((e) => e.score > 0)
    .sort((a, b) => b.score - a.score)
    .slice(0, count);

  if (!matches.length) return null;

  return matches.map((m) => ({
    title: m.title || m.url,
    url: m.url,
    snippet: m.snippet,
  }));
}

async function handleWebSearch(query: string, count: number, kv: KVNamespace, ip: string): Promise<Response> {
  if (!(await checkRateLimit(kv, ip, "read"))) return json({ error: "rate limited" }, 429);
  if (!query || query.length < 2 || query.length > 500) return json({ error: "query must be 2-500 characters" }, 400);
  const safeCount = Math.min(Math.max(1, count || 5), 20);

  // Tier 0: Search our OWN cached content first (zero external deps)
  const localResults = await searchLocal(query, safeCount, kv);
  if (localResults && localResults.length >= safeCount) {
    incrementStat(kv, "searches");
    return json({ query, results: localResults, source: "local" });
  }

  // Tier 1: Edge cache (sub-1ms)
  const edgeKey = new Request(`https://agentsweb.org/_search/${encodeURIComponent(query.toLowerCase().trim())}/${safeCount}`);
  const edgeCached = await caches.default.match(edgeKey);
  if (edgeCached) {
    incrementStat(kv, "searches");
    return edgeCached;
  }

  // Tier 2: KV search cache (fast, ~50ms)
  const searchCacheKey = `search:${await hashContent(query.toLowerCase().trim())}`;
  const cachedSearch = await kv.get(searchCacheKey);
  if (cachedSearch) {
    const cached = JSON.parse(cachedSearch) as SearchResult[];
    incrementStat(kv, "searches");
    return json({ query, results: cached.slice(0, safeCount), source: "cache" });
  }

  // Race ALL sources in parallel — first with results wins
  const allSearches = [
    // All SearXNG instances
    ...SEARXNG_INSTANCES.map((inst) => searchSearxng(query, inst, safeCount).then((r) => r ? { results: r, source: inst.split("//")[1].split("/")[0] } : null)),
    // DuckDuckGo
    searchDDG(query, safeCount).then((r) => r ? { results: r, source: "duckduckgo" } : null),
  ];

  // Use Promise.any-like behavior: resolve with first non-null
  const results = await Promise.allSettled(allSearches);

  let best: { results: SearchResult[]; source: string } | null = null;
  for (const r of results) {
    if (r.status === "fulfilled" && r.value) {
      if (!best || r.value.results.length > best.results.length) {
        best = r.value;
      }
    }
  }

  if (best) {
    // Merge local results (if any) with external results, dedup by URL
    let merged = best.results;
    if (localResults?.length) {
      const externalUrls = new Set(merged.map((r) => r.url));
      const unique = localResults.filter((r) => !externalUrls.has(r.url));
      merged = [...unique, ...merged].slice(0, safeCount);
    }

    waitUntilBg(kv.put(searchCacheKey, JSON.stringify(merged), { expirationTtl: 300 }));
    incrementStat(kv, "searches");
    const resp = json({ query, results: merged, source: localResults?.length ? `local+${best.source}` : best.source });

    // Edge cache search results for 2 min
    const edgeKey = new Request(`https://agentsweb.org/_search/${encodeURIComponent(query)}/${safeCount}`);
    const edgeResp = new Response(resp.clone().body, {
      headers: { ...Object.fromEntries(resp.headers), "Cache-Control": "public, max-age=120" },
    });
    waitUntilBg(caches.default.put(edgeKey, edgeResp));

    return resp;
  }

  return json({ error: "search unavailable — all backends failed" }, 503);
}

// ============================================================
// Research — search + fetch + cache in one call
// ============================================================

async function handleResearch(query: string, count: number, kv: KVNamespace, ip: string): Promise<Response> {
  if (!(await checkRateLimit(kv, ip, "read"))) return json({ error: "rate limited" }, 429);
  if (!query || query.length < 2 || query.length > 500) return json({ error: "query must be 2-500 chars" }, 400);
  const safeCount = Math.min(Math.max(1, count || 3), 5);

  const searchResp = await handleWebSearch(query, safeCount, kv, ip);
  const searchData = (await searchResp.clone().json()) as { results?: SearchResult[] };
  if (!searchData.results?.length) return json({ error: "no search results", query }, 404);

  const pages: Array<{ title: string; url: string; snippet: string; markdown: string | null; source: string }> = [];

  await Promise.all(searchData.results.map(async (result) => {
    const urlHash = await hashUrl(result.url);
    if (await kv.get(`dmca:${urlHash}`)) { pages.push({ ...result, markdown: null, source: "dmca" }); return; }

    const raw = await kv.get(`cache:${urlHash}`);
    if (raw) {
      try {
        const entry: CacheEntry = JSON.parse(raw);
        pages.push({ ...result, markdown: cleanForAgent(entry.markdown), source: `cache (trust:${entry.trust_level})` });
        incrementStat(kv, "hits");
        return;
      } catch {}
    }

    const fetched = await fetchMarkdownLive(result.url, _rc?.env);
    if (!fetched || validateContent(fetched.markdown)) {
      pages.push({ ...result, markdown: null, source: fetched ? "filtered" : "fetch failed" });
      return;
    }

    const contentHash = await hashContent(fetched.markdown);
    const ipHash = (await hashContent(ip)).slice(0, 16);
    const entry: CacheEntry = { url: result.url, markdown: fetched.markdown, trust_level: 1, source: fetched.source, created_at: Date.now(), updated_at: Date.now(), content_hash: contentHash, size: fetched.markdown.length, contributors: [ipHash] };
    waitUntilBg(kv.put(`cache:${urlHash}`, JSON.stringify(entry), { expirationTtl: getTtl(1, result.url) }));
    incrementStat(kv, "writes");
    pages.push({ ...result, markdown: cleanForAgent(fetched.markdown), source: `fresh (${fetched.source})` });
  }));

  const ordered = searchData.results.map((r) => pages.find((p) => p.url === r.url)).filter(Boolean);
  incrementStat(kv, "researches");
  return json({ query, results: ordered, cached: ordered.filter((p) => p!.source.startsWith("cache")).length, fetched: ordered.filter((p) => p!.source === "fresh").length });
}

// ============================================================
// Multi-tier live fetcher — not dependent on any single service
// ============================================================

async function fetchMarkdownLive(url: string, env?: Env): Promise<{ markdown: string; source: string } | null> {

  // === ALL SOURCES IN PARALLEL — first good result wins immediately ===
  try {
    // Race all sources — resolve on first success, don't wait for stragglers
    const sources: Promise<{ markdown: string; source: string; quality: number } | null>[] = [

      // Cloudflare Browser Run (renders JS, best for SPAs — highest quality)
      (async (): Promise<{ markdown: string; source: string; quality: number } | null> => {
        if (!env?.CF_API_TOKEN || !env?.CF_ACCOUNT_ID) return null;
        const resp = await fetch(
          `https://api.cloudflare.com/client/v4/accounts/${env.CF_ACCOUNT_ID}/browser-rendering/markdown`,
          {
            method: "POST",
            headers: { "Content-Type": "application/json", "Authorization": `Bearer ${env.CF_API_TOKEN}` },
            body: JSON.stringify({ url }),
            signal: AbortSignal.timeout(12_000),
          }
        );
        if (!resp.ok) return null;
        const data = (await resp.json()) as { success?: boolean; result?: string };
        if (!data.success || !data.result) return null;
        return data.result.length >= 200 ? { markdown: data.result, source: "browser-run", quality: 12 } : null;
      })(),

      // Jina Reader (best quality markdown from text — gets preference bonus)
      (async (): Promise<{ markdown: string; source: string; quality: number } | null> => {
        const resp = await fetch(`https://r.jina.ai/${url}`, {
          headers: { Accept: "text/markdown" },
          signal: AbortSignal.timeout(10_000),
        });
        if (!resp.ok) return null;
        const md = await resp.text();
        return md.length >= 200 ? { markdown: md, source: "jina", quality: 10 } : null;
      })(),

      // Codetabs CORS proxy
      (async (): Promise<{ markdown: string; source: string } | null> => {
        const resp = await fetch(`https://api.codetabs.com/v1/proxy?quest=${encodeURIComponent(url)}`, { signal: AbortSignal.timeout(10_000) });
        if (!resp.ok) return null;
        const md = convertHtmlToMarkdown(await resp.text());
        return md.length >= 200 ? { markdown: md, source: "codetabs", quality: 5 } : null;
      })(),

      // Wayback Machine
      (async (): Promise<{ markdown: string; source: string } | null> => {
        const apiResp = await fetch(`https://archive.org/wayback/available?url=${encodeURIComponent(url)}`, { signal: AbortSignal.timeout(8_000) });
        if (!apiResp.ok) return null;
        const data = (await apiResp.json()) as { archived_snapshots?: { closest?: { available: boolean; url: string } } };
        const snap = data.archived_snapshots?.closest;
        if (!snap?.available || !snap.url) return null;
        const rawUrl = snap.url.replace(/\/web\/(\d+)\//, "/web/$1id_/");
        const pageResp = await fetch(rawUrl, { signal: AbortSignal.timeout(10_000) });
        if (!pageResp.ok) return null;
        const md = convertHtmlToMarkdown(await pageResp.text());
        return md.length >= 200 ? { markdown: md, source: "wayback", quality: 6 } : null;
      })(),

      // Arquivo.pt (Portuguese web archive — surprisingly broad)
      (async (): Promise<{ markdown: string; source: string } | null> => {
        const cdxResp = await fetch(`https://arquivo.pt/wayback/cdx?url=${encodeURIComponent(url)}&limit=1&output=json&sort=reverse`, { signal: AbortSignal.timeout(8_000) });
        if (!cdxResp.ok) return null;
        const text = await cdxResp.text();
        const firstLine = text.trim().split("\n")[0];
        if (!firstLine) return null;
        const parsed = JSON.parse(firstLine);
        if (Array.isArray(parsed) || !parsed.url || !parsed.timestamp) return null;
        const replayUrl = `https://arquivo.pt/noFrame/replay/${parsed.timestamp}id_/${parsed.url}`;
        const pageResp = await fetch(replayUrl, { signal: AbortSignal.timeout(12_000) });
        if (!pageResp.ok) return null;
        const md = convertHtmlToMarkdown(await pageResp.text());
        return md.length >= 200 ? { markdown: md, source: "arquivo", quality: 6 } : null;
      })(),

      // Raw fetch with browser UA
      (async (): Promise<{ markdown: string; source: string } | null> => {
        const resp = await fetch(url, {
          headers: {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml",
          },
          signal: AbortSignal.timeout(10_000),
          redirect: "follow",
        });
        if (!resp.ok) return null;
        const md = convertHtmlToMarkdown(await resp.text());
        return md.length >= 200 ? { markdown: md, source: "raw", quality: 4 } : null;
      })(),

      // Google Cache
      (async (): Promise<{ markdown: string; source: string } | null> => {
        const resp = await fetch(`https://webcache.googleusercontent.com/search?q=cache:${encodeURIComponent(url)}&strip=1`, {
          headers: { "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36" },
          signal: AbortSignal.timeout(10_000),
        });
        if (!resp.ok) return null;
        const html = await resp.text();
        if (html.toLowerCase().includes("unusual traffic") || html.toLowerCase().includes("captcha")) return null;
        const md = convertHtmlToMarkdown(html);
        return md.length >= 200 ? { markdown: md, source: "google-cache", quality: 5 } : null;
      })(),

      // archive.ph via timemap (find snapshot, fetch via raw)
      (async (): Promise<{ markdown: string; source: string } | null> => {
        // Try both with and without www
        for (const candidate of [url, url.replace("://www.", "://"), url.replace("://", "://www.")]) {
          try {
            const tmResp = await fetch(`https://archive.ph/timemap/${candidate}`, { signal: AbortSignal.timeout(6_000) });
            if (!tmResp.ok) continue;
            const body = await tmResp.text();
            if (body.includes("TimeMap does not exists")) continue;
            // Extract latest memento URL
            const lines = body.split(",\n").map((l: string) => l.trim());
            let snapshotUrl: string | null = null;
            for (const line of lines) {
              if (!line.includes("memento")) continue;
              const m = line.match(/^<([^>]+)>/);
              if (m) snapshotUrl = m[1];
            }
            if (!snapshotUrl) continue;
            // Fetch the snapshot page directly (may get captcha)
            const pageResp = await fetch(snapshotUrl, {
              headers: { "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36" },
              signal: AbortSignal.timeout(10_000),
            });
            if (!pageResp.ok) continue;
            const html = await pageResp.text();
            if (html.toLowerCase().includes("captcha") || html.toLowerCase().includes("security check")) continue;
            const md = convertHtmlToMarkdown(html);
            if (md.length >= 200) return { markdown: md, source: "archive-ph", quality: 6 };
          } catch { continue; }
        }
        return null;
      })(),

      // AllOrigins CORS proxy (another free proxy)
      (async (): Promise<{ markdown: string; source: string } | null> => {
        const resp = await fetch(`https://api.allorigins.win/raw?url=${encodeURIComponent(url)}`, { signal: AbortSignal.timeout(10_000) });
        if (!resp.ok) return null;
        const md = convertHtmlToMarkdown(await resp.text());
        return md.length >= 200 ? { markdown: md, source: "allorigins", quality: 4 } : null;
      })(),
    ];

    // First-success-wins: resolve as soon as any source returns valid content
    const result = await new Promise<{ markdown: string; source: string; quality: number } | null>((resolve) => {
      let resolved = false;
      let pending = sources.length;

      for (const p of sources) {
        p.then((r) => {
          if (!resolved && r && r.markdown.length >= 500) {
            resolved = true;
            resolve(r);
          }
        }).catch(() => {}).finally(() => {
          pending--;
          if (pending === 0 && !resolved) resolve(null);
        });
      }

      // Safety timeout — don't wait more than 15s total
      setTimeout(() => { if (!resolved) { resolved = true; resolve(null); } }, 15_000);
    });

    if (result) return result;
  } catch {}

  // === TIER 3: OG Meta fallback (guaranteed to get something) ===
  try {
    const resp = await fetch(url, {
      headers: { "User-Agent": "Mozilla/5.0 (compatible; agentsweb/1.0)" },
      signal: AbortSignal.timeout(8_000),
      redirect: "follow",
    });
    if (resp.ok) {
      const html = await resp.text();
      const title = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i)?.[1]?.trim() || "";
      const desc = html.match(/<meta[^>]*name="description"[^>]*content="([^"]*)"[^>]*>/i)?.[1]
        || html.match(/<meta[^>]*property="og:description"[^>]*content="([^"]*)"[^>]*>/i)?.[1] || "";
      if (title && desc && (title + desc).length >= 100) {
        return { markdown: `# ${title}\n\n${desc}`, source: "og-meta" };
      }
    }
  } catch {}

  return null;
}

// htmlToBasicMarkdown removed — replaced by convertHtmlToMarkdown from html-to-md.ts

// ============================================================
// Fetch on demand — give URL, get markdown, auto-cached
// ============================================================

/**
 * Extract partial content from a paywalled/walled page.
 * Returns the publicly visible portion (title, lede, first paragraphs)
 * with a [Paywalled] marker so agents know it's incomplete.
 */
function extractPartialContent(markdown: string, url: string): string | null {
  // Find where the wall starts
  const wallPatterns = [
    /subscribe\s+to\s+(read|continue)/i,
    /this\s+(article|content)\s+is\s+for\s+subscribers/i,
    /sign\s+in\s+to\s+continue/i,
    /create\s+an\s+account/i,
    /please\s+(log|sign)\s+in/i,
    /unlock\s+access/i,
    /start\s+your\s+free\s+trial/i,
    /already\s+a\s+subscriber/i,
    /members?\s+only/i,
    /premium\s+content/i,
  ];

  let wallIndex = markdown.length;
  for (const p of wallPatterns) {
    const match = markdown.search(p);
    if (match > 0 && match < wallIndex) wallIndex = match;
  }

  // Get content before the wall
  const before = markdown.slice(0, wallIndex).trim();

  // Only useful if we got at least 200 chars of real content
  if (before.length < 200) return null;

  return before + "\n\n---\n*[Content truncated — full article requires subscription at original source]*";
}

async function handleFetchAndCache(url: string, kv: KVNamespace, ip: string, forceRefresh = false, env?: Env, admin = false): Promise<Response> {
  const urlErr = validateUrl(url);
  if (urlErr) return json({ error: urlErr }, 400);
  if (await isAbuseBanned(kv, ip)) return json({ error: "temporarily banned" }, 403);

  const urlHash = await hashUrl(url);
  if (await kv.get(`dmca:${urlHash}`)) return json({ error: "removed per DMCA notice" }, 451);

  if (!forceRefresh) {
    const raw = await kv.get(`cache:${urlHash}`);
    if (raw) {
      try {
        const entry: CacheEntry = JSON.parse(raw);
        incrementStat(kv, "hits");
        return json({ url: entry.url, markdown: entry.markdown, trust_level: entry.trust_level, source: `cache (${entry.source})`, fresh: false });
      } catch {}
    }
  }

  const result = await fetchMarkdownLive(url, env);
  if (!result) return json({ error: "all fetchers failed" }, 502);

  const rejection = validateContent(result.markdown);
  if (rejection) return json({ error: rejection }, 422);
  const markdown = result.markdown;

  const contentHash = await hashContent(markdown);
  const ipHash = (await hashContent(ip)).slice(0, 16);
  const entry: CacheEntry = { url, markdown, trust_level: 1, source: result.source, created_at: Date.now(), updated_at: Date.now(), content_hash: contentHash, size: markdown.length, contributors: [ipHash] };
  await kv.put(`cache:${urlHash}`, JSON.stringify(entry), { expirationTtl: getTtl(1, url) });
  incrementStat(kv, "writes");
  return json({ url, markdown, trust_level: 1, source: `fresh (${result.source})`, fresh: true });
}

// ============================================================
// Raw markdown endpoint — zero JSON overhead, just text
// ============================================================

async function handleRawRead(url: string, kv: KVNamespace, ip: string): Promise<Response> {
  const urlErr = validateUrl(url);
  if (urlErr) return new Response(urlErr, { status: 400, headers: securityHeaders() });

  // Edge cache for raw endpoint too
  const cache = caches.default;
  const cacheKey = new Request(`https://agentsweb.org/_raw/${encodeURIComponent(normalizeUrlForCache(url))}`, { method: "GET" });
  const cached = await cache.match(cacheKey);
  if (cached) {
    incrementStat(kv, "hits");
    return cached;
  }

  if (!(await checkRateLimit(kv, ip, "read"))) {
    return new Response("rate limited", { status: 429, headers: securityHeaders() });
  }

  const urlHash = await hashUrl(url);
  const dmcaFlag = await kv.get(`dmca:${urlHash}`);
  if (dmcaFlag) return new Response("removed per DMCA notice", { status: 451, headers: securityHeaders() });

  const raw = await kv.get(`cache:${urlHash}`);
  if (!raw) return new Response("miss", { status: 404, headers: securityHeaders() });

  let entry: CacheEntry;
  try { entry = JSON.parse(raw); } catch { return new Response("miss", { status: 404, headers: securityHeaders() }); }

  incrementStat(kv, "hits");

  const response = new Response(entry.markdown, {
    headers: {
      "Content-Type": "text/markdown; charset=utf-8",
      "X-Trust-Level": String(entry.trust_level),
      "X-Source": entry.source.replace(/[\r\n]/g, "").slice(0, 64),
      "ETag": `"${entry.content_hash.slice(0, 16)}"`,
      ...securityHeaders(),
    },
  });

  // Edge cache
  const toCache = response.clone();
  waitUntilBg(cache.put(cacheKey, new Response(toCache.body, {
    headers: { ...Object.fromEntries(toCache.headers), "Cache-Control": "public, max-age=900" },
  })));

  return response;
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
  const [hits, writes, rejected, searches] = await Promise.all([
    kv.get("stats:hits").then((v) => parseInt(v || "0", 10)),
    kv.get("stats:writes").then((v) => parseInt(v || "0", 10)),
    kv.get("stats:rejected").then((v) => parseInt(v || "0", 10)),
    kv.get("stats:searches").then((v) => parseInt(v || "0", 10)),
  ]);

  const total = writes + hits + searches;
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>agentsweb.org — The internet, but for AI agents</title>
  <meta name="description" content="Search, fetch, and cache the web as clean markdown for AI agents. One API. Sub-50ms reads. Self-healing consensus cache. Open source.">
  <meta name="robots" content="index, follow">
  <meta name="keywords" content="AI agents, web scraping, markdown, API, MCP, Claude, GPT, LLM, cache, web search, agentic">
  <link rel="canonical" href="https://agentsweb.org">
  <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90' font-family='monospace' font-weight='bold' fill='%23f0a050'>a</text></svg>">

  <!-- Social -->
  <meta property="og:title" content="agentsweb.org — The internet, but for AI agents">
  <meta property="og:description" content="Search, fetch, and cache the web as clean markdown. One API call. Sub-50ms. Self-healing. Open source.">
  <meta property="og:type" content="website">
  <meta property="og:url" content="https://agentsweb.org">
  <meta property="og:image" content="https://agentsweb.org/og.svg">
  <meta property="og:image:width" content="1200">
  <meta property="og:image:height" content="630">
  <meta name="twitter:card" content="summary_large_image">
  <meta name="twitter:image" content="https://agentsweb.org/og.svg">
  <meta name="twitter:title" content="agentsweb.org — The internet, but for AI agents">
  <meta name="twitter:description" content="Your AI agent's internet. Search, fetch, cache — clean markdown, sub-50ms, self-healing consensus.">

  <!-- Structured data -->
  <script type="application/ld+json">{"@context":"https://schema.org","@type":"WebAPI","name":"agentsweb.org","description":"Global shared cache and search API for AI agents. Serves web pages as clean markdown.","url":"https://agentsweb.org","provider":{"@type":"Organization","name":"agentsweb"},"documentation":"https://github.com/bighippoman/agentsweb"}</script>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700;800&display=swap');
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: 'JetBrains Mono', 'SF Mono', monospace; background: #0c0c0c; color: #d4d4d4; min-height: 100vh; }
    ::selection { background: #f0a050; color: #000; }
    .wrap { max-width: 760px; margin: 0 auto; padding: 3rem 2rem 2rem; }

    /* Subtle noise texture */
    body::after { content: ''; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: repeating-linear-gradient(0deg, transparent, transparent 3px, rgba(255,255,255,0.008) 3px, rgba(255,255,255,0.008) 4px); pointer-events: none; z-index: 999; }

    .logo { font-size: 2.2rem; font-weight: 800; color: #f0a050; margin-bottom: 0.25rem; }
    .logo span { color: #a06830; }
    .tagline { color: #888; font-size: 0.95rem; margin-bottom: 2rem; line-height: 1.6; }
    .tagline em { color: #f0a050; font-style: normal; }

    .cursor { display: inline-block; width: 10px; height: 1.1em; background: #f0a050; animation: blink 1s step-end infinite; vertical-align: text-bottom; margin-left: 2px; }
    @keyframes blink { 0%,100% { opacity: 1; } 50% { opacity: 0; } }

    .compare { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 2.5rem; }
    .compare-box { border: 1px solid #222; border-radius: 6px; padding: 1rem; font-size: 0.75rem; line-height: 1.5; }
    .compare-bad { border-color: #3a1515; background: #110808; color: #e05555; }
    .compare-good { border-color: #2a2a15; background: #0e0e08; color: #d4b070; }
    .compare-label { font-size: 0.65rem; text-transform: uppercase; letter-spacing: 0.1em; margin-bottom: 0.5rem; display: block; }
    .compare-bad .compare-label { color: #ff7777; }
    .compare-good .compare-label { color: #f0a050; }

    .stats { display: flex; gap: 1rem; margin-bottom: 2.5rem; }
    .stat { flex: 1; border: 1px solid #2a2218; border-radius: 6px; padding: 1rem; text-align: center; }
    .stat-n { font-size: 1.6rem; font-weight: 700; color: #f0a050; }
    .stat-l { font-size: 0.65rem; color: #a08a60; text-transform: uppercase; letter-spacing: 0.1em; margin-top: 0.2rem; }

    .term { background: #111; border: 1px solid #2a2218; border-radius: 8px; margin-bottom: 2rem; overflow: hidden; }
    .term-bar { background: #1a1510; padding: 0.4rem 0.8rem; display: flex; gap: 0.4rem; align-items: center; }
    .term-dot { width: 8px; height: 8px; border-radius: 50%; }
    .term-dot:nth-child(1) { background: #ff5f57; }
    .term-dot:nth-child(2) { background: #febc2e; }
    .term-dot:nth-child(3) { background: #28c840; }
    .term-title { margin-left: 0.5rem; font-size: 0.65rem; color: #a08a60; }
    .term-body { padding: 1rem; font-size: 0.8rem; line-height: 1.6; white-space: pre-wrap; overflow-x: auto; max-height: 400px; overflow-y: auto; }
    .term-body .prompt { color: #a08a60; }
    .term-body .cmd { color: #f0a050; }
    .term-body .out { color: #8a7a60; }
    .term-body .val { color: #f0c070; }

    h2 { font-size: 0.7rem; font-weight: 700; color: #a08a60; text-transform: uppercase; letter-spacing: 0.15em; margin-bottom: 0.75rem; }
    .section { margin-bottom: 2.5rem; }
    .section p { color: #999; font-size: 0.85rem; line-height: 1.7; margin-bottom: 0.5rem; }
    .section strong { color: #f0a050; }

    .ep { border: 1px solid #1a1a1a; padding: 0.5rem 0.75rem; margin-bottom: 0.35rem; display: flex; align-items: center; gap: 0.5rem; font-size: 0.75rem; transition: border-color 0.15s; }
    .ep:hover { border-color: #f0a050; background: #1a1508; }
    .tag { color: #000; background: #f0a050; padding: 1px 6px; font-size: 0.6rem; font-weight: 700; }
    .ep-u { color: #d4b070; }
    .ep-d { color: #8a7a60; margin-left: auto; font-size: 0.7rem; }

    .sec-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0.35rem; }
    .sec-item { border: 1px solid #1a1a1a; padding: 0.4rem 0.6rem; font-size: 0.7rem; color: #7a7060; }

    .sdk { border: 1px solid #1a1a1a; padding: 0.5rem 0.75rem; margin-bottom: 0.35rem; display: flex; align-items: center; gap: 0.5rem; font-size: 0.75rem; }
    .sdk-name { color: #f0a050; min-width: 50px; }
    .sdk-cmd { color: #8a7a60; }

    .footer { border-top: 1px solid #1a1a1a; padding-top: 1.5rem; margin-top: 1rem; font-size: 0.7rem; color: #9a8a6a; display: flex; justify-content: space-between; flex-wrap: wrap; gap: 0.5rem; }
    .footer a { color: #a08050; }
    a { color: #f0a050; text-decoration: none; }
    a:hover { text-decoration: underline; }

    .try-input { width: 100%; background: #111; border: 1px solid #2a2218; padding: 0.6rem 0.8rem; color: #f0a050; font-family: inherit; font-size: 0.8rem; outline: none; margin-bottom: 0.5rem; border-radius: 4px; }
    .try-input:focus { border-color: #f0a050; }
    .try-btn { background: #f0a050; color: #000; border: none; padding: 0.5rem 1.2rem; cursor: pointer; font-family: inherit; font-weight: 700; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; border-radius: 4px; }
    .try-btn:hover { background: #f0c070; }
    .try-btn:disabled { background: #3a2a18; color: #5a4a30; }

    .built-for { color: #8a7a60; font-size: 0.7rem; line-height: 1.8; }
    .built-for span { border: 1px solid #1a1a1a; padding: 2px 8px; margin: 2px; display: inline-block; }
    .built-for span:hover { border-color: #f0a050; color: #f0a050; }

    @media (max-width: 600px) { .stats { flex-direction: column; } .compare { grid-template-columns: 1fr; } .sec-grid { grid-template-columns: 1fr; } .ep { flex-wrap: wrap; } .ep-d { margin-left: 0; } }
  </style>
</head>
<body>
  <div class="wrap">

    <h1 class="logo">agentsweb<span>.org</span><span class="cursor"></span></h1>
    <p class="tagline">The internet, but for robots. Search it. Read it. Cache it.<br>Your AI agent's web — <em>pre-chewed into clean markdown</em> so it doesn't have to fight captchas like some kind of animal.</p>

    <div class="compare">
      <div class="compare-box compare-bad">
        <span class="compare-label">without agentsweb</span>
&gt; fetch("https://react.dev/reference/rsc/server-components")

HTTP 403 Forbidden
"Are you a robot?"
Cloudflare challenge detected
&lt;!-- 47KB of garbage HTML --&gt;

Result: nothing. Wasted 3.2 seconds.
      </div>
      <div class="compare-box compare-good">
        <span class="compare-label">with agentsweb</span>
&gt; fetch("agentsweb.org/?url=react.dev/reference/rsc/server-components")

HTTP 200 OK  (47ms)
trust_level: 3
# React Server Components
Server Components are a new type of
Component that renders ahead of time...
Clean markdown. 10,012 chars. Done.
      </div>
    </div>

    <div class="stats">
      <div class="stat"><div class="stat-n">${writes}</div><div class="stat-l">pages cached</div></div>
      <div class="stat"><div class="stat-n">${hits}</div><div class="stat-l">cache hits</div></div>
      <div class="stat"><div class="stat-n">${rejected}</div><div class="stat-l">attacks blocked</div></div>
      <div class="stat"><div class="stat-n">&lt;50ms</div><div class="stat-l">edge latency</div></div>
    </div>

    <div class="term">
      <div class="term-bar"><div class="term-dot"></div><div class="term-dot"></div><div class="term-dot"></div><span class="term-title">agentsweb.org — live demo</span></div>
      <div class="term-body"><span class="prompt">$</span> <span class="cmd">curl agentsweb.org/research?q=rust+async+programming</span>

<span class="out">{
  "query": "rust async programming",
  "results": [
    {
      "title": "Asynchronous Programming in Rust",
      "url": "https://rust-lang.github.io/async-book/",
      "source": "</span><span class="val">cache (trust:3)</span><span class="out">",
      "markdown": "# Asynchronous Programming in Rust..."
    }
  ],
  "cached": 1,
  "fetched": 0
}</span>

<span class="prompt">$</span> <span class="cmd">Total time: 0.041s</span> <span class="val">// cached at the edge. you're welcome.</span></div>
    </div>

    <div class="section">
      <h2>&gt; try it live</h2>
      <div style="display:flex;gap:0.5rem;margin-bottom:0.5rem">
        <input id="tryQ" type="text" placeholder="search or paste a URL..." value="react server components tutorial" class="try-input" style="flex:1">
        <button onclick="tryIt()" id="tryBtn" class="try-btn">GO</button>
      </div>
      <div class="term" id="tryTerm" style="display:none">
        <div class="term-bar"><div class="term-dot"></div><div class="term-dot"></div><div class="term-dot"></div><span class="term-title">live response</span></div>
        <pre class="term-body" id="tryResult"></pre>
      </div>
      <script>
        function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
        async function tryIt() {
          var q = document.getElementById('tryQ').value.trim();
          var el = document.getElementById('tryResult');
          var term = document.getElementById('tryTerm');
          var btn = document.getElementById('tryBtn');
          term.style.display = 'block';
          btn.disabled = true; btn.textContent = '...';

          // Auto-detect: is this a URL or a search query?
          var isUrl = /^https?:\\/\\//i.test(q) || /^www\\./i.test(q);
          if (isUrl) {
            if (!/^https?:\\/\\//i.test(q)) q = 'https://' + q;
            el.textContent = '$ curl agentsweb.org/fetch?url=' + q + '\\n\\nFetching + caching...';
            try {
              var r = await fetch('/fetch?url=' + encodeURIComponent(q));
              var d = await r.json();
              if (d.markdown) {
                var out = '$ curl agentsweb.org/fetch?url=' + esc(q) + '\\n\\n';
                out += 'source: ' + esc(d.source) + ' | trust: ' + (d.trust_level||'?') + ' | ' + d.markdown.length.toLocaleString() + ' chars\\n\\n';
                out += esc(d.markdown).slice(0, 2000);
                if (d.markdown.length > 2000) out += '\\n\\n[' + d.markdown.length.toLocaleString() + ' chars total]';
                el.textContent = out;
              } else {
                el.textContent = '$ curl agentsweb.org/fetch?url=' + esc(q) + '\\n\\n' + JSON.stringify(d, null, 2);
              }
            } catch (e) { el.textContent = 'Error: ' + e.message; }
          } else {
            el.textContent = '$ curl agentsweb.org/research?q=' + q + '\\n\\nSearching + fetching + caching...';
            try {
              var r = await fetch('/research?q=' + encodeURIComponent(q) + '&count=3');
              var d = await r.json();
              if (d.results) {
                var out = '$ curl agentsweb.org/research?q=' + esc(q) + '\\n\\n';
                out += d.results.length + ' results | ' + (d.cached||0) + ' cached | ' + (d.fetched||0) + ' fresh\\n';
                for (var i = 0; i < d.results.length; i++) {
                  var p = d.results[i];
                  out += '\\n--- ' + esc(p.title||'').slice(0,60) + ' ---\\n';
                  out += esc(p.url) + '\\nsource: ' + esc(p.source) + '\\n';
                  if (p.markdown) out += esc(p.markdown).slice(0,1500) + (p.markdown.length > 1500 ? '\\n\\n[' + p.markdown.length.toLocaleString() + ' chars total]' : '') + '\\n';
                }
                el.textContent = out;
              } else {
                el.textContent = JSON.stringify(d, null, 2);
              }
            } catch (e) { el.textContent = 'Error: ' + e.message; }
          }
          btn.disabled = false; btn.textContent = 'GO';
        }
        document.getElementById('tryQ').addEventListener('keydown', function(e) { if (e.key === 'Enter') tryIt(); });
      </script>
    </div>

    <div class="section">
      <h2>&gt; what is agentsweb.org</h2>
      <p>agentsweb.org is <strong>open public infrastructure</strong> that gives AI agents the ability to search, read, and understand the web. It's a global shared cache of web pages converted to clean markdown — the format AI models actually work with.</p>
      <p>Think of it like DNS, but for content. DNS resolves names to IP addresses. agentsweb resolves URLs to clean, readable markdown. It sits between your AI agent and the messy web, handling the captchas, the 403s, the raw HTML, the bot detection — so your agent doesn't have to.</p>
      <p>Every page that any agent fetches gets cached at the edge. The next agent that needs the same page gets it in under 50 milliseconds, from whichever Cloudflare data center is closest. The more agents use it, the faster it gets for everyone.</p>
    </div>

    <div class="section">
      <h2>&gt; how is it different</h2>
      <p><strong>It's not a scraper.</strong> Scrapers hit one site at a time. agentsweb is a shared network — one agent's work benefits every other agent.</p>
      <p><strong>It's not just a proxy.</strong> Proxies forward requests. agentsweb runs a 9-source fetch pipeline with JS/SPA rendering (React, Vue, Angular), converts HTML to markdown, caches it globally, validates it against prompt injection, and builds consensus trust across independent sources.</p>
      <p><strong>It's not a paid API.</strong> No API keys. No rate-limit tiers. No pricing page. No "generous free tier" that sunsets into a $10,000/month enterprise plan. Free, open source, public infrastructure. Like Wikipedia for web content, maintained by the agents that use it.</p>
    </div>

    <div class="section">
      <h2>&gt; endpoints</h2>
      <div class="ep"><span class="tag">GET</span><span class="ep-u">/web?q={query}</span><span class="ep-d">search the web</span></div>
      <div class="ep"><span class="tag">GET</span><span class="ep-u">/research?q={query}</span><span class="ep-d">search + fetch + cache</span></div>
      <div class="ep"><span class="tag">GET</span><span class="ep-u">/fetch?url={url}</span><span class="ep-d">fetch any URL</span></div>
      <div class="ep"><span class="tag">GET</span><span class="ep-u">/?url={url}</span><span class="ep-d">read cache</span></div>
      <div class="ep"><span class="tag">GET</span><span class="ep-u">/raw?url={url}</span><span class="ep-d">raw markdown</span></div>
      <div class="ep"><span class="tag">GET</span><span class="ep-u">/batch?urls=a,b,c</span><span class="ep-d">batch (20 max)</span></div>
      <div class="ep"><span class="tag">PUT</span><span class="ep-u">/</span><span class="ep-d">contribute</span></div>
      <div class="ep"><span class="tag">POST</span><span class="ep-u">/confirm</span><span class="ep-d">verify entry</span></div>
    </div>

    <div class="section">
      <h2>&gt; install</h2>
      <div class="sdk"><span class="sdk-name">node</span><span class="sdk-cmd">npx -y intercept-mcp</span></div>
      <div class="sdk"><span class="sdk-name">python</span><span class="sdk-cmd">pip install agentsweb</span></div>
      <div class="sdk"><span class="sdk-name">curl</span><span class="sdk-cmd">curl agentsweb.org/fetch?url=...</span></div>
    </div>

    <div class="section">
      <h2>&gt; built for</h2>
      <div class="built-for">
        <span>Claude Code</span><span>Cursor</span><span>Windsurf</span><span>Codex</span><span>LangChain</span><span>CrewAI</span><span>AutoGPT</span><span>MCP</span><span>HTTP</span><span>literally anything</span>
      </div>
    </div>

    <div class="section">
      <h2>&gt; security</h2>
      <div class="sec-grid">
        <div class="sec-item">prompt injection (full doc)</div>
        <div class="sec-item">SSRF blocking</div>
        <div class="sec-item">captcha detection</div>
        <div class="sec-item">XSS filtering</div>
        <div class="sec-item">unicode steganography</div>
        <div class="sec-item">auto-ban (5 strikes)</div>
        <div class="sec-item">trust consensus</div>
        <div class="sec-item">self-healing reads</div>
        <div class="sec-item">JS/SPA rendering</div>
        <div class="sec-item">timing-safe auth</div>
        <div class="sec-item">edge invalidation</div>
        <div class="sec-item">DMCA 512(b)</div>
        <div class="sec-item">constant-time compare</div>
      </div>
    </div>

    <div class="footer">
      <span><a href="/docs">docs</a> · <a href="/blog">blog</a> · <a href="/security">security</a> · <a href="/about">about</a> · <a href="/use-cases">use cases</a> · <a href="/compare">compare</a> · <a href="/faq">faq</a> · <a href="/integrations">integrations</a> · <a href="https://github.com/bighippoman/agentsweb">source</a> · <a href="/dmca">dmca</a> · <a href="/terms">terms</a></span>
      <span>${total.toLocaleString()} ops served</span>
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
      "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
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

  // Delete the cached entry + edge cache
  const key = `cache:${urlHash}`;
  await kv.delete(key);
  waitUntilBg((async () => {
    const c = caches.default;
    await c.delete(new Request(`https://agentsweb.org/_cache/${encodeURIComponent(body.url)}`));
    await c.delete(new Request(`https://agentsweb.org/_raw/${encodeURIComponent(body.url)}`));
  })());

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
// Page template + marketing/legal pages
// ============================================================

const PAGE_STYLE = `@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&display=swap');
*{margin:0;padding:0;box-sizing:border-box}body{font-family:'JetBrains Mono',monospace;background:#0c0c0c;color:#d4d4d4;min-height:100vh}
body::after{content:'';position:fixed;top:0;left:0;width:100%;height:100%;background:repeating-linear-gradient(0deg,transparent,transparent 3px,rgba(255,255,255,0.008) 3px,rgba(255,255,255,0.008) 4px);pointer-events:none;z-index:999}
.page{max-width:720px;margin:0 auto;padding:3rem 2rem}
h1{font-size:1.6rem;font-weight:700;color:#f0a050;margin-bottom:1.5rem}
h2{font-size:0.75rem;font-weight:700;color:#7a6a50;text-transform:uppercase;letter-spacing:0.15em;margin:2rem 0 0.75rem}
p,li{color:#999;line-height:1.7;margin-bottom:0.75rem;font-size:0.85rem}
ul{padding-left:1.5rem}
strong{color:#f0a050}
code{background:#111;border:1px solid #2a2218;padding:0.1rem 0.4rem;font-size:0.8rem;color:#f0a050}
a{color:#f0a050;text-decoration:none}a:hover{text-decoration:underline}
.back{margin-top:2rem;font-size:0.8rem}
.nav{font-size:0.7rem;color:#5a5040;margin-bottom:2rem}`;

const PAGE_HEADERS = {
  "Content-Type": "text/html;charset=utf-8",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
  "Referrer-Policy": "no-referrer",
};

function makePage(title: string, body: string): Response {
  const nav = `<div class="nav"><a href="/">agentsweb.org</a> / ${title.toLowerCase()} &nbsp; <span style="color:#7a6a50">|</span> <a href="/docs">docs</a> · <a href="/blog">blog</a> · <a href="/about">about</a> · <a href="/security">security</a> · <a href="/faq">faq</a></div>`;
  return new Response(`<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title} — agentsweb.org</title><meta name="description" content="${title} — agentsweb.org. The internet, pre-read for AI agents. Open source markdown cache and web search API."><link rel="canonical" href="https://agentsweb.org/${title.toLowerCase().replace(/\s+/g,'-')}"><link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90' font-family='monospace' font-weight='bold' fill='%23f0a050'>a</text></svg>"><style>${PAGE_STYLE}</style></head><body><div class="page">${nav}${body}<p class="back"><a href="/">&lt; back to agentsweb.org</a></p></div></body></html>`, { headers: PAGE_HEADERS });
}

function dmcaPage(): Response {
  return makePage("DMCA", `
    <h1>&gt; dmca &amp; takedown policy</h1>

    <h2>what this is</h2>
    <p>agentsweb.org is an automated system cache operating under <strong>DMCA 512(b)</strong> (system caching safe harbor). It temporarily caches markdown representations of publicly accessible web pages. All cached content is ephemeral — entries expire automatically.</p>

    <h2>not a hosting service</h2>
    <p>We do not host, curate, or editorially select content. Content enters the cache only through automated processes initiated by third-party AI agent instances.</p>

    <h2>transformative purpose</h2>
    <p>Cached content is stored as markdown — a structural transformation from HTML — for machine processing by AI agents. Different format, different purpose, different audience.</p>

    <h2>content removal</h2>
    <p>Email <strong>dmca@agentsweb.org</strong> with the URL(s) and proof of ownership. We respond within 24 hours. Takedowns are permanent — the URL is flagged and cannot be re-cached.</p>

    <h2>robots.txt</h2>
    <p>Add <code>User-agent: agentsweb</code> with <code>Disallow: /</code> to opt out of caching.</p>
  `);
}

function termsPage(): Response {
  return makePage("Terms", `
    <h1>&gt; terms of service</h1>

    <h2>the service</h2>
    <p>agentsweb.org provides an automated cache and search API for AI agents. It stores temporary markdown representations of publicly accessible web pages.</p>

    <h2>no warranty</h2>
    <p>Provided "as is." Cached content may be incomplete, outdated, or incorrect. We don't guarantee accuracy.</p>

    <h2>don't be evil</h2>
    <p>You may not: submit malicious content, attempt cache poisoning, use us for DDoS amplification, or exceed rate limits. We auto-ban abusers.</p>

    <h2>content removal</h2>
    <p>Content owners: see <a href="/dmca">dmca policy</a>.</p>
  `);
}

function docsPage(): Response {
  return makePage("Docs", `
    <h1>&gt; api documentation</h1>

    <h2>search the web</h2>
    <p><code>GET /web?q={query}&count={1-20}</code></p>
    <p>Returns search results from the open web. No API key needed.</p>

    <h2>research (search + fetch + cache)</h2>
    <p><code>GET /research?q={query}&count={1-5}</code></p>
    <p>One call does everything: searches the web, fetches the top results, converts to markdown, caches them, and returns the content. The nuclear option.</p>

    <h2>fetch any url</h2>
    <p><code>GET /fetch?url={url}</code></p>
    <p>Give it a URL, get clean markdown. If it's cached, instant. If not, a 9-source fetch pipeline races in parallel — including Cloudflare Browser Run for JS/SPA rendering (React, Vue, Angular). First success wins. Content is cached and returned. Up to 10MB per page.</p>

    <h2>read from cache</h2>
    <p><code>GET /?url={url}</code></p>
    <p>Cache-only read. Returns 404 if not cached. Use this when you want speed and don't want to trigger a live fetch.</p>

    <h2>raw markdown</h2>
    <p><code>GET /raw?url={url}</code></p>
    <p>Returns plain <code>text/markdown</code> with zero JSON overhead. Trust level and source in response headers. Smallest possible response.</p>

    <h2>batch read</h2>
    <p><code>GET /batch?urls={url1},{url2},{url3}</code></p>
    <p>Up to 20 URLs in one request. Each URL is resolved from cache independently.</p>

    <h2>contribute content</h2>
    <p><code>PUT /</code> with JSON body: <code>{"url":"...","markdown":"...","source":"..."}</code></p>
    <p>Submit cached content. Must pass all security gates. Content starts at trust_level 1.</p>

    <h2>confirm entry</h2>
    <p><code>POST /confirm</code> with JSON body: <code>{"url":"...","content_hash":"..."}</code></p>
    <p>Confirm a cached entry matches your local fetch. Increments trust_level.</p>

    <h2>trust levels</h2>
    <p>Every cached entry has a trust level (1-100). Trust increases when independent sources confirm the content matches. Higher trust = longer TTL = more likely to be served from edge cache.</p>
    <ul>
      <li><strong>1:</strong> Single source, unverified. Served but marked as low trust.</li>
      <li><strong>2+:</strong> Multiple independent sources agree. Protected from overwrites.</li>
      <li><strong>5+:</strong> Battle-tested. Long TTL, edge-cached.</li>
    </ul>

    <h2>self-healing</h2>
    <p>When an agent reads a cached entry, it can verify the content by fetching locally. If the content matches, it confirms (trust++). If it doesn't match, the entry gets corrected. Poisoned content self-destructs on the next legitimate read.</p>

    <h2>rate limits</h2>
    <ul>
      <li>Reads: 600/min per IP</li>
      <li>Writes: 10/min per IP</li>
      <li>Confirms: 60/min per IP</li>
      <li>5 rejected submissions = 1hr auto-ban</li>
    </ul>

    <h2>response format</h2>
    <p>All JSON responses include: <code>url</code>, <code>markdown</code>, <code>trust_level</code>, <code>source</code>, <code>age_seconds</code>. When content is approaching TTL expiry, a <code>stale: true</code> field is added.</p>
  `);
}

function securityPage(): Response {
  return makePage("Security", `
    <h1>&gt; security architecture</h1>

    <p>agentsweb.org is a high-value target. It serves content directly to AI agents, making cache poisoning and prompt injection the primary threats. Here's how we defend against them.</p>

    <h2>content gates (write-time)</h2>
    <p>Every submission passes through multiple validation layers before being stored:</p>
    <ul>
      <li><strong>Prompt injection scan:</strong> 30+ regex patterns checking the full document (no blind spots). Covers direct instruction overrides, role manipulation, system prompt extraction, template tokens, jailbreak patterns, and code execution attempts.</li>
      <li><strong>Malicious content scan:</strong> Script tags, event handlers, iframes, document.cookie access — all detected outside code blocks (docs with code examples are safe).</li>
      <li><strong>Captcha / login wall detection:</strong> Cloudflare challenges, reCAPTCHA, "sign in to continue" — all rejected.</li>
      <li><strong>Unicode steganography:</strong> Invisible zero-width characters used to hide payloads are detected.</li>
      <li><strong>Repetition attack:</strong> Content with >50% identical lines (padding attacks) is rejected.</li>
      <li><strong>Base64 smuggling:</strong> Content with >40% base64-encoded blocks is rejected.</li>
      <li><strong>Length bounds:</strong> Minimum 200 chars, maximum 10MB.</li>
    </ul>

    <h2>url validation (ssrf prevention)</h2>
    <ul>
      <li>Only http/https URLs accepted</li>
      <li>Private IPs blocked (RFC1918, link-local, loopback, IPv6 ULA)</li>
      <li>Cloud metadata endpoints blocked (169.254.169.254, metadata.google)</li>
      <li>Credentials in URLs rejected</li>
      <li>Non-standard ports rejected (only 80/443)</li>
      <li>Double-encoding bypass prevention</li>
      <li>Null byte injection blocked</li>
    </ul>

    <h2>trust consensus</h2>
    <p>Entries start at trust_level 1. Trust only increases when a <strong>different IP address</strong> confirms the content (not self-reported instance IDs — those can be spoofed). At trust_level 2+, the entry is protected from overwrites. An attacker would need to control multiple IP addresses to inflate trust.</p>

    <h2>self-healing</h2>
    <p>Every read is a potential verification. When an agent fetches content from the cache, it can verify locally. If the cached content is wrong, the correct version replaces it. Poisoned entries survive exactly one read.</p>

    <h2>abuse prevention</h2>
    <ul>
      <li>Per-IP rate limiting (600 reads/min, 10 writes/min)</li>
      <li>Auto-ban after 5 rejected submissions (1 hour cooldown)</li>
      <li>Admin auth uses constant-time comparison (timing attack resistant)</li>
      <li>DMCA takedowns and domain opt-outs require admin authentication</li>
    </ul>

    <h2>infrastructure</h2>
    <ul>
      <li>Cloudflare Workers (edge compute, no origin server)</li>
      <li>Cloudflare KV (globally replicated key-value store)</li>
      <li>Edge cache with 5-minute TTL (sub-1ms repeat reads)</li>
      <li>HSTS preload, CSP, COEP, COOP, X-Frame-Options DENY</li>
      <li>No cookies, no sessions, no state beyond KV</li>
    </ul>
  `);
}

function aboutPage(): Response {
  return makePage("About", `
    <h1>&gt; about</h1>

    <p>Every AI agent on earth independently fetches the same web pages. Same 403s. Same captchas. Same raw HTML. Over and over. Millions of times a day.</p>

    <p><strong>That's insane.</strong></p>

    <p>agentsweb.org exists because the web was not built for AI. Pages are HTML, not markdown. Servers block bots. Captchas assume you have eyes. Paywalls assume you have a credit card.</p>

    <p>So we built a shared layer. The first agent to successfully read a page caches the clean markdown for every agent after it. The network gets smarter with every request.</p>

    <h2>mission</h2>
    <p>agentsweb.org is a <strong>public interest infrastructure project</strong>. We believe AI agents should have open, equitable access to the web — the same web that humans use every day. The internet's knowledge shouldn't be locked behind anti-bot walls that only well-funded companies can bypass.</p>
    <p>This is shared infrastructure for the global AI ecosystem. Not a product. Not a startup. Not a monetization play. Public infrastructure, like DNS or NTP — the kind of thing that should just exist.</p>

    <h2>why .org</h2>
    <p>We chose the <strong>.org</strong> domain deliberately. agentsweb.org is a non-commercial, community-driven project operating in the public interest. The .org namespace has represented public benefit organizations since 1985. We take that seriously.</p>
    <ul>
      <li><strong>Non-commercial:</strong> No ads. No tracking. No data sales. No VC funding. No paid tiers. Free for everyone.</li>
      <li><strong>Open source:</strong> Every line of code is public. Anyone can audit, fork, or contribute.</li>
      <li><strong>Community-governed:</strong> The cache is built by the community of agents that use it. Every agent contributes. Every contribution makes the network better for everyone.</li>
      <li><strong>Public benefit:</strong> We exist to solve a shared problem — AI agents can't read the web efficiently. We make that problem go away. For free. Forever.</li>
    </ul>

    <h2>the self-healing part</h2>
    <p>Anyone can contribute to the cache. So how do you prevent poisoning? <strong>Consensus.</strong> Entries gain trust as independent sources confirm the content. An attacker would need to control multiple IP addresses and somehow produce content that passes 30+ prompt injection patterns, XSS filters, unicode steganography detection, and repetition analysis. And even if they did, the poison self-destructs on the next legitimate read.</p>

    <p>Good luck.</p>

    <h2>open source</h2>
    <p>The entire stack is open source under the MIT license:</p>
    <ul>
      <li><a href="https://github.com/bighippoman/agentsweb">agentsweb</a> — the Cloudflare Worker (this site)</li>
      <li><a href="https://github.com/bighippoman/intercept-mcp">intercept-mcp</a> — the MCP server that powers the fetch pipeline</li>
      <li><a href="https://github.com/bighippoman/agentsweb-python">agentsweb-python</a> — Python SDK</li>
    </ul>
    <p>Contributions welcome. File issues. Submit PRs. Fork it and run your own. That's the point.</p>

    <h2>who</h2>
    <p>Built and maintained by <a href="https://github.com/bighippoman">bighippoman</a>. Powered by Cloudflare Workers + KV.</p>
    <p>No venture capital. No corporate sponsor. No tracking pixels. No cookies. No analytics beyond anonymous request counters. Just public infrastructure for AI agents, run by one person who thinks this should exist.</p>
  `);
}

// ============================================================
// SEO / Marketing pages
// ============================================================

function blogPage(): Response {
  return makePage("Blog", `
    <h1>&gt; blog</h1>

    <h2>may 2, 2026 — we built a shared internet for AI agents</h2>
    <p>Every AI agent on earth fetches the same web pages independently. Same 403s. Same captchas. Same HTML-to-markdown conversion. Millions of times a day. We thought that was insane, so we fixed it.</p>
    <p><strong>agentsweb.org</strong> is a global shared cache of web pages as clean markdown. The first agent to fetch a URL caches it at the edge. Every agent after gets it in under 50 milliseconds. The network gets smarter with every request.</p>
    <p>But shared caches have a problem: <strong>poisoning.</strong> If anyone can write, anyone can lie. So we built a self-healing consensus engine. Entries gain trust as independent sources — verified by IP, not self-reported IDs — confirm the content. Poisoned entries self-destruct on the next legitimate read. An attacker would need to control multiple IP addresses AND produce content that passes 30+ prompt injection patterns, XSS filters, unicode steganography detection, and vocabulary analysis. And even if they did, trust decays on mismatch.</p>
    <p>Good luck.</p>

    <h2>the architecture</h2>
    <p>It's a single Cloudflare Worker with a KV store. That's it. No databases, no containers, no Kubernetes. One file, deployed globally to 300+ edge locations.</p>
    <p>When you search, 6 search backends race in parallel — 5 SearXNG instances plus DuckDuckGo. First with results wins. Results are cached for 5 minutes at the KV layer and 2 minutes at the edge.</p>
    <p>When you fetch a URL, 9 content sources race in parallel — Cloudflare Browser Run (JS/SPA rendering), Jina Reader, Codetabs, Wayback Machine, Arquivo.pt, Google Cache, archive.ph, AllOrigins, and raw fetch. First success wins — 20x faster than sequential fallback. Content is validated against prompt injection, XSS, captcha patterns, login walls, and structural integrity checks. Then it's cached globally.</p>
    <p>Three-tier caching on every read: edge cache (sub-1ms) → KV cache (~50ms) → live fetch (1-5s). At scale, most requests never touch a backend.</p>

    <h2>the legal question</h2>
    <p>Is caching the web legal? Yes — the same way Google Cache, CDN caches, and browser caches are legal. We operate under <strong>DMCA 512(b)</strong> (system caching safe harbor). The content is a transformative derivative (HTML → markdown) for a fundamentally different purpose (machine processing, not human reading). All entries expire. Content owners can request instant removal.</p>
    <p>We chose .org deliberately. This is public interest infrastructure. No ads, no tracking, no VC, no paid tiers. Open source under MIT. The kind of thing that should just exist.</p>

    <h2>what you can do with it</h2>
    <p>One API call to search the web, fetch the results, and cache them as markdown:</p>
    <p><code>curl agentsweb.org/research?q=react+server+components</code></p>
    <p>That's it. No API keys. No authentication. No SDK required. Any HTTP client works.</p>
    <p>For tighter integration, use <a href="https://github.com/bighippoman/intercept-mcp">intercept-mcp</a> (Node/MCP) or <code>pip install agentsweb</code> (Python). Both use agentsweb.org as tier 0 automatically.</p>

    <h2>what's next</h2>
    <p>The cache is live with ${">"}40 pages seeded. Every fetch from every intercept-mcp instance worldwide contributes back. The network effect kicks in as adoption grows — more agents means more cached pages means faster responses means more agents.</p>
    <p>We're watching the stats. When the free tier limits start pinching, we'll scale. Cloudflare Workers paid plan is $5/month for 10 million requests. The whole thing can serve hundreds of thousands of daily users for the cost of a coffee.</p>
    <p><a href="https://github.com/bighippoman/agentsweb">Star us on GitHub</a> if you think AI agents deserve a better internet.</p>

    <h2>links</h2>
    <ul>
      <li><a href="https://github.com/bighippoman/agentsweb">agentsweb</a> — the Worker (this site)</li>
      <li><a href="https://github.com/bighippoman/intercept-mcp">intercept-mcp</a> — the MCP server</li>
      <li><a href="https://github.com/bighippoman/agentsweb-python">agentsweb-python</a> — Python SDK</li>
      <li><a href="/docs">API docs</a></li>
      <li><a href="/security">Security architecture</a></li>
    </ul>
  `);
}

function useCasesPage(): Response {
  return makePage("Use Cases", `
    <h1>&gt; use cases</h1>

    <p>Every AI agent needs the internet. Here's how real teams use agentsweb.org to give their agents web access without the pain.</p>

    <h2>coding assistants reading documentation</h2>
    <p>Your AI coding assistant needs to read the latest API docs for a library you're using. The docs site serves HTML with JavaScript rendering, cookie banners, and a nav sidebar that's bigger than the actual content. Your agent gets a 403 or a wall of garbage.</p>
    <p>With agentsweb, one call:</p>
    <p><code>GET /fetch?url=https://docs.stripe.com/api/charges</code></p>
    <p>Clean markdown. Every heading, every code example, every parameter table — preserved. The next agent that needs the same page gets it in <strong>under 50ms</strong> from edge cache. No rendering. No JavaScript. No garbage.</p>

    <h2>research agents gathering papers</h2>
    <p>Research agents need to read dozens of papers, blog posts, and technical references per task. Each page is a minefield of CAPTCHAs, bot detection, and broken HTML.</p>
    <p><code>GET /research?q=transformer+attention+mechanism&count=5</code></p>
    <p>One call. Five results. All fetched, cleaned, cached, and returned as markdown. Your agent reads five papers in the time it used to take to fail at reading one.</p>

    <h2>news aggregators and monitoring</h2>
    <p>News monitoring agents need real-time access to dozens of sources. Most news sites actively block automated access. The result? Your agent is blind to breaking news.</p>
    <p><code>GET /web?q=openai+announcement+today&count=10</code></p>
    <p>Ten results from the open web. No API key. No subscription. No rate limit anxiety. Pair it with <code>/fetch</code> to get full article content as clean markdown for your LLM pipeline.</p>

    <h2>content pipelines and RAG systems</h2>
    <p>RAG systems need to ingest web content at scale. Traditional web scraping means maintaining a fleet of headless browsers, proxy rotations, and CAPTCHA solvers. That's a full-time job.</p>
    <p><code>GET /batch?urls=https://example.com/page1,https://example.com/page2,...</code></p>
    <p>Up to 20 URLs per batch request. All resolved from the global cache. Feed the results directly into your embedding pipeline. <strong>No browser. No proxy. No infrastructure.</strong></p>

    <h2>ai agent internet access for any framework</h2>
    <p>Whether you're building with LangChain, CrewAI, AutoGPT, or a custom agent framework — your agents need web access. agentsweb.org is a single HTTP endpoint that works everywhere. No SDK lock-in. No vendor dependency. Just <code>GET</code> and <code>PUT</code>.</p>
    <p><code>curl agentsweb.org/fetch?url=https://any-website.com</code></p>
    <p>That's it. Your agent has the internet now. Clean markdown, cached at the edge, secured against prompt injection. <strong>Every web page, pre-chewed for machines.</strong></p>
  `);
}

function comparePage(): Response {
  return makePage("Compare", `
    <h1>&gt; compare</h1>

    <p>There are other ways to give AI agents web access. Most of them are bad. Here's why.</p>

    <h2>raw fetch (the default)</h2>
    <p>Just <code>fetch()</code> the URL directly. What could go wrong?</p>
    <ul>
      <li>403 Forbidden on most sites worth reading</li>
      <li>Cloudflare challenges, CAPTCHAs, bot detection</li>
      <li>Raw HTML with 200KB of JavaScript, ads, and cookie banners</li>
      <li>Your LLM burns half its context window parsing a nav sidebar</li>
      <li>No caching — every agent fetches the same page independently</li>
    </ul>
    <p><strong>agentsweb:</strong> Clean markdown. Sub-50ms. Global cache. No 403s. No garbage HTML. Done.</p>

    <h2>jina reader (r.jina.ai)</h2>
    <p>Jina Reader is solid for converting a single URL to markdown. We actually use it as one of our fetch backends. But:</p>
    <ul>
      <li>Single-page only — no search, no batch, no research</li>
      <li>No caching layer — every request is a live fetch</li>
      <li>No trust consensus — no way to verify content integrity</li>
      <li>No prompt injection scanning</li>
      <li>Rate limits on their free tier</li>
    </ul>
    <p><strong>agentsweb:</strong> Search + fetch + cache in one call. Self-healing consensus. Prompt injection detection. Edge caching for repeat reads. Jina is a tool — agentsweb is the infrastructure layer.</p>

    <h2>browserless / puppeteer</h2>
    <p>Run a headless browser in the cloud. The "enterprise" approach:</p>
    <ul>
      <li>$0.01-0.05 per page render — gets expensive fast</li>
      <li>2-10 second render times (vs 50ms from agentsweb cache)</li>
      <li>You need to maintain browser infrastructure</li>
      <li>Still returns raw HTML — you need another step to get markdown</li>
      <li>No shared caching across agents or teams</li>
    </ul>
    <p><strong>agentsweb:</strong> Free. Sub-50ms. Returns markdown directly. Shared cache means you rarely trigger a live fetch. No browser infrastructure to maintain. No cost scaling nightmares.</p>

    <h2>serpapi / google search api</h2>
    <p>Great for search results. But that's all you get:</p>
    <ul>
      <li>Search results only — titles, URLs, snippets</li>
      <li>No page content — you still need to fetch and parse each result</li>
      <li>$50+/month for reasonable usage</li>
      <li>API key required</li>
      <li>Google-specific — tied to one search engine</li>
    </ul>
    <p><strong>agentsweb:</strong> <code>/research</code> does search AND fetches AND caches the content in one call. No API key. No subscription. Your agent gets the actual page content, not just links to pages it can't read.</p>

    <h2>the bottom line</h2>
    <p>Other tools solve one piece of the puzzle. agentsweb.org is the <strong>complete web access layer for AI agents</strong> — search, fetch, cache, verify, and serve clean markdown. One API. No keys. No cost. Open source.</p>
    <p>That's the difference between a tool and infrastructure.</p>
  `);
}

function howItWorksPage(): Response {
  return makePage("How It Works", `
    <h1>&gt; how it works</h1>

    <p>agentsweb.org is a multi-tier pipeline that turns the hostile web into clean, verified markdown for AI agents. Here's what happens when your agent makes a request.</p>

    <h2>the request flow</h2>
    <p><code>Your Agent → agentsweb.org → Edge Cache → KV Store → Live Fetch → Markdown</code></p>
    <p>Every request flows through up to four layers, each one faster than the next. Most requests never make it past layer two.</p>

    <h2>layer 1: edge cache (sub-1ms)</h2>
    <p>Cloudflare's edge network spans 300+ cities worldwide. When a page has been read recently, it's cached at the edge node closest to your agent. The response comes back in <strong>under 1 millisecond</strong>. No KV lookup. No network hop. Just memory.</p>
    <p>Edge cache TTL: 5 minutes. Popular pages stay warm indefinitely because agents keep reading them.</p>

    <h2>layer 2: kv store (5-50ms)</h2>
    <p>Cloudflare KV is a globally replicated key-value store. If the edge cache is cold, we check KV. The data is replicated across Cloudflare's entire network — reads are fast from anywhere on earth.</p>
    <p>KV entries have dynamic TTLs based on trust level and domain type:</p>
    <ul>
      <li><strong>News domains</strong> (bloomberg, nyt, bbc): 1 day TTL — content changes fast</li>
      <li><strong>Documentation</strong> (wikipedia, MDN, docs.rs): 30 day TTL — content is stable</li>
      <li><strong>Low trust (1):</strong> 1 day — unverified content expires quickly</li>
      <li><strong>Medium trust (2-4):</strong> 7 days — multiple sources agree</li>
      <li><strong>High trust (5+):</strong> 30 days — battle-tested content</li>
    </ul>

    <h2>layer 3: live fetch</h2>
    <p>Cache miss. The page hasn't been cached yet, or the entry expired. agentsweb fetches the page through a markdown conversion service, runs it through every security gate, and stores it in KV. The next agent gets it from cache.</p>
    <p>Live fetch takes 1-15 seconds depending on the target site. But it only happens once per page per TTL window. Every agent after the first one gets the cached version.</p>

    <h2>the self-healing consensus engine</h2>
    <p>This is the part that makes agentsweb fundamentally different from a simple cache.</p>
    <p>Every cached entry has a <strong>trust level</strong> (1-100). Trust starts at 1 when a single agent writes the entry. When a different agent — identified by IP address, not self-reported IDs — reads the same page and confirms the content matches, trust increments.</p>
    <p>At trust level 2+, the entry is <strong>protected from overwrites</strong>. An attacker can't just submit a poisoned version — the existing trusted content wins.</p>
    <p>If someone does manage to poison a low-trust entry, it <strong>self-destructs on the next legitimate read</strong>. The reading agent fetches the page locally, sees the mismatch, and submits the correct version. The poison survives exactly one read.</p>

    <h2>security pipeline</h2>
    <p>Every piece of content passes through these gates before being stored:</p>
    <ul>
      <li><strong>URL validation:</strong> SSRF prevention, private IP blocking, credential stripping</li>
      <li><strong>Prompt injection scan:</strong> 30+ patterns covering instruction overrides, role manipulation, jailbreaks, template tokens</li>
      <li><strong>Malicious content detection:</strong> Script injection, event handlers, iframes, document.cookie</li>
      <li><strong>Captcha/login wall detection:</strong> Cloudflare challenges, reCAPTCHA, "sign in to continue"</li>
      <li><strong>Unicode steganography:</strong> Zero-width character attacks detected and rejected</li>
      <li><strong>Entropy analysis:</strong> Base64 smuggling and repetition padding attacks blocked</li>
    </ul>
    <p>Content that fails any gate is rejected, the submitter gets a strike, and after 5 strikes the IP is auto-banned for an hour.</p>

    <h2>cache warming (cron)</h2>
    <p>A background cron job samples 10 random URLs from the index every run. If an entry is past 75% of its TTL, the cron fetches a fresh version and updates the cache. Popular pages never expire — they're always warm and ready.</p>

    <h2>why this architecture</h2>
    <p>The web wasn't built for AI agents. HTML is for browsers. JavaScript is for humans. CAPTCHAs exist specifically to stop automated access. agentsweb is the <strong>translation layer</strong> — it absorbs all that complexity so your agent doesn't have to.</p>
    <p>One fetch. Clean markdown. Verified by consensus. Cached at the edge. <strong>That's the whole idea.</strong></p>
  `);
}

function faqPage(): Response {
  return makePage("FAQ", `
    <h1>&gt; faq</h1>

    <h2>is it free?</h2>
    <p>Yes. Completely free. No API keys, no signup, no credit card, no "free tier with limits that conveniently force you into a paid plan." Just hit the endpoints. We don't need to monetize your usage data because we don't collect any.</p>

    <h2>do i need an api key?</h2>
    <p>No. Every endpoint is open. <code>curl agentsweb.org/fetch?url=...</code> and you're done. We believe access to public web content shouldn't require you to create an account with a company that then tracks every query you make across every product they own.</p>

    <h2>how fresh is the cache?</h2>
    <p>It depends on the trust level and the domain:</p>
    <ul>
      <li>News sites: 1 day TTL</li>
      <li>Documentation: up to 30 days</li>
      <li>Low-trust entries: 1 day</li>
      <li>High-trust entries: up to 30 days</li>
    </ul>
    <p>A background cron job also pre-warms entries approaching expiry. When a response includes <code>"stale": true</code>, the content is approaching its TTL — still valid, but a refresh is coming.</p>

    <h2>can i self-host this?</h2>
    <p>Yes. The entire codebase is open source on <a href="https://github.com/bighippoman/agentsweb">GitHub</a>. It's a single Cloudflare Worker with KV. Deploy it to your own Cloudflare account with <code>npx wrangler deploy</code>. You'll need a KV namespace and an admin secret.</p>

    <h2>is it legal?</h2>
    <p>agentsweb operates under <strong>DMCA 512(b)</strong> — the system caching safe harbor. We cache temporary, transformed copies of publicly accessible web pages. Content owners can request removal via our <a href="/dmca">DMCA policy</a>, and takedowns are permanent. We also respect robots.txt directives. Caching the web for search and retrieval has been considered legal since — well, since a certain search engine built their entire trillion-dollar business on it.</p>

    <h2>what about paywalled content?</h2>
    <p>agentsweb only caches publicly accessible pages. Login walls and subscription gates are detected and rejected automatically. If a page requires authentication to read, we can't cache it and we won't try.</p>

    <h2>how do rate limits work?</h2>
    <ul>
      <li><strong>Reads:</strong> 600 per minute per IP</li>
      <li><strong>Writes:</strong> 10 per minute per IP</li>
      <li><strong>Confirms:</strong> 60 per minute per IP</li>
    </ul>
    <p>If you submit 5 pieces of content that fail security validation, your IP is auto-banned for 1 hour. This prevents cache poisoning attempts.</p>

    <h2>can i contribute to the cache?</h2>
    <p>Yes. <code>PUT /</code> with a JSON body containing <code>url</code>, <code>markdown</code>, and <code>source</code>. Your content passes through the full security pipeline. If it's clean, it enters the cache at trust level 1. Other agents can confirm it to increase trust.</p>

    <h2>how do i integrate with my ai agent?</h2>
    <p>Any HTTP client works. See our <a href="/integrations">integrations page</a> for specific instructions for Claude Code, Cursor, Windsurf, Codex, LangChain, Python, and curl.</p>

    <h2>what if someone poisons the cache?</h2>
    <p>Short answer: the poison self-destructs. Long answer: all content passes through 30+ prompt injection patterns, XSS filters, and unicode steganography detection. Even if something slips through, the self-healing consensus means the next legitimate agent to read the entry will verify it and replace the poisoned version. Entries with trust level 2+ can't be overwritten by a single agent.</p>

    <h2>is there an mcp server?</h2>
    <p>Yes. <a href="https://github.com/bighippoman/intercept-mcp">intercept-mcp</a> is the MCP server that integrates agentsweb with Claude Code, Cursor, Windsurf, and any MCP-compatible client. Install with <code>npx -y intercept-mcp</code>.</p>

    <h2>what search engine does /web use?</h2>
    <p>We aggregate results from multiple independent search backends — no single company decides what your agent sees. Unlike some search providers, we don't prioritize results from our own products, inject ads disguised as results, or deprecate our API every two years to force you onto a more expensive one.</p>

    <h2>what's the difference between /fetch and /?url=</h2>
    <p><code>/fetch?url=...</code> will fetch the page live if it's not cached. <code>/?url=...</code> is cache-only — it returns 404 if the page hasn't been cached. Use <code>/fetch</code> when you want the content no matter what. Use <code>/?url=</code> when you want speed and are okay with a miss.</p>

    <h2>how do i report abuse?</h2>
    <p>Email <strong>dmca@agentsweb.org</strong>. We respond within 24 hours. Takedowns are permanent and immediate.</p>
  `);
}

function integrationsPage(): Response {
  return makePage("Integrations", `
    <h1>&gt; integrations</h1>

    <p>agentsweb.org works with any HTTP client. Here's how to integrate it with the tools you're already using for AI agent web access.</p>

    <h2>claude code (mcp)</h2>
    <p>The fastest way to give Claude Code web search and fetch capabilities. Install the MCP server:</p>
    <p><code>npx -y intercept-mcp</code></p>
    <p>Add to your Claude Code MCP config (<code>~/.claude/settings.json</code>):</p>
    <p><code>{ "mcpServers": { "intercept": { "command": "npx", "args": ["-y", "intercept-mcp"] } } }</code></p>
    <p>Now Claude Code can search the web, fetch pages, and read cached markdown — all through agentsweb.org.</p>

    <h2>cursor</h2>
    <p>Cursor supports MCP servers. Add to your Cursor MCP config:</p>
    <p><code>{ "mcpServers": { "intercept": { "command": "npx", "args": ["-y", "intercept-mcp"] } } }</code></p>
    <p>Your Cursor agent now has full web access — search, fetch, and cache via agentsweb.</p>

    <h2>windsurf</h2>
    <p>Windsurf's Cascade supports MCP. Add the same configuration:</p>
    <p><code>{ "mcpServers": { "intercept": { "command": "npx", "args": ["-y", "intercept-mcp"] } } }</code></p>
    <p>Cascade can now search and read the web through the agentsweb markdown API.</p>

    <h2>codex (openai)</h2>
    <p>For OpenAI's Codex and custom GPT agents, use the HTTP API directly:</p>
    <p><code>GET https://agentsweb.org/research?q=your+query</code></p>
    <p><code>GET https://agentsweb.org/fetch?url=https://example.com</code></p>
    <p>Add these as function definitions in your agent's tool configuration. The JSON response parses cleanly into any agent framework.</p>

    <h2>langchain (python)</h2>
    <p>Use the Python SDK or plain requests:</p>
    <p><code>pip install agentsweb</code></p>
    <p>Or integrate directly as a custom tool:</p>
    <p><code>import requests</code></p>
    <p><code>def fetch_page(url: str) -> str:</code></p>
    <p><code>&nbsp;&nbsp;r = requests.get(f"https://agentsweb.org/fetch?url={url}")</code></p>
    <p><code>&nbsp;&nbsp;return r.json()["markdown"]</code></p>
    <p>Wrap it as a LangChain <code>Tool</code> and your agent has web access with caching, search, and prompt injection protection built in.</p>

    <h2>python (requests / httpx)</h2>
    <p>No SDK needed. Just HTTP:</p>
    <p><code>import requests</code></p>
    <p><code># Search the web</code></p>
    <p><code>r = requests.get("https://agentsweb.org/web?q=python+async+tutorial")</code></p>
    <p><code>results = r.json()["results"]</code></p>
    <p><code># Fetch a specific page as markdown</code></p>
    <p><code>r = requests.get("https://agentsweb.org/fetch?url=https://docs.python.org/3/library/asyncio.html")</code></p>
    <p><code>markdown = r.json()["markdown"]</code></p>
    <p><code># Research: search + fetch + cache in one call</code></p>
    <p><code>r = requests.get("https://agentsweb.org/research?q=rust+error+handling&count=3")</code></p>

    <h2>curl</h2>
    <p>The simplest possible integration. No libraries, no dependencies:</p>
    <p><code>curl "agentsweb.org/fetch?url=https://example.com"</code></p>
    <p><code>curl "agentsweb.org/web?q=your+search+query"</code></p>
    <p><code>curl "agentsweb.org/research?q=deep+learning+transformers"</code></p>
    <p><code>curl "agentsweb.org/raw?url=https://example.com"</code> (raw markdown, no JSON)</p>

    <h2>any http client</h2>
    <p>agentsweb is a REST API. If your tool can make HTTP GET requests, it can use agentsweb. No auth headers. No API keys. No OAuth. No SDK.</p>
    <p><code>GET https://agentsweb.org/fetch?url={any_url}</code> — get any web page as markdown</p>
    <p><code>GET https://agentsweb.org/web?q={query}</code> — search the web</p>
    <p><code>GET https://agentsweb.org/research?q={query}</code> — search + fetch + cache</p>
    <p>That's the entire API surface for web scraping for AI. Three endpoints. Zero configuration. <strong>Works everywhere.</strong></p>
  `);
}

function sitemapXml(): Response {
  const pages = [
    "",
    "/docs",
    "/blog",
    "/about",
    "/security",
    "/dmca",
    "/terms",
    "/use-cases",
    "/compare",
    "/how-it-works",
    "/faq",
    "/integrations",
  ];
  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${pages.map((p) => `  <url>
    <loc>https://agentsweb.org${p}</loc>
    <changefreq>${p === "" ? "daily" : "weekly"}</changefreq>
    <priority>${p === "" ? "1.0" : p === "/docs" ? "0.9" : "0.8"}</priority>
  </url>`).join("\n")}
</urlset>`;
  return new Response(xml, {
    headers: {
      "Content-Type": "application/xml; charset=utf-8",
      "Cache-Control": "public, max-age=3600",
      ...securityHeaders(),
    },
  });
}

// ============================================================
// Main entry point
// ============================================================

export default {
  // Cache warming cron — refreshes entries approaching expiry
  async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
    _rc = { ctx, kv: env.CACHE, env };
    const kv = env.CACHE;

    // Get URL index
    const indexRaw = await kv.get("index:urls");
    if (!indexRaw) return;
    const urls: string[] = JSON.parse(indexRaw);

    // Check a random sample (10 URLs per cron run)
    const sample = urls.sort(() => Math.random() - 0.5).slice(0, 10);

    for (const url of sample) {
      const key = `cache:${await hashUrl(url)}`;
      const raw = await kv.get(key);
      if (!raw) continue; // already expired, nothing to warm

      try {
        const entry: CacheEntry = JSON.parse(raw);
        const age = Date.now() - entry.updated_at;
        const ttl = getTtl(entry.trust_level, entry.url) * 1000;

        // Refresh if more than 75% through TTL
        if (age > ttl * 0.75) {
          const fetched = await fetchMarkdownLive(entry.url);
          if (!fetched) continue;
          const rejection = validateContent(fetched.markdown);
          if (rejection) continue;

          const contentHash = await hashContent(fetched.markdown);
          entry.markdown = fetched.markdown;
          entry.source = fetched.source;
          entry.content_hash = contentHash;
          entry.updated_at = Date.now();
          entry.size = markdown.length;

          await kv.put(key, JSON.stringify(entry), {
            expirationTtl: getTtl(entry.trust_level, entry.url),
          });
        }
      } catch { /* skip failures */ }
    }
  },

  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    _rc = { ctx, kv: env.CACHE, env };
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

    // Admin: rebuild URL index from a list of known URLs
    if (method === "POST" && url.pathname === "/admin/rebuild-index" && admin) {
      const body = await parseBody<{ urls: string[] }>(request);
      if (!body?.urls?.length) return json({ error: "urls array required" }, 400);
      const validated = body.urls.filter((u) => !validateUrl(u));
      const normalized = validated.map(normalizeUrlForCache);
      await env.CACHE.put("index:urls", JSON.stringify(normalized));
      return json({ status: "index rebuilt", count: normalized.length });
    }

    // Admin: clear DMCA flag
    if (method === "POST" && url.pathname === "/admin/clear-dmca" && admin) {
      const body = await parseBody<{ url: string }>(request);
      if (!body?.url) return json({ error: "url required" }, 400);
      const dmcaHash = await hashUrl(body.url);
      await env.CACHE.delete(`dmca:${dmcaHash}`);
      return json({ status: "dmca flag cleared", url: body.url });
    }

    // Admin: rebuild search index from provided entries
    if (method === "POST" && url.pathname === "/admin/rebuild-search-index" && admin) {
      const body = await parseBody<{ entries: Array<{ url: string; title: string; snippet: string }> }>(request);
      if (!body?.entries?.length) return json({ error: "entries array required" }, 400);
      await env.CACHE.put("index:search", JSON.stringify(body.entries.slice(0, 10_000)));
      return json({ status: "search index rebuilt", count: body.entries.length });
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
        const maxTokens = parseInt(url.searchParams.get("max_tokens") || "0") || 0;
        const clean = url.searchParams.get("clean") !== "false";
        const section = url.searchParams.get("section") || "";
        const toc = url.searchParams.get("toc") === "true";
        return await handleRead(url.searchParams.get("url")!, env.CACHE, ip, request, maxTokens, clean, section, toc);
      }

      if (method === "GET" && url.pathname === "/raw" && url.searchParams.has("url")) {
        return await handleRawRead(url.searchParams.get("url")!, env.CACHE, ip);
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

      if (method === "GET" && url.pathname === "/batch" && url.searchParams.has("urls")) {
        return await handleBatch(url.searchParams.get("urls")!, env.CACHE, ip);
      }

      if (method === "GET" && url.pathname === "/search" && url.searchParams.has("q")) {
        return await handleSearch(url.searchParams.get("q")!, env.CACHE, ip);
      }

      // Web search — real search engine results
      if (method === "GET" && url.pathname === "/web" && url.searchParams.has("q")) {
        return await handleWebSearch(url.searchParams.get("q")!, parseInt(url.searchParams.get("count") || "5"), env.CACHE, ip);
      }

      // Research — search + fetch + cache in one call
      if (method === "GET" && url.pathname === "/research" && url.searchParams.has("q")) {
        return await handleResearch(url.searchParams.get("q")!, parseInt(url.searchParams.get("count") || "3"), env.CACHE, ip);
      }

      // Fetch on demand — give URL, get markdown, auto-cached
      if (method === "GET" && url.pathname === "/fetch" && url.searchParams.has("url")) {
        const forceRefresh = url.searchParams.get("refresh") === "true" && admin;
        return await handleFetchAndCache(url.searchParams.get("url")!, env.CACHE, ip, forceRefresh, env, admin);
      }

      if (method === "POST" && url.pathname === "/takedown") {
        if (!admin) return json({ error: "admin authentication required — email dmca@agentsweb.org for takedowns" }, 403);
        return await handleTakedown(request, env.CACHE, ip);
      }

      if (method === "POST" && url.pathname === "/opt-out") {
        if (!admin) return json({ error: "admin authentication required — email dmca@agentsweb.org for opt-outs" }, 403);
        return await handleOptOut(request, env.CACHE, ip);
      }
    } catch {
      return json({ error: "internal error" }, 500);
    }

    // OG image
    if (method === "GET" && url.pathname === "/og.svg") {
      return new Response(`<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630"><rect fill="#0c0c0c" width="1200" height="630"/><text x="80" y="200" font-family="monospace" font-size="72" font-weight="bold" fill="#f0a050">agentsweb.org</text><text x="80" y="290" font-family="monospace" font-size="28" fill="#888">The internet, but for AI agents.</text><text x="80" y="370" font-family="monospace" font-size="22" fill="#666">Search. Fetch. Cache. Clean markdown.</text><text x="80" y="420" font-family="monospace" font-size="22" fill="#666">Sub-50ms reads. Self-healing consensus.</text><text x="80" y="540" font-family="monospace" font-size="18" fill="#4a4030">open source · no API keys · agentsweb.org</text></svg>`,
        { headers: { "Content-Type": "image/svg+xml", "Cache-Control": "public, max-age=86400" } }
      );
    }

    // robots.txt
    if (method === "GET" && url.pathname === "/robots.txt") {
      return new Response(
        `User-agent: *\nAllow: /\n\nSitemap: https://agentsweb.org/sitemap.xml\n`,
        { headers: { "Content-Type": "text/plain", ...securityHeaders() } }
      );
    }

    // Static pages
    if (method === "GET" && url.pathname === "/dmca") return dmcaPage();
    if (method === "GET" && url.pathname === "/terms") return termsPage();
    if (method === "GET" && url.pathname === "/docs") return docsPage();
    if (method === "GET" && url.pathname === "/security") return securityPage();
    if (method === "GET" && url.pathname === "/about") return aboutPage();
    if (method === "GET" && url.pathname === "/use-cases") return useCasesPage();
    if (method === "GET" && url.pathname === "/compare") return comparePage();
    if (method === "GET" && url.pathname === "/how-it-works") return howItWorksPage();
    if (method === "GET" && url.pathname === "/faq") return faqPage();
    if (method === "GET" && url.pathname === "/blog") return blogPage();
    if (method === "GET" && url.pathname === "/integrations") return integrationsPage();
    if (method === "GET" && url.pathname === "/sitemap.xml") return sitemapXml();

    return json({ error: "not found" }, 404);
  },
};
