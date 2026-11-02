import { safeFetch } from "./transport.js";
function robotsMatch(pattern: string, path: string): boolean {
  let re = "";
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i];
    if (c === "*") re += ".*";
    else if (c === "$" && i === pattern.length - 1) re += "$";
    else re += c.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }
  try {
    return new RegExp("^" + re).test(path);
  } catch {
    return false;
  }
}

/** Evaluate a robots.txt body for our agent against a path. Standard precedence:
 *  the most specific applicable group wins (agentsweb > *), then the longest
 *  matching rule wins, with Allow beating Disallow on ties. */
export function robotsPathAllowed(robotsTxt: string, path: string): boolean {
  // Preserve blank lines: a truly blank line is a record separator (per RFC), so
  // an empty `User-agent: agentsweb` record followed by a separate
  // `User-agent: * / Disallow: /` block must NOT inherit the * rules. Comment-only
  // lines are NOT separators (they may sit between a UA line and its rules).
  const rawLines = robotsTxt.split(/\r?\n/);
  const groups = new Map<string, { allow: string[]; disallow: string[] }>();
  let currentAgents: string[] = [];
  let lastWasAgent = false;
  for (const rawLine of rawLines) {
    const line = rawLine.replace(/#.*$/, "").trim();
    if (line === "") {
      if (rawLine.trim() === "") {
        currentAgents = [];
        lastWasAgent = false;
      } // blank = record boundary
      continue; // comment-only line: not a separator
    }
    const idx = line.indexOf(":");
    if (idx === -1) continue;
    const field = line.slice(0, idx).trim().toLowerCase();
    const value = line.slice(idx + 1).trim();
    if (field === "user-agent") {
      if (!lastWasAgent) currentAgents = [];
      const ua = value.toLowerCase();
      currentAgents.push(ua);
      if (!groups.has(ua)) groups.set(ua, { allow: [], disallow: [] });
      lastWasAgent = true;
    } else if (field === "allow" || field === "disallow") {
      lastWasAgent = false;
      for (const a of currentAgents) {
        const g = groups.get(a);
        if (g) (field === "allow" ? g.allow : g.disallow).push(value);
      }
    } else {
      lastWasAgent = false;
    }
  }

  const group = groups.get("agentsweb") || groups.get("*");
  if (!group) return true;

  let decision: boolean | null = null;
  let bestLen = -1;
  for (const rule of group.disallow) {
    if (rule === "") continue; // empty Disallow = allow everything
    if (robotsMatch(rule, path) && rule.length > bestLen) {
      bestLen = rule.length;
      decision = false;
    }
  }
  for (const rule of group.allow) {
    if (rule === "") continue;
    if (robotsMatch(rule, path) && rule.length >= bestLen) {
      bestLen = rule.length;
      decision = true;
    }
  }
  return decision === null ? true : decision;
}

// Per-isolate cache of robots.txt BODIES, keyed by host (rules vary by path, so
// we memo the raw rules, not the decision). Dedupes the cold-path double lookup
// (handleFetchAndCache + fetchMarkdownLive both check the same URL) and is
// politeness toward origins. KV is still the cross-isolate persistent layer.
const robotsRulesMemo = new Map<string, { rules: string; expires: number }>();

/** Returns false only if the site's robots.txt disallows our agent for this path.
 *  Fetches+caches robots.txt per host (6h KV + per-isolate memo).
 *  Network errors, throttling and server failures deny retrieval. */
export async function robotsAllows(
  url: string,
  kv: KVNamespace,
  parentSignal?: AbortSignal,
): Promise<boolean> {
  let host: string, path: string, protocol: string;
  try {
    const u = new URL(url);
    host = u.host;
    path = (u.pathname || "/") + (u.search || "");
    protocol = u.protocol;
  } catch {
    return true;
  }

  const memo = robotsRulesMemo.get(protocol + "//" + host);
  let rules: string | null | undefined =
    memo && memo.expires > Date.now() ? memo.rules : undefined;
  if (rules === undefined) {
    const cacheKey = `robots:v2:${protocol}//${host}`;
    rules = await kv.get(cacheKey);
    if (rules === null) {
      try {
        const resp = await safeFetch(`${protocol}//${host}/robots.txt`, {
          headers: { "User-Agent": "agentsweb" },
          signal: AbortSignal.any([
            AbortSignal.timeout(5_000),
            ...(parentSignal ? [parentSignal] : []),
          ]),
          redirect: "follow",
        });
        if (resp.status >= 500 || resp.status === 429) return false;
        rules = resp.ok ? (await resp.text()).slice(0, 100_000) : "";
      } catch {
        return false;
      }
      // Cache 6h. Empty string means an absent robots.txt or no rules.
      await kv.put(cacheKey, rules, { expirationTtl: 21_600 });
    }
    if (robotsRulesMemo.size > 1000) robotsRulesMemo.clear(); // bound isolate memory
    robotsRulesMemo.set(protocol + "//" + host, {
      rules: rules ?? "",
      expires: Date.now() + 300_000,
    });
  }
  if (!rules) return true;
  try {
    return robotsPathAllowed(rules, path);
  } catch {
    return true;
  }
}

// ============================================================
// Multi-tier live fetcher — not dependent on any single service
// ============================================================
