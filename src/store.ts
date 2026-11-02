import { hash, passages, ftsQuery, contentProblem } from "./content.js";
import { normalizeUrl } from "./url-identity.js";
import type { Env, Document, Passage } from "./types.js";

type DocumentRow = Omit<Document, "markdown"> & { body_key?: string };

export async function removal(env: Env, raw: string): Promise<string | null> {
  const url = normalizeUrl(raw),
    hostname = new URL(url).hostname.replace(/^www\./, "");
  const parts = hostname.split(".");
  const domains = parts
    .map((_, i) => parts.slice(i).join("."))
    .filter((d) => d.includes("."));
  const keys = [url, ...domains.map((d) => `domain:${d}`)];
  const row = await env.DB.prepare(
    `SELECT reason FROM removals WHERE key IN (${keys.map(() => "?").join(",")}) LIMIT 1`,
  )
    .bind(...keys)
    .first<{ reason: string }>();
  if (row) return row.reason;
  // Preserve pre-migration takedowns and opt-outs.
  const oldUrl = legacyIdentity(url);
  const [blocked, removed, oldRemoved] = await Promise.all([
    Promise.all(domains.map((d) => env.CACHE.get(`block:${d}`))).then(
      (values) => values.some(Boolean),
    ),
    env.CACHE.get(`dmca:${await hash(url)}`),
    env.CACHE.get(`dmca:${await hash(oldUrl)}`),
  ]);
  return blocked
    ? "domain opted out"
    : removed || oldRemoved
      ? "removed at owner request"
      : null;
}

export function legacyIdentity(raw: string): string {
  const u = new URL(raw);
  u.protocol = "https:";
  u.hostname = u.hostname.replace(/^www\./, "");
  u.hash = "";
  for (const key of [...u.searchParams.keys()])
    if (/^(utm_|fbclid|gclid|ref|mc_|_ga|msclkid)/i.test(key))
      u.searchParams.delete(key);
  return u.toString().replace(/(?<!:)\/+$/, u.pathname === "/" ? "/" : "");
}

export async function readDocument(
  env: Env,
  raw: string,
): Promise<Document | null> {
  const url = normalizeUrl(raw);
  if (await removal(env, url)) return null;
  const row = await env.DB.prepare(
    "SELECT * FROM documents WHERE url=? AND expires_at>?",
  )
    .bind(url, Date.now())
    .first<DocumentRow>();
  if (row) {
    const markdown = await env.CACHE.get(
      row.body_key || `body:${row.content_hash}`,
    );
    if (markdown) return { ...row, markdown };
  }
  // Legacy timestamps also moved on confirmations; only a new retrieval can
  // publish them under the v2 freshness contract. Their KV data is retained.
  return null;
}

export async function ingest(
  env: Env,
  value: Omit<Document, "content_hash" | "expires_at" | "title"> &
    Partial<Pick<Document, "title">>,
): Promise<Document> {
  const url = normalizeUrl(value.url);
  if (await removal(env, url)) throw new Error("content removed");
  const problem = contentProblem(value.markdown);
  if (problem) throw new Error(problem);
  const now = Date.now(),
    contentHash = await hash(value.markdown);
  const doc: Document = {
    ...value,
    url,
    content_hash: contentHash,
    title:
      value.title ||
      value.markdown.match(/^#\s+(.+)/m)?.[1]?.slice(0, 250) ||
      new URL(url).hostname,
    expires_at: now + 7 * 86_400_000,
  };
  // Immutable bodies mean an out-of-date KV replica can miss, never return a
  // different version under the metadata/hash selected transactionally in D1.
  const bodyKey = `body:${contentHash}:${crypto.randomUUID()}`;
  await env.CACHE.put(bodyKey, value.markdown, { expirationTtl: 30 * 86400 });
  const statements = [
    env.DB.prepare(
      `INSERT INTO documents(url,host,title,content_hash,source,source_kind,completeness,retrieved_at,verified_at,expires_at,archived_at,body_key)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(url) DO UPDATE SET body_key=excluded.body_key,title=excluded.title,content_hash=excluded.content_hash,source=excluded.source,source_kind=excluded.source_kind,
      completeness=excluded.completeness,retrieved_at=excluded.retrieved_at,verified_at=excluded.verified_at,expires_at=excluded.expires_at,archived_at=excluded.archived_at
      WHERE excluded.retrieved_at >= documents.retrieved_at`,
    ).bind(
      url,
      new URL(url).hostname,
      doc.title,
      contentHash,
      doc.source,
      doc.source_kind,
      doc.completeness,
      doc.retrieved_at,
      doc.verified_at,
      doc.expires_at,
      doc.archived_at ?? null,
      bodyKey,
    ),
    env.DB.prepare(
      "INSERT INTO versions(url,content_hash,retrieved_at) VALUES(?,?,?) ON CONFLICT(url,content_hash) DO UPDATE SET retrieved_at=MAX(versions.retrieved_at,excluded.retrieved_at)",
    ).bind(url, contentHash, doc.retrieved_at),
    ...passages(doc.markdown, url).map((p, i) =>
      env.DB.prepare(
        "INSERT INTO chunks(url,content_hash,ordinal,title,heading,text,start,end,citation_url) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(url,content_hash,ordinal) DO UPDATE SET start=excluded.start,end=excluded.end",
      ).bind(
        url,
        contentHash,
        i,
        doc.title,
        p.heading,
        p.text,
        p.start,
        p.end,
        p.citation_url,
      ),
    ),
    env.DB.prepare(
      "INSERT INTO counters(name,value) VALUES('writes',1) ON CONFLICT(name) DO UPDATE SET value=value+1",
    ),
  ];
  await env.DB.batch(statements);
  return doc;
}

export async function queueRefresh(env: Env, raw: string): Promise<boolean> {
  const url = normalizeUrl(raw);
  if (await removal(env, url)) return false;
  const now = Date.now();
  const claimed = await env.DB.prepare(
    "INSERT INTO jobs(url,queued_at) VALUES(?,?) ON CONFLICT(url) DO UPDATE SET queued_at=excluded.queued_at WHERE jobs.queued_at<? RETURNING url",
  )
    .bind(url, now, now - 15 * 60_000)
    .first();
  if (!claimed) return false;
  try {
    await env.DB.prepare(
      "UPDATE documents SET last_refresh_attempt=? WHERE url=?",
    )
      .bind(now, url)
      .run();
    await env.REVALIDATE.send({ url });
    return true;
  } catch (error) {
    await env.DB.prepare("DELETE FROM jobs WHERE url=? AND queued_at=?")
      .bind(url, now)
      .run();
    throw error;
  }
}

export async function rateLimit(
  env: Env,
  ip: string,
  action: "read" | "fetch" | "write",
): Promise<boolean> {
  const minute = Math.floor(Date.now() / 60_000),
    limit = { read: 600, fetch: 30, write: 10 }[action];
  const key = `${action}:${minute}:${(await hash(`${minute}:${ip}`)).slice(0, 32)}`;
  const row = await env.DB.prepare(
    "INSERT INTO limits(key,count,expires_at) VALUES(?,1,?) ON CONFLICT(key) DO UPDATE SET count=count+1 WHERE count<? RETURNING count",
  )
    .bind(key, (minute + 2) * 60_000, limit)
    .first();
  return !!row;
}

export async function count(env: Env, name: string): Promise<void> {
  await env.DB.prepare(
    "INSERT INTO counters(name,value) VALUES(?,1) ON CONFLICT(name) DO UPDATE SET value=value+1",
  )
    .bind(name)
    .run();
}

export async function search(
  env: Env,
  query: string,
  limit = 5,
  url?: string,
): Promise<
  Array<
    Passage & {
      title: string;
      content_hash: string;
      retrieved_at: string;
      verified_at: string | null;
      source: string;
      source_kind: string;
      completeness: string;
      relevance: number;
    }
  >
> {
  const match = ftsQuery(query);
  if (!match) return [];
  const rows = await env.DB.prepare(
    `SELECT c.*,d.source,d.source_kind,d.completeness,d.retrieved_at,d.verified_at,bm25(chunks_fts,8,5,1) AS rank
    FROM chunks_fts JOIN chunks c ON c.id=chunks_fts.rowid JOIN documents d ON d.url=c.url AND d.content_hash=c.content_hash
    WHERE chunks_fts MATCH ? AND d.expires_at>? ${url ? "AND d.url=?" : ""} ORDER BY rank LIMIT ?`,
  )
    .bind(
      ...(url
        ? [match, Date.now(), normalizeUrl(url), Math.min(limit * 3, 60)]
        : [match, Date.now(), Math.min(limit * 3, 60)]),
    )
    .all<any>();
  const results = [];
  for (const row of rows.results) {
    if (await removal(env, row.url)) continue;
    results.push({
      url: row.url,
      heading: row.heading,
      text: row.text,
      start: row.start,
      end: row.end,
      citation_url: row.citation_url,
      title: row.title,
      content_hash: row.content_hash,
      retrieved_at: new Date(row.retrieved_at).toISOString(),
      verified_at: row.verified_at
        ? new Date(row.verified_at).toISOString()
        : null,
      source: row.source,
      source_kind: row.source_kind,
      completeness: row.completeness,
      relevance: -row.rank,
    });
    if (results.length >= limit) break;
  }
  return results;
}

export async function remove(
  env: Env,
  key: string,
  reason: string,
): Promise<void> {
  const domain = key.startsWith("domain:");
  const where = domain ? "(host=? OR host LIKE ?)" : "url=?";
  const args = domain
    ? [key.slice(7), `%.${key.slice(7)}`]
    : [normalizeUrl(key)];
  await env.DB.batch([
    env.DB.prepare(
      "INSERT OR REPLACE INTO removals(key,reason,created_at) VALUES(?,?,?)",
    ).bind(key, reason, Date.now()),
    env.DB.prepare(
      `DELETE FROM chunks WHERE url IN (SELECT url FROM documents WHERE ${where})`,
    ).bind(...args),
    env.DB.prepare(
      `DELETE FROM versions WHERE url IN (SELECT url FROM documents WHERE ${where})`,
    ).bind(...args),
    env.DB.prepare(`DELETE FROM documents WHERE ${where}`).bind(...args),
  ]);
}

export function evidence(doc: Document) {
  return {
    url: doc.url,
    title: doc.title,
    source: doc.source,
    source_kind: doc.source_kind,
    completeness: doc.completeness,
    content_hash: doc.content_hash,
    retrieved_at: new Date(doc.retrieved_at).toISOString(),
    verified_at: doc.verified_at
      ? new Date(doc.verified_at).toISOString()
      : null,
    age_seconds: Math.max(
      0,
      Math.floor((Date.now() - doc.retrieved_at) / 1000),
    ),
    trust_level: doc.verified_at ? 2 : 1,
    ...(doc.archived_at ? { archived_at: doc.archived_at } : {}),
  };
}
