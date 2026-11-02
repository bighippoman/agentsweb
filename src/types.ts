export interface Env {
  CACHE: KVNamespace;
  DB: D1Database;
  REVALIDATE: Queue<{ url: string }>;
  ADMIN_SECRET: string;
  CF_API_TOKEN?: string;
  CF_ACCOUNT_ID?: string;
}

export interface Document {
  url: string;
  markdown: string;
  source: string;
  source_kind: "live" | "archive" | "metadata";
  completeness: "complete" | "partial";
  retrieved_at: number;
  verified_at: number | null;
  content_hash: string;
  title: string;
  expires_at: number;
  archived_at?: string;
}

export interface Passage {
  url: string;
  heading: string;
  text: string;
  start: number;
  end: number;
  citation_url: string;
}
