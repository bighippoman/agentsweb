CREATE TABLE documents (
  url TEXT PRIMARY KEY, host TEXT NOT NULL, title TEXT NOT NULL,
  content_hash TEXT NOT NULL, source TEXT NOT NULL, source_kind TEXT NOT NULL,
  completeness TEXT NOT NULL, retrieved_at INTEGER NOT NULL, verified_at INTEGER,
  expires_at INTEGER NOT NULL, archived_at TEXT
);
CREATE INDEX documents_expiry ON documents(expires_at);
CREATE INDEX documents_host ON documents(host);
CREATE TABLE versions (
  url TEXT NOT NULL, content_hash TEXT NOT NULL, retrieved_at INTEGER NOT NULL,
  PRIMARY KEY(url, content_hash)
);
CREATE TABLE chunks (
  id INTEGER PRIMARY KEY, url TEXT NOT NULL, content_hash TEXT NOT NULL,
  ordinal INTEGER NOT NULL, title TEXT NOT NULL, heading TEXT NOT NULL, text TEXT NOT NULL,
  start INTEGER NOT NULL, end INTEGER NOT NULL, citation_url TEXT NOT NULL,
  UNIQUE(url, content_hash, ordinal)
);
CREATE INDEX chunks_document ON chunks(url, content_hash);
CREATE VIRTUAL TABLE chunks_fts USING fts5(title, heading, text, content='chunks', content_rowid='id', tokenize='unicode61');
CREATE TRIGGER chunks_insert AFTER INSERT ON chunks BEGIN
  INSERT INTO chunks_fts(rowid,title,heading,text) VALUES(new.id,new.title,new.heading,new.text);
END;
CREATE TRIGGER chunks_delete AFTER DELETE ON chunks BEGIN
  INSERT INTO chunks_fts(chunks_fts,rowid,title,heading,text) VALUES('delete',old.id,old.title,old.heading,old.text);
END;
CREATE TABLE counters (name TEXT PRIMARY KEY, value INTEGER NOT NULL DEFAULT 0);
CREATE TABLE limits (key TEXT PRIMARY KEY, count INTEGER NOT NULL, expires_at INTEGER NOT NULL);
CREATE INDEX limits_expiry ON limits(expires_at);
CREATE TABLE jobs (url TEXT PRIMARY KEY, queued_at INTEGER NOT NULL);
CREATE TABLE removals (key TEXT PRIMARY KEY, reason TEXT NOT NULL, created_at INTEGER NOT NULL);
