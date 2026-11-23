/**
 * Login sessions for the dashboard. The cookie carries random bytes; only
 * their SHA-256 is persisted, so this table cannot be replayed as a login if
 * read. `get` enforces expiry in the query, so an expired row never resolves.
 */
export interface Session {
  email: string;
  expiresAt: number;
}

export interface SessionStore {
  create(tokenHash: string, email: string, now: number, expiresAt: number): Promise<void>;
  get(tokenHash: string, now: number): Promise<Session | null>;
  delete(tokenHash: string): Promise<void>;
}

export function d1SessionStore(db: D1Database): SessionStore {
  return {
    async create(tokenHash, email, now, expiresAt) {
      await db
        .prepare("INSERT OR REPLACE INTO sessions (token_hash, email, created_at, expires_at) VALUES (?1,?2,?3,?4)")
        .bind(tokenHash, email, now, expiresAt)
        .run();
    },

    async get(tokenHash, now) {
      const row = await db
        .prepare("SELECT email, expires_at FROM sessions WHERE token_hash=?1 AND expires_at>?2")
        .bind(tokenHash, now)
        .first<{ email: string; expires_at: number }>();
      return row ? { email: row.email, expiresAt: row.expires_at } : null;
    },

    async delete(tokenHash) {
      await db.prepare("DELETE FROM sessions WHERE token_hash=?1").bind(tokenHash).run();
    },
  };
}

/** Node-test fake. Expiry is checked in `get`, matching the SQL predicate. */
export function memorySessionStore(): SessionStore {
  const rows = new Map<string, Session & { createdAt: number }>();
  return {
    async create(tokenHash, email, now, expiresAt) {
      rows.set(tokenHash, { email, expiresAt, createdAt: now });
    },
    async get(tokenHash, now) {
      const row = rows.get(tokenHash);
      if (!row || row.expiresAt <= now) return null;
      return { email: row.email, expiresAt: row.expiresAt };
    },
    async delete(tokenHash) {
      rows.delete(tokenHash);
    },
  };
}