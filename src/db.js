/*
 * One small interface over Postgres: query(text, params) -> { rows, count } and
 * transaction(fn), where fn receives its own query function bound to one connection.
 * Hosted: node-postgres with DATABASE_URL. Local and tests: PGlite (see db-local.js).
 */

const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS users (
    id         TEXT PRIMARY KEY,
    sub        TEXT NOT NULL UNIQUE,              -- pairwise Veyns subject: only meaningful to this app
    name       TEXT,
    balance    INTEGER NOT NULL CHECK (balance >= 0),
    created_at BIGINT NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS sessions (
    id_hash    TEXT PRIMARY KEY,                  -- SHA-256 of the cookie value
    user_id    TEXT NOT NULL REFERENCES users(id),
    expires_at BIGINT NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS login_nonces (
    id         TEXT PRIMARY KEY,                  -- held by the browser in an HttpOnly cookie
    nonce      TEXT NOT NULL,
    expires_at BIGINT NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS transfers (
    id         TEXT PRIMARY KEY,
    from_user  TEXT NOT NULL REFERENCES users(id),
    to_user    TEXT NOT NULL REFERENCES users(id),
    amount     INTEGER NOT NULL CHECK (amount > 0),
    note       TEXT NOT NULL DEFAULT '',
    status     TEXT NOT NULL CHECK (status IN ('draft', 'held', 'accepted', 'declined', 'recalled', 'discarded')),
    created_at BIGINT NOT NULL,
    sent_at    BIGINT,
    expires_at BIGINT,
    closed_at  BIGINT
  )`,
  `CREATE TABLE IF NOT EXISTS approvals (
    id           TEXT PRIMARY KEY,                -- also the Veyns idempotency key and operation id
    transfer_id  TEXT NOT NULL REFERENCES transfers(id),
    kind         TEXT NOT NULL CHECK (kind IN ('send', 'accept')),
    user_id      TEXT NOT NULL REFERENCES users(id),
    statement    TEXT NOT NULL,
    details      TEXT NOT NULL,
    digest       TEXT NOT NULL,
    nonce        TEXT NOT NULL,
    status       TEXT NOT NULL CHECK (status IN ('open', 'approved', 'failed', 'cancelled')),
    method       TEXT,
    request_id   TEXT,
    challenge    TEXT,
    approval_url TEXT,
    decision_id  TEXT,
    acked        BOOLEAN NOT NULL DEFAULT false,
    proof_id     TEXT UNIQUE,                     -- token jti or decision id: one proof settles one approval
    error        TEXT,
    created_at   BIGINT NOT NULL,
    closed_at    BIGINT
  )`,
  'CREATE INDEX IF NOT EXISTS transfers_from ON transfers (from_user, status)',
  'CREATE INDEX IF NOT EXISTS transfers_to ON transfers (to_user, status)',
  'CREATE INDEX IF NOT EXISTS approvals_transfer ON approvals (transfer_id, status)',
];

const INT8 = 20; // Timestamps are BIGINT; read them back as numbers.

export const isUniqueViolation = error => error?.code === '23505';

async function migrate(db) {
  await db.transaction(async q => {
    // Several cold-starting instances may race to create the schema.
    await q('SELECT pg_advisory_xact_lock(4960)');
    for (const statement of SCHEMA) await q(statement);
  });
}

async function openPostgres(url) {
  const { default: pg } = await import('pg');
  const pool = new pg.Pool({
    connectionString: url,
    max: 5,
    idleTimeoutMillis: 5_000,
    connectionTimeoutMillis: 10_000,
    types: { getTypeParser: (oid, format) => (oid === INT8 ? Number : pg.types.getTypeParser(oid, format)) },
  });
  const wrap = result => ({ rows: result.rows, count: result.rowCount ?? 0 });
  return {
    query: async (text, params) => wrap(await pool.query(text, params)),
    async transaction(fn) {
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        const result = await fn(async (text, params) => wrap(await client.query(text, params)));
        await client.query('COMMIT');
        return result;
      } catch (error) {
        await client.query('ROLLBACK').catch(() => {});
        throw error;
      } finally {
        client.release();
      }
    },
    close: () => pool.end(),
  };
}

/** Opens Postgres when a URL is given, otherwise PGlite (in memory, or persisted under `dir`). */
export async function openDb({ url, dir }) {
  let db;
  if (url) {
    db = await openPostgres(url);
  } else {
    // A computed specifier keeps PGlite (a dev dependency) out of the deployed function bundle.
    const localModule = './db-local.js';
    const { openPglite } = await import(localModule);
    db = await openPglite(dir, INT8);
  }
  await migrate(db);
  return db;
}
