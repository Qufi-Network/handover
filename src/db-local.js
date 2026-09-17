import { PGlite } from '@electric-sql/pglite';

/** Postgres compiled to WebAssembly, for local runs and tests. */
export async function openPglite(dir, int8Oid) {
  const pg = await PGlite.create({ ...(dir ? { dataDir: dir } : {}), parsers: { [int8Oid]: Number } });
  const wrap = result => ({ rows: result.rows, count: result.affectedRows ?? 0 });
  return {
    query: async (text, params) => wrap(await pg.query(text, params)),
    transaction: fn => pg.transaction(tx => fn(async (text, params) => wrap(await tx.query(text, params)))),
    close: () => pg.close(),
  };
}
