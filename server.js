import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createApp } from './src/app.js';

const root = path.dirname(fileURLToPath(import.meta.url));
try {
  process.loadEnvFile(path.join(root, '.env'));
} catch {
  // No .env yet: defaults work, and the app walks you through connecting to Veyns.
}

const env = process.env;
const port = Number(env.PORT || 4960);
const host = env.HOST || '127.0.0.1';
const publicOrigin = (env.PUBLIC_ORIGIN || `http://localhost:${port}`).replace(/\/$/, '');
const dataDir = path.resolve(root, env.DATA_DIR || 'data');
fs.mkdirSync(dataDir, { recursive: true });

const app = createApp({
  publicOrigin,
  issuer: (env.VEYNS_ISSUER || 'https://sandbox.id.veyns.io').replace(/\/$/, ''),
  clientId: env.VEYNS_CLIENT_ID || '',
  backendSecret: env.VEYNS_BACKEND_SECRET || '',
  // Without DATABASE_URL, a local PGlite database lives in data/pgdata.
  databaseUrl: env.DATABASE_URL || '',
  holdSeconds: Number(env.HOLD_SECONDS || 86_400),
  graceSeconds: Number(env.GRACE_SECONDS || 300),
  startingCredits: Number(env.STARTING_CREDITS || 1000),
  dataDir,
  publicDir: path.join(root, 'public'),
});

app.server.listen(port, host, () => {
  console.log(`Handover is running at ${publicOrigin}`);
});
