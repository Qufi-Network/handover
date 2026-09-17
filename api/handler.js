import { createApp } from '../src/app.js';

// Vercel serves public/ from its CDN and sends every /api/* request here (see vercel.json).
const env = process.env;
const productionHost = env.VERCEL_PROJECT_PRODUCTION_URL;

const app = createApp({
  // Veyns only accepts the exact origin registered in its console, so default to the production domain.
  publicOrigin: (env.PUBLIC_ORIGIN || (productionHost ? `https://${productionHost}` : 'http://localhost:3000')).replace(/\/$/, ''),
  issuer: (env.VEYNS_ISSUER || 'https://sandbox.id.veyns.io').replace(/\/$/, ''),
  clientId: env.VEYNS_CLIENT_ID || '',
  backendSecret: env.VEYNS_BACKEND_SECRET || '',
  requirePalm: env.REQUIRE_PALM === 'true',
  databaseUrl: env.DATABASE_URL || env.POSTGRES_URL || '',
  requireDatabaseUrl: true,
  holdSeconds: Number(env.HOLD_SECONDS || 86_400),
  graceSeconds: Number(env.GRACE_SECONDS || 300),
  startingCredits: Number(env.STARTING_CREDITS || 1000),
});

export default function handler(req, res) {
  // The rewrite passes the original path as __path; put it back so the app routes normally.
  const url = new URL(req.url, 'http://internal');
  const original = url.searchParams.get('__path');
  if (original !== null) {
    url.searchParams.delete('__path');
    req.url = `/api/${original}${url.search}`;
  }
  return app.handle(req, res);
}
