# Handover

A small app built on the Veyns sandbox. You hand play-money credits to someone and approve it with Veyns. They have 24 hours to accept with their own Veyns approval (browser or palm). If they don't, you recall the credits.

Node 24, no build step. Data lives in Postgres. Locally that's PGlite (Postgres running inside Node, stored in `data/pgdata`); on Vercel it's a hosted Postgres database.

## Run it

```bash
npm install
node server.js
```

Open http://localhost:4960. The first screen shows the exact values to register.

## Connect it to Veyns

1. Go to https://sandbox.id.veyns.io/console and sign in.
2. Register an application:
   - Website origin: `http://localhost:4960`
   - Redirect URI: `http://localhost:4960/` (the SDK always uses the page origin plus `/`)
   - ID token signature: **ES256**
3. Paste the client ID into the setup screen. It is saved to `data/config.json`.

For palm approvals, also create a **backend credential** in the console. Copy `.env.example` to `.env`, put the secret in `VEYNS_BACKEND_SECRET`, then restart. Palm also needs Veyns staff to admit the app and the accounts to the pilot, and each person to connect their scanner from their Veyns account page.

If the console refuses a `localhost` origin, serve the app over HTTPS (for example through a tunnel). Set `PUBLIC_ORIGIN` to that address and register it instead.

## Deploy to Vercel

`public/` is served from Vercel's CDN. Every `/api/*` request goes to one function, `api/handler.js`, through the rewrite in `vercel.json`.

1. `npx vercel login`, then `npx vercel deploy --prod` from this folder. Note the production address, for example `https://veyns-handover.vercel.app`.
2. In the Vercel dashboard, open the project → **Storage** → create a **Neon** Postgres database and connect it. That adds `DATABASE_URL`, and the tables are created on first use.
3. In the Veyns console, register that exact address as the origin, the address plus `/` as the redirect URI, and ES256.
4. Project → **Settings → Environment Variables**: add `VEYNS_CLIENT_ID`, and `VEYNS_BACKEND_SECRET` if you want palm approvals.
5. Redeploy: `npx vercel deploy --prod`.

The app uses the production domain as its origin (`VERCEL_PROJECT_PRODUCTION_URL`). Preview deployments are refused by the origin check, because Veyns only accepts the registered origin. Set `PUBLIC_ORIGIN` if you add a custom domain.

## How it uses Veyns

| Step | Veyns feature | Server checks |
|---|---|---|
| Sign in | `veyns.signin` with a server nonce | signature (JWKS), issuer, audience, expiry, single-use nonce bound to this browser, `veyns_intent=login`, fresh `auth_time` |
| Approve a send or accept, in the browser | `veyns.approve` with a per-approval nonce | the above, plus same account, `veyns_intent=action`, digest equals the stored action, token used once; then `/v1/actions/consume` |
| Approve with palm | `POST /v1/approvals`, polled | decision signature, `request_id`, `request_nonce`, `amr` includes `veyns:palm`, digest, freshness; then `/ack` |

Each hand-over's statement and details are built and stored on the server. The browser never decides what gets approved. Claiming the approval, moving the balance and changing the hand-over state happen in one Postgres transaction. Each step is a conditional update whose row count is checked. So a replayed approval can't run twice, and an accept racing a recall on another server instance can't both succeed.

The receiver has `HOLD_SECONDS`, judged by when they approved. Recall opens `GRACE_SECONDS` after that, so an approval finished just in time still lands. To try recall quickly, set `HOLD_SECONDS=120` and `GRACE_SECONDS=10`.

## Test

```bash
npm test
```

The tests run the whole server on in-memory PGlite against a fake Veyns issuer that signs real ES256 tokens. They also cover the Vercel entry point. They cover forged, replayed, wrong-app and wrong-action tokens, palm decisions that aren't palm scans, the window and grace period, recall, decline and discarded drafts.
