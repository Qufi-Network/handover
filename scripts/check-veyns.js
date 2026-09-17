/*
 * Live checks against the real Veyns sandbox and a deployed Handover.
 *
 *   node scripts/check-veyns.js https://handover-lac.vercel.app
 *
 * Everything a script can prove without a person: discovery, signing keys, that Veyns
 * accepts this origin for sign-in, palm sign-in and approvals, the app's own config and
 * database, and (if VEYNS_BACKEND_SECRET is set locally) the backend credential.
 * The ceremonies themselves need a real person and a real palm.
 */
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
try { process.loadEnvFile(path.join(root, '.env')); } catch { /* optional */ }

const appUrl = (process.argv[2] || process.env.PUBLIC_ORIGIN || '').replace(/\/$/, '');
const issuer = (process.env.VEYNS_ISSUER || 'https://sandbox.id.veyns.io').replace(/\/$/, '');
const secret = process.env.VEYNS_BACKEND_SECRET || '';
if (!appUrl) {
  console.error('Usage: node scripts/check-veyns.js https://your-app.vercel.app');
  process.exit(2);
}

let failures = 0;
const pass = (name, detail = '') => console.log(`  ✔ ${name}${detail ? ` — ${detail}` : ''}`);
const fail = (name, detail = '') => { failures++; console.log(`  ✖ ${name}${detail ? ` — ${detail}` : ''}`); };
const skip = (name, detail = '') => console.log(`  – ${name}${detail ? ` — ${detail}` : ''}`);
const b64 = bytes => crypto.randomBytes(bytes).toString('base64url');

async function http(url, init = {}) {
  const response = await fetch(url, { ...init, signal: AbortSignal.timeout(15_000) });
  const text = await response.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* HTML error pages */ }
  const plain = text.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 160);
  return { status: response.status, json, plain };
}

/** Starts a ceremony exactly as veyns.js does, from the app's origin. Nothing is approved. */
function prepare(clientId, intent, extra = {}) {
  const verifier = b64(48);
  return http(`${issuer}/v1/authorize/prepare`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin: appUrl },
    body: JSON.stringify({
      response_type: 'code', response_mode: 'web_message', client_id: clientId,
      redirect_uri: `${appUrl}/`, scope: `openid ${intent}`, state: b64(16), nonce: b64(24),
      code_challenge: crypto.createHash('sha256').update(verifier).digest('base64url'),
      code_challenge_method: 'S256', intent, ...extra,
    }),
  });
}

const describe = r => (r.json ? r.json.error_description || r.json.error || JSON.stringify(r.json).slice(0, 160) : r.plain);

console.log(`\nVeyns sandbox: ${issuer}`);
const discovery = await http(`${issuer}/.well-known/openid-configuration`);
const d = discovery.json || {};
if (discovery.status === 200 && d.issuer === issuer && d.code_challenge_methods_supported?.includes('S256')
  && d.id_token_signing_alg_values_supported?.includes('ES256')) pass('discovery', 'issuer, PKCE S256 and ES256 advertised');
else fail('discovery', `HTTP ${discovery.status}`);

const jwks = await http(`${issuer}/jwks.json`);
const ecKeys = (jwks.json?.keys || []).filter(k => k.kty === 'EC' && k.crv === 'P-256' && k.kid);
let imported = 0;
for (const k of ecKeys) {
  try { crypto.createPublicKey({ key: { kty: 'EC', crv: 'P-256', x: k.x, y: k.y }, format: 'jwk' }); imported++; } catch { /* counted below */ }
}
if (imported > 0 && imported === ecKeys.length) pass('signing keys', `${imported} ES256 key(s) load in Node`);
else fail('signing keys', `${imported}/${ecKeys.length} ES256 keys usable`);

console.log(`\nApp: ${appUrl}`);
const config = await http(`${appUrl}/api/config`);
const c = config.json || {};
if (config.status !== 200) {
  fail('app config', `HTTP ${config.status}: ${describe(config)}`);
  process.exit(1);
}
c.configured ? pass('client ID set', c.clientId) : fail('client ID set', 'add VEYNS_CLIENT_ID and redeploy');
c.publicOrigin === appUrl ? pass('origin', c.publicOrigin) : fail('origin', `app thinks it is ${c.publicOrigin}; set PUBLIC_ORIGIN=${appUrl}`);
c.palmEnabled ? pass('palm approvals switched on', 'VEYNS_BACKEND_SECRET is set on the server')
  : fail('palm approvals switched on', 'add VEYNS_BACKEND_SECRET in Vercel and redeploy');
c.requirePalm ? pass('palm required', 'REQUIRE_PALM=true') : skip('palm required', 'optional: REQUIRE_PALM=true refuses browser sign-in and approvals');

const login = await http(`${appUrl}/api/login/start`, { method: 'POST', headers: { origin: appUrl, 'content-type': 'application/json' }, body: '{}' });
login.status === 200 ? pass('database', 'sign-in nonce written') : fail('database', `HTTP ${login.status}: ${describe(login)}`);

if (c.clientId) {
  console.log(`\nVeyns accepts this app (${c.clientId}) from ${appUrl}`);
  const checks = [
    ['browser sign-in', await prepare(c.clientId, 'login')],
    ['palm sign-in', await prepare(c.clientId, 'login', { required_method: 'palm' })],
    ['approval', await prepare(c.clientId, 'action', { action: { statement: 'Handover live check', details: { check: true } } })],
  ];
  for (const [name, r] of checks) {
    const target = r.json?.authorization_url ? new URL(r.json.authorization_url) : null;
    if (r.status < 300 && target?.origin === issuer && target.pathname === '/authorize') pass(name, 'ceremony can start');
    else fail(name, `HTTP ${r.status}: ${describe(r)}`);
  }
}

console.log('\nBackend credential (palm approvals from the server)');
const anonymous = await http(`${issuer}/v1/approvals/${b64(24)}`);
anonymous.status === 401 ? pass('approvals API refuses anonymous calls') : fail('approvals API refuses anonymous calls', `HTTP ${anonymous.status}`);
if (secret && c.clientId) {
  const authorization = 'Basic ' + Buffer.from(`${c.clientId}:${secret}`).toString('base64');
  const probe = await http(`${issuer}/v1/approvals/${b64(24)}`, { headers: { authorization } });
  if (probe.status === 401) fail('credential accepted', 'Veyns rejected it: create or rotate it in the console');
  else if (probe.status === 404) pass('credential accepted', 'Veyns authenticated the app (unknown request id → 404)');
  else skip('credential accepted', `unexpected HTTP ${probe.status}: ${describe(probe)}`);
} else {
  skip('credential accepted', 'set VEYNS_BACKEND_SECRET in a local .env to check it from here');
}

console.log(failures ? `\n${failures} check(s) need attention.\n` : '\nEverything a script can check is working. Next: a real palm sign-in.\n');
process.exit(failures ? 1 : 0);
