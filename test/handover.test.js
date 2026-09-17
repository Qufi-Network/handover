import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import http from 'node:http';
import { createApp } from '../src/app.js';
import { actionDigest, canonicalJson } from '../src/veyns.js';

const ISSUER = 'https://issuer.test';
const ORIGIN = 'http://handover.test';
const CLIENT_ID = 'handover-test';
const SECRET = 'backend-secret';
const quiet = { error() {}, warn() {}, log() {} };

/** A stand-in for the Veyns service: real ES256 signatures, in-memory palm requests. */
function mockIssuer(clock) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'k1', alg: 'ES256', use: 'sig' };
  const requests = new Map();
  const log = { created: [], acks: [], consumed: [], cancelled: [] };
  const b64 = value => Buffer.from(JSON.stringify(value)).toString('base64url');
  const json = (status, body) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

  function token(claims) {
    const t = clock();
    const input = `${b64({ alg: 'ES256', kid: 'k1', typ: 'JWT' })}.${b64({
      iss: ISSUER, aud: CLIENT_ID, iat: t, exp: t + 300, auth_time: t,
      veyns_presence: true, amr: ['veyns:browser'], ...claims,
    })}`;
    const signature = crypto.sign('sha256', Buffer.from(input), { key: privateKey, dsaEncoding: 'ieee-p1363' });
    return `${input}.${signature.toString('base64url')}`;
  }

  async function fetch(url, init = {}) {
    const { pathname } = new URL(url);
    const method = init.method || 'GET';
    const body = init.body ? JSON.parse(init.body) : undefined;
    if (pathname === '/jwks.json') return json(200, { keys: [jwk] });
    if (init.headers?.authorization !== 'Basic ' + Buffer.from(`${CLIENT_ID}:${SECRET}`).toString('base64')) {
      return json(401, { error: 'invalid_client' });
    }
    if (method === 'POST' && pathname === '/v1/approvals') {
      log.approvalHeaders = init.headers;
      if (mock.refuseApprovals) return json(400, { error: 'invalid_request', error_description: mock.refuseApprovals });
      const id = crypto.randomBytes(18).toString('base64url');
      const record = {
        request_id: id, subject: body.subject, status: 'pending', required_method: 'palm', kind: 'approval',
        challenge: crypto.randomBytes(18).toString('base64url'),
        action: { ...body.action, digest: actionDigest(body.action.statement, body.action.details) },
        approval_url: `${ISSUER}/approve#${id}.${'v'.repeat(32)}`,
      };
      requests.set(id, record);
      log.created.push(record);
      return json(201, record);
    }
    let m;
    if (method === 'GET' && (m = pathname.match(/^\/v1\/approvals\/([^/]+)$/))) return json(200, requests.get(m[1]));
    if ((m = pathname.match(/^\/v1\/approvals\/([^/]+)\/cancel$/))) {
      log.cancelled.push(m[1]);
      return json(200, requests.get(m[1]));
    }
    if ((m = pathname.match(/^\/v1\/approvals\/([^/]+)\/ack$/))) {
      log.acks.push({ request_id: m[1], ...body });
      return json(200, { acknowledged: true });
    }
    if (pathname === '/v1/actions/consume') {
      log.consumed.push(body);
      return json(200, {});
    }
    return json(404, { error: 'not_found' });
  }

  function approvePalm(requestId, overrides = {}) {
    const r = requests.get(requestId);
    r.status = 'approved';
    r.decision_id = crypto.randomBytes(12).toString('base64url');
    r.decision = token({
      sub: r.subject, veyns_intent: 'action', amr: ['veyns:palm'], request_id: r.request_id,
      request_nonce: r.challenge, veyns_action: { statement: r.action.statement, digest: r.action.digest },
      ...overrides,
    });
  }

  const mock = { fetch, token, approvePalm, log, refuseApprovals: null };
  return mock;
}

async function start(t, overrides = {}) {
  let time = 1_800_000_000;
  const clock = () => time;
  const issuer = mockIssuer(clock);
  const app = createApp({
    publicOrigin: ORIGIN, issuer: ISSUER, clientId: CLIENT_ID, backendSecret: SECRET,
    now: clock, fetchImpl: issuer.fetch, log: quiet, ...overrides,
  });
  await new Promise(resolve => app.server.listen(0, '127.0.0.1', resolve));
  t.after(() => app.close());
  const { port } = app.server.address();

  function client() {
    const jar = new Map();
    const call = (method, path, body, headers = {}) => new Promise((resolve, reject) => {
      const payload = body === undefined ? undefined : JSON.stringify(body);
      const req = http.request({
        host: '127.0.0.1', port, method, path,
        headers: {
          origin: ORIGIN,
          cookie: [...jar].map(([k, v]) => `${k}=${v}`).join('; '),
          ...(payload ? { 'content-type': 'application/json' } : {}),
          ...headers,
        },
      }, res => {
        for (const cookie of res.headers['set-cookie'] || []) {
          const pair = cookie.split(';')[0];
          const i = pair.indexOf('=');
          if (/Max-Age=0\b/.test(cookie)) jar.delete(pair.slice(0, i));
          else jar.set(pair.slice(0, i), pair.slice(i + 1));
        }
        let data = '';
        res.on('data', chunk => { data += chunk; });
        res.on('end', () => resolve({ status: res.statusCode, body: data ? JSON.parse(data) : null }));
      });
      req.on('error', reject);
      req.end(payload);
    });
    return { get: path => call('GET', path), post: (path, body = {}, headers) => call('POST', path, body, headers) };
  }

  return { issuer, client, advance: seconds => { time += seconds; } };
}

function ok(response) {
  assert.equal(response.status, 200, JSON.stringify(response.body));
  return response.body;
}

async function signIn(env, sub, name) {
  const c = env.client();
  const { nonce } = ok(await c.post('/api/login/start'));
  ok(await c.post('/api/login/finish', { token: env.issuer.token({ sub, nonce, veyns_intent: 'login' }) }));
  ok(await c.post('/api/profile', { name }));
  return c;
}

const approvalToken = (env, sub, approval, extra = {}) => env.issuer.token({
  sub, nonce: approval.nonce, veyns_intent: 'action', jti: crypto.randomUUID(),
  veyns_action: { statement: approval.statement, digest: actionDigest(approval.statement, approval.details) },
  ...extra,
});

async function sendAndApprove(env, from, fromSub, toId, amount, holdSeconds) {
  const { approval } = ok(await from.post('/api/transfers', { to: toId, amount, holdSeconds }));
  const { transfer } = ok(await from.post(`/api/approvals/${approval.id}/browser`, { token: approvalToken(env, fromSub, approval) }));
  return transfer;
}

async function twoPeople(t, options) {
  const env = await start(t, options);
  const alice = await signIn(env, 'sub-alice', 'Alice');
  const bob = await signIn(env, 'sub-bob', 'Bob');
  const bobId = ok(await alice.get('/api/me')).people.find(p => p.name === 'Bob').id;
  return { env, alice, bob, bobId };
}

test('the Vercel entry restores rewritten paths, reads pre-parsed bodies and stays in hosted mode', async t => {
  Object.assign(process.env, { VERCEL_PROJECT_PRODUCTION_URL: 'handover.example.app', VEYNS_CLIENT_ID: 'hosted-client' });
  for (const name of ['DATABASE_URL', 'STORAGE_URL', 'POSTGRES_URL', 'STORAGE_DATABASE_URL']) delete process.env[name];
  const { default: handler } = await import('../api/handler.js');

  const server = http.createServer(async (req, res) => {
    // Imitate Vercel's helpers: the body stream is already consumed and exposed as req.body.
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const raw = Buffer.concat(chunks).toString('utf8');
    Object.defineProperty(req, 'body', { get: () => (raw ? JSON.parse(raw) : undefined) });
    handler(req, res);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }));

  const call = (method, path, raw) => new Promise((resolve, reject) => {
    const req = http.request({
      host: '127.0.0.1', port: server.address().port, method, path,
      headers: { origin: 'https://handover.example.app', 'content-type': 'application/json' },
    }, res => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(data) }));
    });
    req.on('error', reject);
    req.end(raw);
  });

  const config = await call('GET', '/api/handler?__path=config');
  assert.equal(config.status, 200);
  assert.equal(config.body.publicOrigin, 'https://handover.example.app');
  assert.equal(config.body.clientId, 'hosted-client');
  assert.equal(config.body.canSaveClientId, false);

  assert.equal((await call('POST', '/api/handler?__path=setup', 'not json')).status, 400);
  assert.equal((await call('POST', '/api/handler?__path=setup', JSON.stringify({ clientId: 'other-client' }))).status, 403);
  const noDatabase = await call('POST', '/api/handler?__path=login/start', '{}');
  assert.equal(noDatabase.status, 503);
  assert.match(noDatabase.body.error, /add Postgres/);
  assert.equal((await call('GET', '/api/handler?__path=transfers/abcdefgh/nope')).status, 404);
});

test('canonical digest follows the Veyns rules', () => {
  const canonical = canonicalJson({
    statement: 'Transfer $450.00 to Omar K.',
    details: { to: 'omar-k', amount: '450.00', currency: 'USD', nested: { b: [2, 1], a: null } },
  });
  assert.equal(canonical,
    '{"details":{"amount":"450.00","currency":"USD","nested":{"a":null,"b":[2,1]},"to":"omar-k"},"statement":"Transfer $450.00 to Omar K."}');
  assert.equal(actionDigest('Hi'),
    crypto.createHash('sha256').update('{"details":null,"statement":"Hi"}').digest('base64url'));
});

test('sign-in requires this browser\'s single-use nonce, a valid signature and the right app', async t => {
  const env = await start(t);
  const c = env.client();

  let { nonce } = ok(await c.post('/api/login/start'));
  assert.equal((await c.post('/api/login/finish', { token: env.issuer.token({ sub: 's', nonce: 'x'.repeat(43), veyns_intent: 'login' }) })).status, 401);
  // The nonce was consumed by the failed attempt.
  assert.equal((await c.post('/api/login/finish', { token: env.issuer.token({ sub: 's', nonce, veyns_intent: 'login' }) })).status, 401);

  ({ nonce } = ok(await c.post('/api/login/start')));
  assert.equal((await c.post('/api/login/finish', { token: env.issuer.token({ sub: 's', nonce, veyns_intent: 'login', aud: 'other-app' }) })).status, 401);

  ({ nonce } = ok(await c.post('/api/login/start')));
  const [h, , s] = env.issuer.token({ sub: 's', nonce, veyns_intent: 'login' }).split('.');
  const forged = Buffer.from(JSON.stringify({ iss: ISSUER, aud: CLIENT_ID, sub: 'admin', nonce, veyns_intent: 'login', veyns_presence: true, exp: 1_900_000_000, auth_time: 1_800_000_000 })).toString('base64url');
  assert.equal((await c.post('/api/login/finish', { token: `${h}.${forged}.${s}` })).status, 401);

  assert.equal((await c.post('/api/login/start', {}, { origin: 'https://elsewhere.test' })).status, 403);
  assert.equal((await c.get('/api/me')).status, 401);

  ({ nonce } = ok(await c.post('/api/login/start')));
  ok(await c.post('/api/login/finish', { token: env.issuer.token({ sub: 's', nonce, veyns_intent: 'login' }) }));
  assert.equal(ok(await c.get('/api/me')).user.balance, 1000);
});

test('hand over with a browser approval, accept with a palm approval', async t => {
  const { env, alice, bob, bobId } = await twoPeople(t);

  const { approval } = ok(await alice.post('/api/transfers', { to: bobId, amount: 250, note: 'lunch' }));
  assert.equal(approval.statement, 'Hand over 250 credits to Bob, returned to you if not accepted within 24 hours');
  assert.deepEqual(approval.details, {
    transfer: approval.transferId, amount: 250, unit: 'credits', to: 'Bob',
    accept_within: '24 hours', accept_within_seconds: 86_400, if_not_accepted: 'returned to sender', note: 'lunch',
  });

  const wrongAction = approvalToken(env, 'sub-alice', { ...approval, statement: 'Hand over 9,999 credits to Bob' });
  assert.equal((await alice.post(`/api/approvals/${approval.id}/browser`, { token: wrongAction })).status, 401);
  assert.equal((await bob.post(`/api/approvals/${approval.id}/browser`, { token: approvalToken(env, 'sub-bob', approval) })).status, 404);

  const token = approvalToken(env, 'sub-alice', approval);
  ok(await alice.post(`/api/approvals/${approval.id}/browser`, { token }));
  assert.equal((await alice.post(`/api/approvals/${approval.id}/browser`, { token })).status, 409, 'replay is refused');
  assert.equal(env.issuer.log.consumed.length, 1);
  assert.equal(env.issuer.log.consumed[0].operation_id, approval.id);
  assert.equal(ok(await alice.get('/api/me')).user.balance, 750);

  const [held] = ok(await bob.get('/api/me')).incoming;
  assert.equal(held.amount, 250);
  assert.ok(held.canAccept);

  const { approval: accept } = ok(await bob.post(`/api/transfers/${held.id}/approval`));
  assert.equal(accept.statement, 'Accept 250 credits from Alice');
  const started = ok(await bob.post(`/api/approvals/${accept.id}/palm`));
  assert.match(started.approval.approvalUrl, /\/approve#/);
  const requestId = env.issuer.log.created.at(-1).request_id;
  assert.equal(env.issuer.log.created.at(-1).subject, 'pairwise:handover-test:sub-bob');
  assert.equal(env.issuer.log.approvalHeaders['idempotency-key'], accept.id);
  assert.equal(ok(await bob.get(`/api/approvals/${accept.id}`)).approval.status, 'open');

  env.issuer.approvePalm(requestId);
  assert.equal(ok(await bob.get(`/api/approvals/${accept.id}`)).approval.status, 'approved');
  assert.equal(ok(await bob.get('/api/me')).user.balance, 1250);
  ok(await bob.get(`/api/approvals/${accept.id}`));
  assert.deepEqual(env.issuer.log.acks.map(a => a.operation_id), [accept.id], 'acknowledged exactly once');
  assert.equal(ok(await alice.get('/api/me')).history[0].status, 'accepted');
});

test('REQUIRE_PALM refuses browser sign-in and browser approvals', async t => {
  const env = await start(t, { requirePalm: true });
  const c = env.client();
  assert.equal(ok(await c.get('/api/config')).requirePalm, true);

  let { nonce } = ok(await c.post('/api/login/start'));
  const browserLogin = await c.post('/api/login/finish', { token: env.issuer.token({ sub: 'sub-alice', nonce, veyns_intent: 'login' }) });
  assert.equal(browserLogin.status, 401);
  assert.match(browserLogin.body.error, /palm sign-in/);

  ({ nonce } = ok(await c.post('/api/login/start')));
  ok(await c.post('/api/login/finish', { token: env.issuer.token({ sub: 'sub-alice', nonce, veyns_intent: 'login', amr: ['veyns:palm'] }) }));
  ok(await c.post('/api/profile', { name: 'Alice' }));
  const aliceId = ok(await c.get('/api/me')).user.id;

  const { approval } = ok(await c.post('/api/transfers', { to: aliceId, amount: 10 }));
  assert.equal((await c.post(`/api/approvals/${approval.id}/browser`, { token: approvalToken(env, 'sub-alice', approval) })).status, 403);

  ok(await c.post(`/api/approvals/${approval.id}/palm`));
  env.issuer.approvePalm(env.issuer.log.created.at(-1).request_id);
  assert.equal(ok(await c.get(`/api/approvals/${approval.id}`)).approval.status, 'approved');

  // Sent to yourself: shown once, as waiting for you, so it can be accepted.
  const view = ok(await c.get('/api/me'));
  assert.equal(view.user.balance, 990);
  assert.equal(view.outgoing.length, 0);
  assert.equal(view.incoming.length, 1);
  assert.equal(view.incoming[0].direction, 'in');
  assert.equal(view.incoming[0].self, true);
  assert.equal(view.incoming[0].canAccept, true);

  const { approval: accept } = ok(await c.post(`/api/transfers/${view.incoming[0].id}/approval`));
  ok(await c.post(`/api/approvals/${accept.id}/palm`));
  env.issuer.approvePalm(env.issuer.log.created.at(-1).request_id);
  assert.equal(ok(await c.get(`/api/approvals/${accept.id}`)).approval.status, 'approved');
  assert.equal(ok(await c.get('/api/me')).user.balance, 1000);
});

test('a refused palm request says what was sent, keeps the approval open, and never doubles the prefix', async t => {
  const { env, alice, bob, bobId } = await twoPeople(t);
  const held = await sendAndApprove(env, alice, 'sub-alice', bobId, 100);
  const { approval } = ok(await bob.post(`/api/transfers/${held.id}/approval`));

  env.issuer.refuseApprovals = 'Provide the application subject and an idempotency key.';
  const refused = await bob.post(`/api/approvals/${approval.id}/palm`);
  assert.equal(refused.status, 400);
  assert.match(refused.body.error, /Provide the application subject.*subject sent as "pairwise:han…", 30 characters; key 22 characters/);
  assert.equal(ok(await bob.get(`/api/approvals/${approval.id}`)).approval.status, 'open');

  env.issuer.refuseApprovals = null;
  ok(await bob.post(`/api/approvals/${approval.id}/palm`));
  env.issuer.approvePalm(env.issuer.log.created.at(-1).request_id);
  assert.equal(ok(await bob.get(`/api/approvals/${approval.id}`)).approval.status, 'approved');

  // A subject that already carries the pairwise prefix is sent unchanged.
  const carol = env.client();
  const { nonce } = ok(await carol.post('/api/login/start'));
  ok(await carol.post('/api/login/finish', { token: env.issuer.token({ sub: 'pairwise:handover-test:carol', nonce, veyns_intent: 'login' }) }));
  ok(await carol.post('/api/profile', { name: 'Carol' }));
  const carolId = ok(await carol.get('/api/me')).user.id;
  const draft = ok(await carol.post('/api/transfers', { to: carolId, amount: 5 }));
  ok(await carol.post(`/api/approvals/${draft.approval.id}/palm`));
  assert.equal(env.issuer.log.created.at(-1).subject, 'pairwise:handover-test:carol');
});

test('a palm decision that is not a palm scan is refused', async t => {
  const { env, alice, bob, bobId } = await twoPeople(t);
  const held = await sendAndApprove(env, alice, 'sub-alice', bobId, 100);

  const { approval } = ok(await bob.post(`/api/transfers/${held.id}/approval`));
  ok(await bob.post(`/api/approvals/${approval.id}/palm`));
  env.issuer.approvePalm(env.issuer.log.created.at(-1).request_id, { amr: ['veyns:browser'] });

  const result = ok(await bob.get(`/api/approvals/${approval.id}`)).approval;
  assert.equal(result.status, 'failed');
  assert.match(result.error, /not a palm scan/);
  assert.equal(ok(await bob.get('/api/me')).user.balance, 1000);
});

test('the sender chooses 1, 5, 10 or 24 hours, and the choice is signed', async t => {
  const { env, alice, bob, bobId } = await twoPeople(t);
  const config = ok(await alice.get('/api/config'));
  assert.deepEqual(config.holdOptions.map(o => o.label), ['1 hour', '5 hours', '10 hours', '24 hours']);

  assert.equal((await alice.post('/api/transfers', { to: bobId, amount: 10, holdSeconds: 7200 })).status, 400);

  const { approval } = ok(await alice.post('/api/transfers', { to: bobId, amount: 10, holdSeconds: 3600 }));
  assert.equal(approval.statement, 'Hand over 10 credits to Bob, returned to you if not accepted within 1 hour');
  assert.equal(approval.details.accept_within_seconds, 3600);
  const { transfer } = ok(await alice.post(`/api/approvals/${approval.id}/browser`, { token: approvalToken(env, 'sub-alice', approval) }));
  assert.equal(transfer.expiresAt - transfer.sentAt, 3600);
  assert.equal(transfer.holdSeconds, 3600);

  const { approval: accept } = ok(await bob.post(`/api/transfers/${transfer.id}/approval`));
  assert.equal(accept.details.accept_by, new Date(transfer.expiresAt * 1000).toISOString());
});

test('unaccepted credits return to the sender automatically after the window', async t => {
  const { env, alice, bob, bobId } = await twoPeople(t);
  const held = await sendAndApprove(env, alice, 'sub-alice', bobId, 100, 5 * 3600);
  assert.equal(ok(await alice.get('/api/me')).user.balance, 900);

  // Bob opens a palm request but never scans.
  const { approval } = ok(await bob.post(`/api/transfers/${held.id}/approval`));
  ok(await bob.post(`/api/approvals/${approval.id}/palm`));

  env.advance(5 * 3600);
  assert.equal((await bob.post(`/api/transfers/${held.id}/approval`)).status, 409, 'window closed for accepting');
  assert.equal(ok(await alice.get('/api/me')).user.balance, 900, 'nothing returns during the grace period');

  env.advance(300);
  const aliceView = ok(await alice.get('/api/me'));
  assert.equal(aliceView.user.balance, 1000);
  assert.equal(aliceView.outgoing.length, 0);
  assert.equal(aliceView.history[0].status, 'returned');
  assert.equal(ok(await bob.get('/api/me')).incoming.length, 0);
  assert.equal(ok(await bob.get(`/api/approvals/${approval.id}`)).approval.status, 'cancelled');
  assert.ok(env.issuer.log.cancelled.includes(env.issuer.log.created.at(-1).request_id), 'the pending palm request is cancelled at Veyns');

  // Returned exactly once, however many requests arrive afterwards.
  ok(await alice.get('/api/me'));
  ok(await bob.get('/api/me'));
  assert.equal(ok(await alice.get('/api/me')).user.balance, 1000);
});

test('an approval finished before the deadline still lands during the grace period', async t => {
  const { env, alice, bob, bobId } = await twoPeople(t);
  const held = await sendAndApprove(env, alice, 'sub-alice', bobId, 100);

  env.advance(86_300);
  const { approval } = ok(await bob.post(`/api/transfers/${held.id}/approval`));
  const token = approvalToken(env, 'sub-bob', approval);
  env.advance(200);
  ok(await bob.post(`/api/approvals/${approval.id}/browser`, { token }));
  assert.equal(ok(await bob.get('/api/me')).user.balance, 1100);
  env.advance(300);
  const aliceView = ok(await alice.get('/api/me'));
  assert.equal(aliceView.user.balance, 900, 'an accepted hand-over is never returned');
  assert.equal(aliceView.history[0].status, 'accepted');
});

test('declining returns the credits at once; overspending is refused', async t => {
  const { env, alice, bob, bobId } = await twoPeople(t);
  const held = await sendAndApprove(env, alice, 'sub-alice', bobId, 400);
  ok(await bob.post(`/api/transfers/${held.id}/decline`));
  assert.equal(ok(await alice.get('/api/me')).user.balance, 1000);

  assert.equal((await alice.post('/api/transfers', { to: bobId, amount: 1001 })).status, 409);

  // Starting a new hand-over discards the old draft, so its approval can no longer move credits.
  const stale = ok(await alice.post('/api/transfers', { to: bobId, amount: 900 })).approval;
  const fresh = ok(await alice.post('/api/transfers', { to: bobId, amount: 200 })).approval;
  assert.equal((await alice.post(`/api/approvals/${stale.id}/browser`, { token: approvalToken(env, 'sub-alice', stale) })).status, 409);
  ok(await alice.post(`/api/approvals/${fresh.id}/browser`, { token: approvalToken(env, 'sub-alice', fresh) }));
  assert.equal(ok(await alice.get('/api/me')).user.balance, 800);
});
