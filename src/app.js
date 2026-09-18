import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { openDb, isUniqueViolation } from './db.js';
import { createVeyns, actionDigest, isFresh, randomId, HttpError } from './veyns.js';

const SESSION_COOKIE = 'handover_sid';
const LOGIN_COOKIE = 'handover_login';
const SESSION_SECONDS = 7 * 24 * 3600;
const LOGIN_SECONDS = 300;
const PALM_REQUEST_SECONDS = 300;
const STANDARD_HOLD_OPTIONS = [3600, 5 * 3600, 10 * 3600, 24 * 3600];

const STATIC_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
};

const TRANSFER_SELECT = `
  SELECT t.*, f.name AS from_name, r.name AS to_name
  FROM transfers t JOIN users f ON f.id = t.from_user JOIN users r ON r.id = t.to_user`;

// Every state change below is a conditional UPDATE whose row count is checked, so two
// instances racing on the same hand-over (accept vs. automatic return, a replayed approval) cannot both win.
const SQL = {
  userBySub: 'SELECT * FROM users WHERE sub = $1',
  userById: 'SELECT * FROM users WHERE id = $1',
  insertUser: 'INSERT INTO users (id, sub, balance, created_at) VALUES ($1, $2, $3, $4) ON CONFLICT (sub) DO NOTHING',
  setName: 'UPDATE users SET name = $1 WHERE id = $2',
  people: 'SELECT id, name FROM users WHERE name IS NOT NULL ORDER BY lower(name) LIMIT 200',
  debit: 'UPDATE users SET balance = balance - $1 WHERE id = $2 AND balance >= $1',
  credit: 'UPDATE users SET balance = balance + $1 WHERE id = $2',

  insertSession: 'INSERT INTO sessions (id_hash, user_id, expires_at) VALUES ($1, $2, $3)',
  sessionUser: 'SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id_hash = $1 AND s.expires_at > $2',
  deleteSession: 'DELETE FROM sessions WHERE id_hash = $1',
  purgeSessions: 'DELETE FROM sessions WHERE expires_at <= $1',
  insertLogin: 'INSERT INTO login_nonces (id, nonce, expires_at) VALUES ($1, $2, $3)',
  takeLogin: 'DELETE FROM login_nonces WHERE id = $1 RETURNING nonce, expires_at',
  purgeLogins: 'DELETE FROM login_nonces WHERE expires_at <= $1',

  transferById: `${TRANSFER_SELECT} WHERE t.id = $1`,
  heldFor: `${TRANSFER_SELECT} WHERE t.status = 'held' AND (t.from_user = $1 OR t.to_user = $1) ORDER BY t.expires_at`,
  closedFor: `${TRANSFER_SELECT} WHERE t.status IN ('accepted', 'declined', 'recalled', 'returned')
              AND (t.from_user = $1 OR t.to_user = $1) ORDER BY t.closed_at DESC LIMIT 30`,
  insertTransfer: `INSERT INTO transfers (id, from_user, to_user, amount, note, hold_seconds, status, created_at)
                   VALUES ($1, $2, $3, $4, $5, $6, 'draft', $7)`,
  discardDrafts: `UPDATE transfers SET status = 'discarded', closed_at = $1 WHERE from_user = $2 AND status = 'draft' RETURNING id`,
  closeTransfer: 'UPDATE transfers SET status = $1, closed_at = $2 WHERE id = $3 AND status = $4',
  // The window is the one the sender chose when the draft (and its signed statement) was made.
  markHeld: `UPDATE transfers SET status = 'held', sent_at = $1::bigint, expires_at = $1::bigint + COALESCE(hold_seconds, $2::int)
             WHERE id = $3 AND status = 'draft' RETURNING amount, from_user`,
  // Closed windows, past the grace period: each row can be returned exactly once, by whichever request gets there first.
  returnExpired: `UPDATE transfers SET status = 'returned', closed_at = $1::bigint
                  WHERE status = 'held' AND expires_at + $2::int <= $1::bigint RETURNING id, amount, from_user`,
  // Lock order everywhere is approvals, then transfers, then users, so concurrent requests cannot deadlock.
  cancelExpiredApprovals: `UPDATE approvals SET status = 'cancelled', closed_at = $1::bigint WHERE status = 'open'
                           AND transfer_id IN (SELECT id FROM transfers WHERE status = 'held' AND expires_at + $2::int <= $1::bigint)
                           RETURNING request_id`,
  cancelDraftApprovals: `UPDATE approvals SET status = 'cancelled', closed_at = $1 WHERE status = 'open'
                         AND transfer_id IN (SELECT id FROM transfers WHERE from_user = $2 AND status = 'draft')
                         RETURNING request_id`,
  markAccepted: `UPDATE transfers SET status = 'accepted', closed_at = $1
                 WHERE id = $2 AND status = 'held' AND expires_at > $3 RETURNING amount, to_user`,

  approvalById: 'SELECT * FROM approvals WHERE id = $1',
  ownApproval: 'SELECT * FROM approvals WHERE id = $1 AND user_id = $2',
  insertApproval: `INSERT INTO approvals (id, transfer_id, kind, user_id, statement, details, digest, nonce, status, created_at)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'open', $9)`,
  cancelOpenApprovals: `UPDATE approvals SET status = 'cancelled', closed_at = $1
                        WHERE transfer_id = $2 AND status = 'open' RETURNING request_id`,
  closeApproval: `UPDATE approvals SET status = $1, error = $2, closed_at = $3 WHERE id = $4 AND status = 'open'`,
  approve: `UPDATE approvals SET status = 'approved', method = $1, proof_id = $2, closed_at = $3 WHERE id = $4 AND status = 'open'`,
  setPalmRequest: `UPDATE approvals SET method = 'palm', request_id = $1, challenge = $2, approval_url = $3
                   WHERE id = $4 AND status = 'open'`,
  setDecision: 'UPDATE approvals SET decision_id = $1 WHERE id = $2',
  markAcked: 'UPDATE approvals SET acked = true WHERE id = $1',
};

const fmt = n => n.toLocaleString('en-US');
const sha256 = value => crypto.createHash('sha256').update(value).digest('base64url');

function humanDuration(seconds) {
  const plural = (n, unit) => `${n} ${unit}${n === 1 ? '' : 's'}`;
  if (seconds % 3600 === 0) return plural(seconds / 3600, 'hour');
  if (seconds % 60 === 0) return plural(seconds / 60, 'minute');
  return plural(seconds, 'second');
}

function parseCookies(header = '') {
  const cookies = {};
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i > 0) cookies[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return cookies;
}

const asObject = value => (value && typeof value === 'object' && !Array.isArray(value) ? value : {});

async function readJson(req) {
  // Vercel's Node runtime may already have parsed the body.
  if ('body' in req) {
    let body;
    try {
      body = req.body;
    } catch {
      throw new HttpError(400, 'Invalid JSON.');
    }
    if (body !== undefined) return asObject(body);
  }
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 32_768) throw new HttpError(413, 'Request too large.');
    chunks.push(chunk);
  }
  if (!chunks.length) return {};
  try {
    return asObject(JSON.parse(Buffer.concat(chunks).toString('utf8')));
  } catch {
    throw new HttpError(400, 'Invalid JSON.');
  }
}

export function createApp(options) {
  const {
    publicOrigin,
    issuer,
    databaseUrl = '',
    dataDir = null,
    publicDir = null,
    backendSecret = '',
    requirePalm = false,
    holdSeconds = 86_400,
    graceSeconds = 300,
    startingCredits = 1000,
    now = () => Math.floor(Date.now() / 1000),
    fetchImpl = globalThis.fetch,
    log = console,
  } = options;

  // The sender picks 1, 5, 10 or 24 hours. HOLD_SECONDS sets the default and, if it is not one of those
  // (say 120 while testing), is offered as an extra choice.
  const holdOptions = [...new Set([...STANDARD_HOLD_OPTIONS, holdSeconds])].sort((a, b) => a - b);

  // Only a local install may save its client ID from the browser. A hosted one reads it from the environment.
  const configFile = dataDir ? path.join(dataDir, 'config.json') : null;
  let clientId = options.clientId || readSavedClientId();

  let dbPromise = null;
  const database = () => {
    if (!databaseUrl && options.requireDatabaseUrl) {
      return Promise.reject(new HttpError(503, 'No database yet: add Postgres to this project (Vercel → Storage), then redeploy.'));
    }
    dbPromise ??= openDb({ url: databaseUrl, dir: dataDir && path.join(dataDir, 'pgdata') })
      .catch(error => {
        dbPromise = null;
        log.error(error);
        throw new HttpError(503, 'The database is not reachable right now.');
      });
    return dbPromise;
  };

  const veyns = createVeyns({ issuer, getClientId: () => clientId, backendSecret, now, fetchImpl });
  const secureCookies = publicOrigin.startsWith('https:');
  const publicHost = new URL(publicOrigin).host;
  const csp = [
    "default-src 'self'",
    `script-src 'self' ${issuer}`,
    `connect-src 'self' ${issuer}`,
    `img-src 'self' data: ${issuer}`,
    "style-src 'self' https://fonts.googleapis.com",
    'font-src https://fonts.gstatic.com',
    "frame-ancestors 'none'",
    "base-uri 'none'",
    "form-action 'self'",
  ].join('; ');

  function readSavedClientId() {
    if (!configFile) return '';
    try {
      return JSON.parse(fs.readFileSync(configFile, 'utf8')).clientId || '';
    } catch {
      return '';
    }
  }

  /* ------------------------------------------------------------- queries */

  async function query(name, ...params) {
    return (await database()).query(SQL[name], params);
  }
  const one = async (name, ...params) => (await query(name, ...params)).rows[0];
  const all = async (name, ...params) => (await query(name, ...params)).rows;

  /** Runs fn(q) in one transaction; q(name, ...params) returns { rows, count }. */
  async function transaction(fn) {
    return (await database()).transaction(raw => fn((name, ...params) => raw(SQL[name], params)));
  }

  /* ---------------------------------------------------------------- views */

  const userView = user => ({ id: user.id, name: user.name, balance: user.balance });

  /** `direction` matters for a hand-over to yourself: it is incoming in one list and outgoing in the other. */
  function transferView(t, me, direction = t.from_user === me.id ? 'out' : 'in') {
    const time = now();
    const outgoing = direction === 'out';
    return {
      id: t.id,
      amount: t.amount,
      note: t.note,
      status: t.status,
      direction,
      self: t.from_user === t.to_user,
      counterparty: outgoing ? t.to_name : t.from_name,
      holdSeconds: t.hold_seconds ?? (t.sent_at == null ? null : t.expires_at - t.sent_at),
      sentAt: t.sent_at,
      expiresAt: t.expires_at,
      // Unaccepted credits go back to the sender once the window and the grace period have passed.
      returnsAt: t.expires_at == null ? null : t.expires_at + graceSeconds,
      closedAt: t.closed_at,
      canAccept: t.status === 'held' && t.to_user === me.id && time < t.expires_at,
      canDecline: t.status === 'held' && t.to_user === me.id,
    };
  }

  const approvalView = (a, remoteStatus = null) => ({
    id: a.id,
    kind: a.kind,
    transferId: a.transfer_id,
    statement: a.statement,
    details: JSON.parse(a.details),
    status: a.status,
    method: a.method,
    error: a.error,
    remoteStatus,
    nonce: a.status === 'open' ? a.nonce : null,
    approvalUrl: a.status === 'open' ? a.approval_url : null,
  });

  /* ------------------------------------------------------------- helpers */

  const requireConfigured = () => {
    if (!clientId) throw new HttpError(409, 'Connect the app to Veyns first.');
  };

  async function requireUser(cookies) {
    const sid = cookies[SESSION_COOKIE];
    const user = sid && await one('sessionUser', sha256(sid), now());
    if (!user) throw new HttpError(401, 'Please sign in.');
    return user;
  }

  async function ownTransfer(id, user) {
    const t = await one('transferById', id);
    if (!t || (t.from_user !== user.id && t.to_user !== user.id)) throw new HttpError(404, 'Hand-over not found.');
    return t;
  }

  async function ownApproval(id, user) {
    const a = await one('ownApproval', id, user.id);
    if (!a) throw new HttpError(404, 'Approval not found.');
    return a;
  }

  /** Best effort: closing our side never waits on Veyns, and a closed Veyns request can no longer be approved. */
  function cancelRemote(rows) {
    for (const row of rows) {
      if (!row.request_id) continue;
      veyns.backend(`/v1/approvals/${encodeURIComponent(row.request_id)}/cancel`, {})
        .catch(error => log.warn(`Could not cancel Veyns request: ${error.message}`));
    }
  }

  const failApproval = async (id, message) => query('closeApproval', 'failed', message, now(), id);

  /**
   * Sends back every hand-over whose accept window (plus grace) has closed: the rule the sender
   * signed. It runs before each signed-in request, so nobody ever sees a balance that still
   * counts an expired hand-over; no scheduler is needed.
   */
  async function returnExpired() {
    const time = now();
    const closed = await transaction(async q => {
      const replaced = (await q('cancelExpiredApprovals', time, graceSeconds)).rows;
      for (const t of (await q('returnExpired', time, graceSeconds)).rows) await q('credit', t.amount, t.from_user);
      return replaced;
    });
    cancelRemote(closed);
  }

  /** The approvals API names people as `pairwise:<client id>:<subject>`, as in the Veyns guide. */
  const approvalSubject = sub => (sub.startsWith('pairwise:') ? sub : `pairwise:${clientId}:${sub}`);

  // Which naming the service actually accepted, remembered per instance so only the first request pays for both.
  let subjectForm = null;

  /**
   * Asks Veyns for a palm request. The guide writes the subject as `pairwise:<client>:<sub>`,
   * but the service has accepted the bare token subject too, so try both rather than guess.
   * Each attempt gets its own idempotency key: the same key with different input is a conflict.
   */
  async function createPalmRequest(a, user) {
    const forms = [
      { name: 'pairwise', subject: approvalSubject(user.sub), key: a.id },
      { name: 'plain', subject: user.sub, key: `${a.id}-plain` },
    ].filter(form => (subjectForm ? form.name === subjectForm : true));
    if (forms.length === 2 && forms[0].subject === forms[1].subject) forms.pop();

    const refusals = [];
    for (const form of forms) {
      try {
        const remote = await veyns.backend('/v1/approvals', {
          subject: form.subject,
          idempotency_key: form.key,
          expires_in: PALM_REQUEST_SECONDS,
          action: { statement: a.statement, details: JSON.parse(a.details) },
        }, { 'idempotency-key': form.key });
        subjectForm = form.name;
        return remote;
      } catch (error) {
        if (error.status !== 400) throw error;
        refusals.push(`${form.name} (${form.subject.length} characters): ${error.message}`);
      }
    }
    subjectForm = null;
    throw new HttpError(400, `Veyns refused the palm request both ways. ${refusals.join(' — ')} `
      + 'Check that this account has its palm scanner connected and is admitted to the palm pilot.');
  }

  /** Creates the exact action a person will approve, replacing any earlier open approval for the same hand-over. */
  async function newApproval(transfer, user, kind) {
    // The return rule is part of what the sender signs: the window is in the statement and the digest.
    const window = transfer.hold_seconds ?? holdSeconds;
    const statement = kind === 'send'
      ? `Hand over ${fmt(transfer.amount)} credits to ${transfer.to_name}, returned to you if not accepted within ${humanDuration(window)}`
      : `Accept ${fmt(transfer.amount)} credits from ${transfer.from_name}`;
    const details = {
      transfer: transfer.id,
      amount: transfer.amount,
      unit: 'credits',
      ...(kind === 'send'
        ? { to: transfer.to_name, accept_within: humanDuration(window), accept_within_seconds: window, if_not_accepted: 'returned to sender' }
        : { from: transfer.from_name, accept_by: new Date(transfer.expires_at * 1000).toISOString() }),
      ...(transfer.note ? { note: transfer.note } : {}),
    };
    const id = randomId(16);
    const time = now();
    const replaced = await transaction(async q => {
      const closed = (await q('cancelOpenApprovals', time, transfer.id)).rows;
      await q('insertApproval', id, transfer.id, kind, user.id, statement, JSON.stringify(details),
        actionDigest(statement, details), randomId(32), time);
      return closed;
    });
    cancelRemote(replaced);
    return one('approvalById', id);
  }

  /**
   * Executes the business operation for a verified approval. The approval claim, the
   * balance change and the transfer state change commit together or not at all.
   */
  async function settle(a, user, method, proof, authTime) {
    const time = now();
    try {
      await transaction(async q => {
        if ((await q('approve', method, proof, time, a.id)).count !== 1) {
          throw new HttpError(409, 'This approval was already used.');
        }
        if (a.kind === 'send') {
          const held = (await q('markHeld', time, holdSeconds, a.transfer_id)).rows[0];
          if (!held) throw new HttpError(409, 'This hand-over was already sent or discarded.');
          if ((await q('debit', held.amount, held.from_user)).count !== 1) {
            throw new HttpError(409, 'You no longer have enough credits for this.');
          }
        } else {
          // Judge the deadline by when the person approved, so a ceremony finished in time still lands.
          const accepted = (await q('markAccepted', time, a.transfer_id, authTime)).rows[0];
          if (!accepted) {
            const t = (await q('transferById', a.transfer_id)).rows[0];
            throw new HttpError(409, t.status === 'held'
              ? 'The window closed before you approved.'
              : 'This hand-over is no longer waiting for you.');
          }
          await q('credit', accepted.amount, accepted.to_user);
        }
      });
    } catch (caught) {
      const error = isUniqueViolation(caught) ? new HttpError(409, 'This approval proof was already used.') : caught;
      if (error instanceof HttpError) await failApproval(a.id, error.message);
      throw error;
    }
    return {
      approval: approvalView(await one('approvalById', a.id)),
      transfer: transferView(await one('transferById', a.transfer_id), user),
    };
  }

  async function acknowledge(a) {
    try {
      await veyns.backend(`/v1/approvals/${encodeURIComponent(a.request_id)}/ack`,
        { decision_id: a.decision_id, operation_id: a.id });
      await query('markAcked', a.id);
    } catch (error) {
      log.warn(`Veyns acknowledgement will be retried: ${error.message}`);
    }
  }

  /* ------------------------------------------------------------ handlers */

  function getConfig() {
    return {
      configured: Boolean(clientId),
      canSaveClientId: Boolean(configFile),
      clientId,
      issuer,
      publicOrigin,
      redirectUri: `${publicOrigin}/`,
      palmEnabled: veyns.palmEnabled(),
      requirePalm,
      holdSeconds,
      holdOptions: holdOptions.map(seconds => ({ seconds, label: humanDuration(seconds) })),
      graceSeconds,
    };
  }

  function saveSetup({ body }) {
    if (!configFile) throw new HttpError(403, 'Set VEYNS_CLIENT_ID in the hosting environment, then redeploy.');
    if (clientId) throw new HttpError(409, 'This app already has a client ID. Edit .env or data/config.json to change it.');
    const value = String(body.clientId ?? '').trim();
    if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{2,127}$/.test(value)) throw new HttpError(400, 'That does not look like a Veyns client ID.');
    fs.writeFileSync(configFile, `${JSON.stringify({ clientId: value }, null, 2)}\n`);
    clientId = value;
    return getConfig();
  }

  async function loginStart({ setCookie }) {
    requireConfigured();
    const time = now();
    const id = randomId(24);
    const nonce = randomId(32);
    await query('purgeLogins', time);
    await query('insertLogin', id, nonce, time + LOGIN_SECONDS);
    setCookie(LOGIN_COOKIE, id, LOGIN_SECONDS);
    return { nonce };
  }

  async function loginFinish({ body, cookies, setCookie }) {
    requireConfigured();
    const pending = cookies[LOGIN_COOKIE] ? await one('takeLogin', cookies[LOGIN_COOKIE]) : undefined;
    setCookie(LOGIN_COOKIE, '', 0);
    const time = now();
    if (!pending || pending.expires_at <= time) throw new HttpError(401, 'That sign-in expired. Please try again.');

    const claims = await veyns.verifyToken(body.token);
    if (claims.nonce !== pending.nonce) throw new HttpError(401, 'That sign-in did not start in this browser. Please try again.');
    if (claims.veyns_intent !== 'login') throw new HttpError(401, 'That token is not a sign-in.');
    if (!isFresh(claims.auth_time, time - LOGIN_SECONDS, time)) throw new HttpError(401, 'That sign-in is too old. Please try again.');
    if (requirePalm && !(claims.amr || []).includes('veyns:palm')) throw new HttpError(401, 'This app requires palm sign-in.');

    await query('insertUser', randomId(12), claims.sub, startingCredits, time);
    const user = await one('userBySub', claims.sub);
    const sid = randomId(32);
    await query('purgeSessions', time);
    await query('insertSession', sha256(sid), user.id, time + SESSION_SECONDS);
    setCookie(SESSION_COOKIE, sid, SESSION_SECONDS);
    return { user: userView(user) };
  }

  async function logout({ cookies, setCookie }) {
    if (cookies[SESSION_COOKIE]) await query('deleteSession', sha256(cookies[SESSION_COOKIE]));
    setCookie(SESSION_COOKIE, '', 0);
    return { ok: true };
  }

  async function me({ user }) {
    const [held, people, closed] = await Promise.all([all('heldFor', user.id), all('people'), all('closedFor', user.id)]);
    return {
      now: now(),
      user: userView(user),
      people: people.map(p => ({ id: p.id, name: p.name, you: p.id === user.id })),
      // A hand-over to yourself is shown once, where it can be acted on: waiting for you to accept.
      incoming: held.filter(t => t.to_user === user.id).map(t => transferView(t, user, 'in')),
      outgoing: held.filter(t => t.from_user === user.id && t.to_user !== user.id).map(t => transferView(t, user, 'out')),
      history: closed.map(t => transferView(t, user)),
    };
  }

  async function saveProfile({ user, body }) {
    const name = String(body.name ?? '').replace(/\s+/g, ' ').trim();
    // eslint-disable-next-line no-control-regex
    if (name.length < 1 || name.length > 40 || /[\u0000-\u001f\u007f]/.test(name)) {
      throw new HttpError(400, 'Use a name between 1 and 40 characters.');
    }
    await query('setName', name, user.id);
    return { user: userView({ ...user, name }) };
  }

  async function createTransfer({ user, body }) {
    const to = await one('userById', String(body.to ?? ''));
    if (!to || !to.name) throw new HttpError(400, 'Choose who to hand credits to.');
    const amount = Number(body.amount);
    if (!Number.isInteger(amount) || amount < 1 || amount > 1_000_000) throw new HttpError(400, 'Enter a whole number of credits.');
    if (amount > user.balance) throw new HttpError(409, `You have ${fmt(user.balance)} credits.`);
    const note = String(body.note ?? '').replace(/\s+/g, ' ').trim();
    if (note.length > 80) throw new HttpError(400, 'Keep the note under 80 characters.');
    const window = body.holdSeconds === undefined ? holdSeconds : Number(body.holdSeconds);
    if (!holdOptions.includes(window)) {
      throw new HttpError(400, `Choose how long they have to accept: ${holdOptions.map(humanDuration).join(', ')}.`);
    }

    const id = randomId(12);
    const time = now();
    const replaced = await transaction(async q => {
      const closed = (await q('cancelDraftApprovals', time, user.id)).rows;
      await q('discardDrafts', time, user.id);
      await q('insertTransfer', id, user.id, to.id, amount, note, window, time);
      return closed;
    });
    cancelRemote(replaced);
    const transfer = await one('transferById', id);
    return { transfer: transferView(transfer, user), approval: approvalView(await newApproval(transfer, user, 'send')) };
  }

  async function transferAction({ user, params: [id, action] }) {
    const t = await ownTransfer(id, user);
    const time = now();

    if (action === 'approval') {
      if (t.status === 'draft' && t.from_user === user.id) return { approval: approvalView(await newApproval(t, user, 'send')) };
      if (t.status === 'held' && t.to_user === user.id) {
        if (time >= t.expires_at) throw new HttpError(409, 'The window to accept this has closed.');
        return { approval: approvalView(await newApproval(t, user, 'accept')) };
      }
      throw new HttpError(409, 'There is nothing to approve on this hand-over.');
    }

    const close = (from, to, refund) => transaction(async q => {
      const replaced = (await q('cancelOpenApprovals', time, t.id)).rows;
      if ((await q('closeTransfer', to, time, t.id, from)).count !== 1) throw new HttpError(409, 'This hand-over has already been settled.');
      if (refund) await q('credit', t.amount, t.from_user);
      return replaced;
    });

    let replaced;
    if (action === 'discard') {
      if (t.status !== 'draft' || t.from_user !== user.id) throw new HttpError(409, 'Only an unsent draft can be discarded.');
      replaced = await close('draft', 'discarded', false);
    } else {
      if (t.status !== 'held' || t.to_user !== user.id) throw new HttpError(409, 'Only a hand-over waiting for you can be declined.');
      replaced = await close('held', 'declined', true);
    }
    cancelRemote(replaced);
    return { transfer: transferView(await one('transferById', t.id), user) };
  }

  async function approvalAction({ user, params: [id, action], body }) {
    const a = await ownApproval(id, user);

    if (action === 'cancel') {
      if (a.status === 'open') {
        await query('closeApproval', 'cancelled', null, now(), a.id);
        cancelRemote([a]);
      }
      return { approval: approvalView(await one('approvalById', a.id)) };
    }
    if (a.status !== 'open') throw new HttpError(409, 'This approval is already closed.');

    if (action === 'palm') {
      if (!veyns.palmEnabled()) throw new HttpError(400, 'Palm approvals are not set up. Add VEYNS_BACKEND_SECRET.');
      if (a.request_id) return { approval: approvalView(a) };
      const remote = await createPalmRequest(a, user);
      if (remote.action?.digest !== a.digest) {
        await failApproval(a.id, 'Veyns described a different action.');
        cancelRemote([remote]);
        throw new HttpError(502, 'Veyns described a different action. Nothing was approved.');
      }
      await query('setPalmRequest', remote.request_id, remote.challenge, remote.approval_url, a.id);
      return { approval: approvalView(await one('approvalById', a.id)) };
    }

    // Browser approval: the SDK already checked the token, but the browser is not trusted.
    if (requirePalm) throw new HttpError(403, 'This app requires palm approval.');
    const claims = await veyns.verifyToken(body.token);
    const time = now();
    const problem =
      claims.sub !== user.sub ? 'signed by a different account'
      : claims.nonce !== a.nonce ? 'made for a different request'
      : claims.veyns_intent !== 'action' ? 'not an approval'
      : claims.veyns_action?.digest !== a.digest ? 'not bound to this exact action'
      : !isFresh(claims.auth_time, a.created_at, time) ? 'not fresh'
      : null;
    if (problem) throw new HttpError(401, `Approval rejected: ${problem}.`);

    const proof = claims.jti ? `jti:${claims.jti}` : `token:${sha256(body.token)}`;
    const result = await settle(a, user, 'browser', proof, claims.auth_time);
    if (a.request_id) cancelRemote([a]);
    if (claims.jti && backendSecret) {
      await veyns.backend('/v1/actions/consume', { jti: claims.jti, action_digest: a.digest, operation_id: a.id })
        .catch(error => log.warn(`Could not record the action receipt with Veyns: ${error.message}`));
    }
    return result;
  }

  async function readApproval({ user, params: [id] }) {
    let a = await ownApproval(id, user);
    let remoteStatus = null;

    if (a.status === 'open' && a.request_id) {
      const remote = await veyns.backend(`/v1/approvals/${encodeURIComponent(a.request_id)}`);
      remoteStatus = remote.status;
      if (remote.status === 'approved') {
        await settlePalm(a, user, remote);
      } else if (!['pending', 'verifying'].includes(remote.status)) {
        await failApproval(a.id, `The palm approval was ${remote.status}.`);
      }
      a = await one('approvalById', a.id);
    }
    if (a.decision_id && !a.acked) await acknowledge(a);

    return {
      approval: approvalView(await one('approvalById', a.id), remoteStatus),
      transfer: transferView(await one('transferById', a.transfer_id), user),
    };
  }

  async function settlePalm(a, user, remote) {
    const fail = reason => failApproval(a.id, `Palm decision rejected: ${reason}.`);
    let claims;
    try {
      claims = await veyns.verifyToken(remote.decision);
    } catch (error) {
      if (error.status === 400 || error.status === 401) return fail(error.message.replace(/\.$/, ''));
      throw error; // Keys unreachable: leave the approval open and try again on the next poll.
    }
    const problem =
      claims.sub !== user.sub && claims.sub !== approvalSubject(user.sub) ? 'different account'
      : claims.request_id !== a.request_id ? 'different request'
      : claims.request_nonce !== a.challenge ? 'different challenge'
      : claims.veyns_intent !== 'action' ? 'not an approval'
      : !(claims.amr || []).includes('veyns:palm') ? 'not a palm scan'
      : claims.veyns_action?.digest !== a.digest ? 'different action'
      : !isFresh(claims.auth_time, a.created_at, now()) ? 'not fresh'
      : typeof remote.decision_id !== 'string' ? 'missing decision id'
      : null;
    if (problem) return fail(problem);

    await query('setDecision', remote.decision_id, a.id);
    try {
      await settle(a, user, 'palm', `decision:${remote.decision_id}`, claims.auth_time);
    } catch (error) {
      if (!(error instanceof HttpError)) throw error; // Business refusals are already recorded on the approval.
    }
  }

  /* -------------------------------------------------------------- server */

  const routes = [
    { method: 'GET', path: '/api/config', handler: getConfig },
    { method: 'POST', path: '/api/setup', handler: saveSetup },
    { method: 'POST', path: '/api/login/start', handler: loginStart },
    { method: 'POST', path: '/api/login/finish', handler: loginFinish },
    { method: 'POST', path: '/api/logout', handler: logout },
    { method: 'GET', path: '/api/me', handler: me, auth: true },
    { method: 'POST', path: '/api/profile', handler: saveProfile, auth: true },
    { method: 'POST', path: '/api/transfers', handler: createTransfer, auth: true },
    { method: 'POST', path: /^\/api\/transfers\/([\w-]{8,64})\/(approval|discard|decline)$/, handler: transferAction, auth: true },
    { method: 'GET', path: /^\/api\/approvals\/([\w-]{8,64})$/, handler: readApproval, auth: true },
    { method: 'POST', path: /^\/api\/approvals\/([\w-]{8,64})\/(browser|palm|cancel)$/, handler: approvalAction, auth: true },
  ];

  function matchRoute(method, pathname) {
    for (const route of routes) {
      if (route.method !== method) continue;
      if (typeof route.path === 'string') {
        if (route.path === pathname) return { ...route, params: [] };
      } else {
        const m = pathname.match(route.path);
        if (m) return { ...route, params: m.slice(1) };
      }
    }
    return null;
  }

  const cookieString = (name, value, maxAge) =>
    `${name}=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${secureCookies ? '; Secure' : ''}`;

  function sendJson(res, status, body, cookies = []) {
    res.writeHead(status, {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
      ...(cookies.length ? { 'set-cookie': cookies } : {}),
    });
    res.end(JSON.stringify(body));
  }

  function serveStatic(req, res, url) {
    if (!publicDir) return sendJson(res, 404, { error: 'Not found.' });
    if (req.method !== 'GET' && req.method !== 'HEAD') return sendJson(res, 405, { error: 'Method not allowed.' });
    // Veyns only accepts the exact registered origin, so send 127.0.0.1 and friends to it.
    if (req.headers.host && req.headers.host !== publicHost) {
      res.writeHead(302, { location: publicOrigin + url.pathname + url.search });
      return res.end();
    }
    let file;
    try {
      const root = path.resolve(publicDir);
      file = path.resolve(root, url.pathname === '/' ? 'index.html' : decodeURIComponent(url.pathname.slice(1)));
      if (!file.startsWith(root + path.sep)) throw new Error('outside public dir');
    } catch {
      res.writeHead(404, { 'content-type': 'text/plain' });
      return res.end('Not found');
    }
    fs.readFile(file, (error, data) => {
      if (error) {
        res.writeHead(404, { 'content-type': 'text/plain' });
        return res.end('Not found');
      }
      const type = STATIC_TYPES[path.extname(file)] || 'application/octet-stream';
      res.writeHead(200, {
        'content-type': type,
        'cache-control': 'no-cache',
        'x-content-type-options': 'nosniff',
        'referrer-policy': 'no-referrer',
        ...(type.startsWith('text/html') ? { 'content-security-policy': csp } : {}),
      });
      res.end(req.method === 'HEAD' ? undefined : data);
    });
  }

  async function handle(req, res) {
    const url = new URL(req.url, publicOrigin);
    if (!url.pathname.startsWith('/api/')) return serveStatic(req, res, url);

    const outCookies = [];
    try {
      const route = matchRoute(req.method, url.pathname);
      if (!route) throw new HttpError(404, 'Not found.');
      if (req.method !== 'GET' && req.headers.origin !== publicOrigin) {
        throw new HttpError(403, `Open the app at ${publicOrigin}.`);
      }
      const cookies = parseCookies(req.headers.cookie);
      if (route.auth && cookies[SESSION_COOKIE]) await returnExpired();
      const ctx = {
        params: route.params,
        cookies,
        body: req.method === 'POST' ? await readJson(req) : {},
        setCookie: (name, value, maxAge) => outCookies.push(cookieString(name, value, maxAge)),
        user: route.auth ? await requireUser(cookies) : null,
      };
      sendJson(res, 200, await route.handler(ctx), outCookies);
    } catch (error) {
      const status = error instanceof HttpError ? error.status : 500;
      if (status === 500) log.error(error);
      sendJson(res, status, { error: status === 500 ? 'Something went wrong on the server.' : error.message }, outCookies);
    }
  }

  async function safeHandle(req, res) {
    try {
      await handle(req, res);
    } catch (error) {
      log.error(error);
      if (!res.headersSent) sendJson(res, 500, { error: 'Something went wrong on the server.' });
    }
  }

  const server = http.createServer(safeHandle);

  return {
    server,
    handle: safeHandle,
    async close() {
      await new Promise(resolve => {
        server.close(resolve);
        server.closeAllConnections();
      });
      if (dbPromise) await (await dbPromise.catch(() => null))?.close();
    },
  };
}
