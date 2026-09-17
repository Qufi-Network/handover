import crypto from 'node:crypto';

const LEEWAY = 30;

export class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

export const randomId = (bytes = 16) => crypto.randomBytes(bytes).toString('base64url');

/** Veyns canonical JSON: object keys sorted recursively, arrays keep their order, no whitespace. */
export function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort()
      .map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

/** base64url SHA-256 over the canonical {statement, details}; absent details become null. */
export const actionDigest = (statement, details) =>
  crypto.createHash('sha256')
    .update(canonicalJson({ statement, details: details ?? null }), 'utf8')
    .digest('base64url');

/** True when a ceremony happened after `notBefore` and not in the future. */
export const isFresh = (authTime, notBefore, now) =>
  typeof authTime === 'number' && authTime >= notBefore - LEEWAY && authTime <= now + LEEWAY;

export function createVeyns({ issuer, getClientId, backendSecret, now, fetchImpl }) {
  let keys = null;
  let keysLoadedAt = -Infinity;

  async function loadKeys() {
    let body;
    try {
      const response = await fetchImpl(`${issuer}/jwks.json`, { signal: AbortSignal.timeout(10_000) });
      if (!response.ok) throw new Error(`status ${response.status}`);
      body = await response.json();
    } catch {
      throw new HttpError(502, 'Could not load the Veyns signing keys.');
    }
    keys = new Map();
    for (const key of body.keys || []) {
      if (key.kty !== 'EC' || key.crv !== 'P-256' || !key.kid) continue;
      keys.set(key.kid, crypto.createPublicKey({ key: { kty: 'EC', crv: 'P-256', x: key.x, y: key.y }, format: 'jwk' }));
    }
    keysLoadedAt = now();
  }

  async function signingKey(kid) {
    // Refetch at most once a minute so a rotated key is picked up without letting junk kids hammer the issuer.
    if (!keys || (!keys.has(kid) && now() - keysLoadedAt > 60)) await loadKeys();
    const key = keys.get(kid);
    if (!key) throw new HttpError(401, 'The token was signed with an unknown key.');
    return key;
  }

  /** Verifies an ES256 token from this issuer, for this app, and returns its claims. */
  async function verifyToken(token) {
    const parts = typeof token === 'string' ? token.split('.') : [];
    if (parts.length !== 3) throw new HttpError(400, 'Missing or malformed token.');
    let header, claims;
    try {
      header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
      claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    } catch {
      throw new HttpError(400, 'Missing or malformed token.');
    }
    if (header.alg !== 'ES256') throw new HttpError(401, 'Register this app with ES256 ID tokens.');

    const key = await signingKey(header.kid);
    const signed = crypto.verify('sha256', Buffer.from(`${parts[0]}.${parts[1]}`),
      { key, dsaEncoding: 'ieee-p1363' }, Buffer.from(parts[2], 'base64url'));
    if (!signed) throw new HttpError(401, 'The token signature did not verify.');

    const t = now();
    const problem =
      claims.iss !== issuer ? 'unexpected issuer'
      : claims.aud !== getClientId() ? 'issued for a different app'
      : typeof claims.exp !== 'number' || claims.exp + LEEWAY <= t ? 'expired'
      : typeof claims.sub !== 'string' || !claims.sub ? 'missing subject'
      : claims.veyns_presence !== true ? 'no presence'
      : null;
    if (problem) throw new HttpError(401, `Token rejected: ${problem}.`);
    return claims;
  }

  /** Calls the Veyns backend API with the app's Basic credential. */
  async function backend(pathname, body, extraHeaders = {}) {
    if (!backendSecret) throw new HttpError(400, 'Palm approvals need VEYNS_BACKEND_SECRET in .env.');
    const authorization = 'Basic ' + Buffer.from(`${getClientId()}:${backendSecret}`).toString('base64');
    let response;
    try {
      response = await fetchImpl(issuer + pathname, {
        method: body === undefined ? 'GET' : 'POST',
        headers: { ...extraHeaders, authorization, ...(body === undefined ? {} : { 'content-type': 'application/json' }) },
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: AbortSignal.timeout(10_000),
      });
    } catch {
      throw new HttpError(502, 'Veyns is not reachable right now.');
    }
    const out = await response.json().catch(() => ({}));
    if (response.status === 401) throw new HttpError(502, 'Veyns rejected the backend credential. Check VEYNS_BACKEND_SECRET.');
    if (!response.ok) {
      const status = response.status === 409 ? 409 : response.status >= 500 ? 502 : 400;
      throw new HttpError(status, out.error_description || out.error || `Veyns returned ${response.status}.`);
    }
    return out;
  }

  return {
    verifyToken,
    backend,
    palmEnabled: () => Boolean(backendSecret && getClientId()),
  };
}
