const $ = id => document.getElementById(id);

const VIEWS = ['loading', 'setup', 'signin', 'name', 'main'];
const state = { config: null, me: null, skew: 0, loginNonce: null, peopleKey: '' };
let active = null; // the approval currently shown in the dialog

/* ------------------------------------------------------------ helpers */

async function api(path, body) {
  const response = await fetch(path, {
    method: body === undefined ? 'GET' : 'POST',
    headers: body === undefined ? {} : { 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const out = await response.json().catch(() => ({}));
  if (!response.ok) throw Object.assign(new Error(out.error || 'Something went wrong.'), { status: response.status });
  return out;
}

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value == null || value === false) continue;
    if (key === 'class') node.className = value;
    else if (key.startsWith('on')) node.addEventListener(key.slice(2), value);
    else node.setAttribute(key, value);
  }
  node.append(...children.flat().filter(child => child != null && child !== false));
  return node;
}

const button = (label, className, onClick) => el('button', { type: 'button', class: className, onclick: onClick }, label);
const fmt = n => Number(n).toLocaleString('en-US');
const clock = () => Math.floor(Date.now() / 1000) + state.skew;
const wait = ms => new Promise(resolve => setTimeout(resolve, ms));

function duration(seconds) {
  const s = Math.max(0, Math.round(seconds));
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m`;
  return `${Math.floor(m / 60)}h ${String(m % 60).padStart(2, '0')}m`;
}

function holdText(seconds) {
  const plural = (n, unit) => `${n} ${unit}${n === 1 ? '' : 's'}`;
  if (seconds % 3600 === 0) return plural(seconds / 3600, 'hour');
  if (seconds % 60 === 0) return plural(seconds / 60, 'minute');
  return plural(seconds, 'second');
}

function friendly(error) {
  if (error?.code === 'popup_blocked') return 'Your browser blocked the Veyns window. Allow pop-ups for this site, or approve with palm.';
  // Veyns answers an unregistered origin with an HTML page, which the SDK fails to parse as JSON.
  if (error instanceof SyntaxError) return `Veyns refused this site. Register ${location.origin} exactly as a website origin in the Veyns console.`;
  return error?.message || 'Something went wrong.';
}

let toastTimer;
function toast(message) {
  const node = $('toast');
  node.textContent = message;
  node.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { node.hidden = true; }, 5000);
}

function show(view) {
  for (const name of VIEWS) $(`view-${name}`).hidden = name !== view;
  $('who').hidden = view !== 'main' && view !== 'name';
}

let sdkPromise = null;
function loadSdk() {
  sdkPromise ??= new Promise((resolve, reject) => {
    const script = document.createElement('script');
    script.src = `${state.config.issuer}/veyns.js`;
    script.onload = () => (window.veyns ? resolve(window.veyns) : reject(new Error('Veyns did not load.')));
    script.onerror = () => {
      sdkPromise = null;
      script.remove();
      reject(new Error('Could not reach Veyns. Check your connection and try again.'));
    };
    document.head.append(script);
  });
  return sdkPromise;
}

/* --------------------------------------------------------------- boot */

async function boot() {
  show('loading');
  $('loading-text').textContent = 'Loading…';
  $('retry').hidden = true;
  try {
    state.config = await api('/api/config');
    document.querySelectorAll('[data-hold]').forEach(node => { node.textContent = holdText(state.config.holdSeconds); });
    if (!state.config.configured) return showSetup();
    loadSdk().catch(() => {});
    let redirectError = '';
    try {
      await finishRedirectSignIn();
    } catch (error) {
      redirectError = friendly(error);
    }
    await refresh();
    if (redirectError) $('signin-error').textContent = redirectError;
  } catch (error) {
    $('loading-text').textContent = friendly(error);
    $('retry').hidden = false;
  }
}

async function refresh() {
  try {
    state.me = await api('/api/me');
  } catch (error) {
    if (error.status === 401) {
      state.me = null;
      return showSignin();
    }
    throw error;
  }
  state.skew = state.me.now - Math.floor(Date.now() / 1000);
  $('who-name').textContent = state.me.user.name || '';
  if (!state.me.user.name) {
    show('name');
    $('name').focus();
    return;
  }
  renderMain();
  if ($('view-main').hidden) show('main');
}

/* -------------------------------------------------------------- setup */

function showSetup() {
  $('console-link').href = `${state.config.issuer}/console`;
  $('setup-origin').textContent = state.config.publicOrigin;
  $('setup-redirect').textContent = state.config.redirectUri;
  // A hosted copy never takes its client ID from a visitor's browser.
  const local = state.config.canSaveClientId;
  $('setup-paste').hidden = $('setup-form').hidden = !local;
  $('setup-env').hidden = local;
  show('setup');
}

document.querySelectorAll('[data-copy]').forEach(copy => {
  copy.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText($(copy.dataset.copy).textContent);
      copy.textContent = 'Copied';
      setTimeout(() => { copy.textContent = 'Copy'; }, 1500);
    } catch {
      copy.textContent = 'Select it';
    }
  });
});

$('setup-form').addEventListener('submit', async event => {
  event.preventDefault();
  $('setup-error').textContent = '';
  try {
    await api('/api/setup', { clientId: $('client-id').value });
    await boot();
  } catch (error) {
    $('setup-error').textContent = friendly(error);
  }
});

/* ------------------------------------------------------------ sign-in */

async function showSignin() {
  show('signin');
  // When palm is required, palm is the only way in.
  $('signin-browser').hidden = state.config.requirePalm;
  $('signin-palm').className = `btn ${state.config.requirePalm ? 'ink' : 'ghost'} wide`;
  $('signin-browser').disabled = $('signin-palm').disabled = true;
  try {
    // Both must be ready before the click: the Veyns window has to open straight from the gesture.
    const [{ nonce }] = await Promise.all([api('/api/login/start', {}), loadSdk()]);
    state.loginNonce = nonce;
    $('signin-browser').disabled = $('signin-palm').disabled = false;
  } catch (error) {
    $('signin-error').textContent = friendly(error);
  }
}

async function signIn(method) {
  const nonce = state.loginNonce;
  if (!nonce || !window.veyns) return;
  state.loginNonce = null;
  $('signin-error').textContent = '';
  $('signin-browser').disabled = $('signin-palm').disabled = true;
  try {
    const { token } = await window.veyns.signin({
      clientId: state.config.clientId,
      nonce,
      ...(method === 'palm' ? { method: 'palm' } : {}),
    });
    await api('/api/login/finish', { token });
    await refresh();
  } catch (error) {
    if (error.code === 'popup_blocked') {
      // Phones' in-app browsers and strict pop-up settings: run the same sign-in in this tab instead.
      try {
        $('signin-error').textContent = 'Opening Veyns in this tab…';
        await signInWithRedirect(method, nonce);
        return;
      } catch (redirectError) {
        $('signin-error').textContent = friendly(redirectError);
      }
    } else if (error.code !== 'cancelled') {
      $('signin-error').textContent = friendly(error);
    }
    await showSignin();
  }
}

/* ------------------------------------------- sign-in without a pop-up */

const REDIRECT_KEY = 'handover.veyns-redirect';

function randomToken(bytes) {
  const buffer = crypto.getRandomValues(new Uint8Array(bytes));
  return btoa(String.fromCharCode(...buffer)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function sha256Base64Url(text) {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text)));
  return btoa(String.fromCharCode(...digest)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * The same authorization code + PKCE flow veyns.js runs in its pop-up, with response_mode=query:
 * Veyns sends the whole tab back to the registered redirect URI. The server nonce (bound to this
 * browser by cookie) is unchanged, so /api/login/finish checks the result exactly as before.
 */
async function signInWithRedirect(method, nonce) {
  const { issuer, clientId, redirectUri } = state.config;
  const verifier = randomToken(48);
  const flowState = randomToken(16);
  try {
    sessionStorage.setItem(REDIRECT_KEY, JSON.stringify({ state: flowState, verifier }));
  } catch {
    throw new Error('This browser blocks both pop-ups and storage. Open the site in Chrome, Edge or Safari.');
  }
  const response = await fetch(`${issuer}/v1/authorize/prepare`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      response_type: 'code', response_mode: 'query', client_id: clientId, redirect_uri: redirectUri,
      scope: 'openid login', intent: 'login', state: flowState, nonce,
      code_challenge: await sha256Base64Url(verifier), code_challenge_method: 'S256',
      ...(method === 'palm' ? { required_method: 'palm' } : {}),
    }),
  });
  const prepared = await response.json();
  if (!response.ok) throw new Error(prepared.error_description || 'Veyns could not start sign-in.');
  const target = new URL(prepared.authorization_url);
  if (target.origin !== new URL(issuer).origin || target.pathname !== '/authorize') throw new Error('Veyns returned an unexpected sign-in address.');
  location.assign(target.href);
}

/** On the way back from Veyns: exchange the code for an ID token and hand it to the server. */
async function finishRedirectSignIn() {
  const params = new URLSearchParams(location.search);
  if (!params.has('state') || !(params.has('code') || params.has('error'))) return;
  history.replaceState(null, '', location.pathname); // never leave the code in the address bar or history

  let saved = null;
  try {
    saved = JSON.parse(sessionStorage.getItem(REDIRECT_KEY));
    sessionStorage.removeItem(REDIRECT_KEY);
  } catch {
    // Handled below.
  }
  if (!saved || saved.state !== params.get('state')) throw new Error('That sign-in did not start in this tab. Please try again.');
  if (params.has('error')) {
    throw new Error(params.get('error') === 'access_denied' ? 'Sign-in was cancelled.' : params.get('error_description') || 'Veyns could not sign you in.');
  }

  const { issuer, clientId, redirectUri } = state.config;
  const discovery = await (await fetch(`${issuer}/.well-known/openid-configuration`)).json();
  if (new URL(discovery.token_endpoint).origin !== new URL(issuer).origin) throw new Error('Veyns returned an unexpected token address.');
  const response = await fetch(discovery.token_endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code', code: params.get('code'), client_id: clientId,
      redirect_uri: redirectUri, code_verifier: saved.verifier,
    }),
  });
  const tokens = await response.json();
  if (!response.ok) throw new Error(tokens.error_description || 'Veyns could not finish sign-in. Please try again.');
  await api('/api/login/finish', { token: tokens.id_token });
}

$('signin-browser').addEventListener('click', () => signIn('browser'));
$('signin-palm').addEventListener('click', () => signIn('palm'));

$('signout').addEventListener('click', async () => {
  await api('/api/logout', {}).catch(() => {});
  state.me = null;
  state.peopleKey = '';
  $('signin-error').textContent = '';
  await showSignin();
});

$('name-form').addEventListener('submit', async event => {
  event.preventDefault();
  $('name-error').textContent = '';
  try {
    await api('/api/profile', { name: $('name').value });
    await refresh();
  } catch (error) {
    $('name-error').textContent = friendly(error);
  }
});

/* --------------------------------------------------------------- main */

function renderMain() {
  const { user, people, incoming, outgoing, history } = state.me;
  $('balance').textContent = fmt(user.balance);
  const out = outgoing.reduce((sum, t) => sum + t.amount, 0);
  $('held-summary').textContent = out ? `${fmt(out)} more waiting in other hands` : 'Everything you hold is here.';

  // Rebuild the recipient list only when it changes, so a refresh never yanks an open menu.
  const peopleKey = JSON.stringify(people);
  if (peopleKey !== state.peopleKey) {
    state.peopleKey = peopleKey;
    const select = $('send-to');
    const current = select.value;
    select.replaceChildren(
      el('option', { value: '' }, 'Choose someone'),
      ...people.map(p => el('option', { value: p.id }, p.you ? `${p.name} (you)` : p.name)),
    );
    select.value = people.some(p => p.id === current) ? current : '';
  }
  $('send-amount').max = String(user.balance);

  renderTickets($('incoming'), incoming, 'Nothing is waiting for you.');
  renderTickets($('outgoing'), outgoing, 'Nothing is out right now.');
  renderHistory(history);
}

function renderTickets(container, items, emptyText) {
  container.replaceChildren(...(items.length ? items.map(ticket) : [el('p', { class: 'empty' }, emptyText)]));
}

function ticket(t) {
  const now = clock();
  const left = t.expiresAt - now;
  const incoming = t.direction === 'in';
  const actions = el('div', { class: 'ticket-actions' });

  if (incoming) {
    if (left > 0) actions.append(button('Accept', 'btn accent small', () => accept(t)));
    actions.append(button('Decline', 'btn ghost small', () => decline(t)));
  } else if (now >= t.recallAt) {
    actions.append(button('Recall', 'btn ink small', () => recall(t)));
  } else {
    actions.append(el('span', { class: 'quiet' }, `Recall opens in ${duration(t.recallAt - now)}`));
  }

  return el('article', { class: `ticket ${incoming ? 'in' : 'out'}` },
    el('div', { class: 'ticket-amount' },
      el('span', { class: 'num' }, fmt(t.amount)),
      el('span', { class: 'unit' }, 'credits')),
    el('div', { class: 'ticket-body' },
      el('p', { class: 'ticket-who' }, incoming ? `From ${t.counterparty}` : `To ${t.counterparty}`),
      t.note ? el('p', { class: 'ticket-note' }, `“${t.note}”`) : null,
      actions),
    ring(left / state.config.holdSeconds, left > 0 ? duration(left) : 'Closed', left > 0 ? 'left' : null));
}

function ring(fraction, label, sub) {
  const NS = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(NS, 'svg');
  svg.setAttribute('viewBox', '0 0 64 64');
  svg.setAttribute('aria-hidden', 'true');
  const circumference = 2 * Math.PI * 28;
  for (const name of ['ring-track', 'ring-arc']) {
    const circle = document.createElementNS(NS, 'circle');
    circle.setAttribute('class', name);
    circle.setAttribute('cx', '32');
    circle.setAttribute('cy', '32');
    circle.setAttribute('r', '28');
    if (name === 'ring-arc') {
      const filled = circumference * Math.min(1, Math.max(0, fraction));
      circle.setAttribute('stroke-dasharray', `${filled} ${circumference}`);
      circle.setAttribute('transform', 'rotate(-90 32 32)');
      if (filled === 0) circle.setAttribute('stroke-opacity', '0');
    }
    svg.append(circle);
  }
  return el('div', { class: 'ring' }, svg, el('span', { class: 'ring-label' }, label, sub ? el('small', {}, sub) : null));
}

function renderHistory(items) {
  const list = $('history');
  if (!items.length) {
    list.replaceChildren(el('li', { class: 'empty' }, 'Settled hand-overs show up here.'));
    return;
  }
  list.replaceChildren(...items.map(t => {
    const incoming = t.direction === 'in';
    const what = {
      accepted: incoming ? `Received from ${t.counterparty}` : `Handed to ${t.counterparty}`,
      declined: incoming ? `You declined ${t.counterparty}` : `Declined by ${t.counterparty}`,
      recalled: incoming ? `Recalled by ${t.counterparty}` : `Recalled from ${t.counterparty}`,
    }[t.status];
    const accepted = t.status === 'accepted';
    const when = new Date(t.closedAt * 1000).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
    return el('li', {},
      el('time', { datetime: new Date(t.closedAt * 1000).toISOString() }, when),
      el('span', { class: 'what' }, what, t.note ? el('em', {}, ` · “${t.note}”`) : null),
      el('span', { class: 'leader', 'aria-hidden': 'true' }),
      el('span', { class: `amt ${accepted ? (incoming ? 'plus' : '') : 'void'}` },
        accepted ? `${incoming ? '+' : '−'}${fmt(t.amount)}` : fmt(t.amount)));
  }));
}

$('send-form').addEventListener('submit', async event => {
  event.preventDefault();
  $('send-error').textContent = '';
  const submit = event.submitter;
  if (submit) submit.disabled = true;
  try {
    const { approval } = await api('/api/transfers', {
      to: $('send-to').value,
      amount: Number($('send-amount').value),
      note: $('send-note').value,
    });
    openApproval(approval, { discardOnCancel: true });
  } catch (error) {
    $('send-error').textContent = friendly(error);
  } finally {
    if (submit) submit.disabled = false;
  }
});

async function accept(t) {
  try {
    const { approval } = await api(`/api/transfers/${t.id}/approval`, {});
    openApproval(approval);
  } catch (error) {
    toast(friendly(error));
    refresh().catch(() => {});
  }
}

async function decline(t) {
  if (!confirm(`Decline ${fmt(t.amount)} credits from ${t.counterparty}? They go straight back.`)) return;
  try {
    await api(`/api/transfers/${t.id}/decline`, {});
    toast(`Declined. ${t.counterparty} has the credits back.`);
  } catch (error) {
    toast(friendly(error));
  }
  refresh().catch(() => {});
}

async function recall(t) {
  try {
    await api(`/api/transfers/${t.id}/recall`, {});
    toast(`${fmt(t.amount)} credits are back with you.`);
  } catch (error) {
    toast(friendly(error));
  }
  refresh().catch(() => {});
}

/* ----------------------------------------------------------- approval */

const DETAIL_LABELS = { amount: 'Amount', to: 'To', from: 'From', accept_within: 'Accept within', note: 'Note', transfer: 'Reference' };

/** Every signed detail is shown; known ones first, the amount together with its unit. */
function detailRows(details) {
  const known = Object.keys(DETAIL_LABELS).filter(key => key in details);
  const rest = Object.keys(details).filter(key => !(key in DETAIL_LABELS) && key !== 'unit');
  return [...known, ...rest].map(key => {
    const value = key === 'amount' ? `${fmt(details.amount)} ${details.unit ?? ''}`.trim() : String(details[key]);
    return el('div', {}, el('dt', {}, DETAIL_LABELS[key] || key), el('dd', {}, value));
  });
}

function openApproval(approval, { discardOnCancel = false } = {}) {
  const { palmEnabled, requirePalm } = state.config;
  active = { approval, discardOnCancel };
  $('approval-kind').textContent = approval.kind === 'send' ? 'Approve this hand-over' : 'Approve to accept';
  $('approval-statement').textContent = approval.statement;
  $('approval-details').replaceChildren(...detailRows(approval.details));
  $('approve-browser').hidden = requirePalm;
  $('approve-palm').hidden = !palmEnabled;
  $('approval-choose').classList.toggle('single', !palmEnabled || requirePalm);
  $('approval-error').textContent = '';
  $('approval').showModal();

  if (palmEnabled) {
    // Palm first: the request goes to the person's Veyns app as soon as they review the action.
    startPalm(active);
  } else if (requirePalm) {
    $('approval-error').textContent = 'Palm approval is not set up on this site yet.';
    stage('closed');
  } else {
    stage('choose');
  }
}

function stage(name, text = '') {
  $('approval-choose').hidden = name !== 'choose';
  $('approval-wait').hidden = name !== 'wait' && name !== 'palm';
  $('approval-open').hidden = name !== 'palm';
  $('approval-browser-instead').hidden = name !== 'palm' || state.config.requirePalm;
  $('approval-wait-text').textContent = text;
  $('approval-cancel').textContent = name === 'closed' ? 'Close' : 'Cancel';
}

async function afterFailure(current, error) {
  if (active !== current) return;
  $('approval-error').textContent = friendly(error);
  // A refused approval may still be usable (a bad token) or may be closed for good (not enough credits).
  const latest = await api(`/api/approvals/${current.approval.id}`).catch(() => null);
  if (active !== current) return;
  stage(latest?.approval.status === 'open' ? 'choose' : 'closed');
}

async function approveInBrowser() {
  const current = active;
  if (!current || !window.veyns) return;
  const { approval } = current;
  const hadPalmRequest = Boolean(approval.approvalUrl);
  $('approval-error').textContent = '';
  stage('wait', 'Finish in the Veyns window.');
  try {
    const { token } = await window.veyns.approve(
      { statement: approval.statement, details: approval.details },
      { clientId: state.config.clientId, nonce: approval.nonce },
    );
    if (active !== current) return;
    const result = await api(`/api/approvals/${approval.id}/browser`, { token });
    settled(current, result.approval);
  } catch (error) {
    if (error.code === 'cancelled') {
      // Closing the browser window returns to the palm request, which is still waiting.
      if (active === current) stage(hadPalmRequest ? 'palm' : 'choose', hadPalmRequest ? PALM_WAITING : '');
      return;
    }
    afterFailure(current, error);
  }
}

const PALM_WAITING = 'Open Veyns on your phone, check the request and scan your palm.';

async function startPalm(current) {
  if (!current || active !== current) return;
  $('approval-error').textContent = '';
  stage('wait', 'Sending the request to your Veyns app…');
  try {
    const { approval } = await api(`/api/approvals/${current.approval.id}/palm`, {});
    if (active !== current) return;
    current.approval = approval;
    stage('palm', PALM_WAITING);
    pollPalm(current);
  } catch (error) {
    afterFailure(current, error);
  }
}

$('approve-browser').addEventListener('click', approveInBrowser);
$('approval-browser-instead').addEventListener('click', approveInBrowser);
$('approve-palm').addEventListener('click', () => startPalm(active));

$('approval-open').addEventListener('click', () => {
  if (active?.approval.approvalUrl) window.open(active.approval.approvalUrl, 'veyns-approval', 'popup=yes,width=420,height=640,noopener');
});

async function pollPalm(current) {
  const deadline = Date.now() + 330_000;
  while (active === current && Date.now() < deadline) {
    await wait(2500);
    if (active !== current) return;
    try {
      const { approval } = await api(`/api/approvals/${current.approval.id}`);
      if (active !== current) return;
      if (approval.status === 'approved') return settled(current, approval);
      if (approval.status !== 'open') {
        $('approval-error').textContent = approval.error || 'The approval ended.';
        return stage('closed');
      }
      if (approval.remoteStatus === 'verifying') $('approval-wait-text').textContent = 'Checking your palm…';
    } catch (error) {
      if (error.status === 401) return location.reload();
      // Network blips: keep waiting until the deadline.
    }
  }
  if (active === current) {
    await api(`/api/approvals/${current.approval.id}/cancel`, {}).catch(() => {});
    $('approval-error').textContent = 'The palm request timed out.';
    stage('closed');
  }
}

function settled(current, approval) {
  if (active !== current) return;
  active = null;
  $('approval').close();
  const d = approval.details;
  if (approval.kind === 'send') {
    $('send-form').reset();
    toast(`Handed over. ${d.to} has ${d.accept_within} to accept.`);
  } else {
    toast(`Accepted ${fmt(d.amount)} credits from ${d.from}.`);
  }
  refresh().catch(() => {});
}

async function dismissApproval() {
  const current = active;
  active = null;
  $('approval').close();
  if (!current) return;
  // Closing never approves anything. Cancel our side, and drop an unsent draft.
  await api(`/api/approvals/${current.approval.id}/cancel`, {}).catch(() => {});
  if (current.discardOnCancel) await api(`/api/transfers/${current.approval.transferId}/discard`, {}).catch(() => {});
  refresh().catch(() => {});
}

$('approval-cancel').addEventListener('click', dismissApproval);
$('approval').addEventListener('cancel', event => {
  event.preventDefault();
  dismissApproval();
});

/* -------------------------------------------------------------- start */

$('retry').addEventListener('click', boot);

// No push from Veyns or from this server: check in every 15 seconds while the page is visible.
setInterval(() => {
  if (state.me?.user.name && !active && !document.hidden) refresh().catch(() => {});
}, 15_000);

boot();
