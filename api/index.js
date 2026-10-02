'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const TOKENS_FILE = path.join(process.cwd(), 'tokens.json');
const AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth';
const TOKEN_URL = 'https://oauth2.googleapis.com/token';
const API = 'https://health.googleapis.com/v4';
const DEFAULT_SCOPE = 'https://www.googleapis.com/auth/googlehealth.activity_and_fitness.readonly';
const SKEW_SECONDS = 60; // refresh a minute early rather than racing expiry

const CLIENT_KEY_TOKENS = new Map();

function encodeState(csrf, clientKey) {
  if (!clientKey) return csrf;
  return `${csrf}:${Buffer.from(clientKey).toString('base64url')}`;
}

function decodeState(stateParam) {
  if (!stateParam) return { csrf: '', clientKey: null };
  const parts = stateParam.split(':');
  const csrf = parts[0];
  let clientKey = null;
  if (parts.length > 1) {
    try {
      clientKey = Buffer.from(parts[1], 'base64url').toString('utf8');
    } catch {}
  }
  return { csrf, clientKey };
}

// ---------- config ----------

function parseEnv(text) {
  const out = {};
  for (const line of text.split('\n')) {
    if (/^\s*(#|$)/.test(line)) continue;
    const m = line.match(/^\s*([\w.-]+)\s*=\s*(.*)$/);
    if (m) out[m[1]] = m[2].trim().replace(/^(['"])(.*)\1$/, '$2');
  }
  return out;
}

function loadConfig(req) {
  let file = {};
  try {
    file = parseEnv(fs.readFileSync(path.join(process.cwd(), '.env'), 'utf8'));
  } catch {}
  const get = (k, d) => process.env[k] || file[k] || d;
  const cfg = {
    clientId: get('GOOGLE_CLIENT_ID'),
    clientSecret: get('GOOGLE_CLIENT_SECRET'),
    scope: get('GOOGLE_SCOPE', DEFAULT_SCOPE),
  };

  if (req) {
    const proto = req.headers['x-forwarded-proto'] || 'https';
    const host = req.headers['x-forwarded-host'] || req.headers.host || 'localhost:8080';
    cfg.baseUrl = `${proto}://${host}`;
    cfg.redirectUri = `${cfg.baseUrl}/callback`;
  }

  return cfg;
}

function authorizeUrl(cfg, state) {
  const q = new URLSearchParams({
    client_id: cfg.clientId,
    redirect_uri: cfg.redirectUri,
    response_type: 'code',
    scope: cfg.scope,
    state,
    access_type: 'offline', // required for Google to issue a refresh token
    prompt: 'consent', // ensures consent and refresh token re-issuance
    include_granted_scopes: 'true',
  });
  return `${AUTH_URL}?${q}`;
}

const isExpired = (t) => !t || !t.expires_at || t.expires_at - SKEW_SECONDS <= Date.now() / 1000;

function normalize(raw, prev = {}) {
  return {
    access_token: raw.access_token,
    refresh_token: raw.refresh_token || prev.refresh_token,
    expires_at: Math.floor(Date.now() / 1000) + Number(raw.expires_in || 3600),
    scope: raw.scope || prev.scope,
    token_type: raw.token_type || 'Bearer',
  };
}

function parseTokenString(val) {
  if (!val) return null;
  try {
    const raw = Buffer.from(val, 'base64url').toString('utf8');
    const parsed = JSON.parse(raw);
    if (parsed && (parsed.access_token || parsed.refresh_token)) return parsed;
  } catch {}
  return { access_token: val, expires_at: Math.floor(Date.now() / 1000) + 3600 };
}

function cleanSearch(url) {
  const params = new URLSearchParams(url.searchParams);
  params.delete('__path');
  params.delete('token');
  params.delete('clientKey');
  params.delete('client_key');
  const s = params.toString();
  return s ? `?${s}` : '';
}

// ---------- cookies & tokens ----------

function parseCookies(req) {
  const header = req.headers.cookie || '';
  const list = {};
  for (const cookie of header.split(';')) {
    const parts = cookie.split('=');
    if (parts.length >= 2) {
      list[parts[0].trim()] = decodeURIComponent(parts.slice(1).join('=').trim());
    }
  }
  return list;
}

function loadClientKeysFile() {
  try {
    const text = fs.readFileSync(TOKENS_FILE, 'utf8').trim();
    if (!text) return {};
    const parsed = JSON.parse(text);
    if (parsed && typeof parsed === 'object' && parsed.clientKeys) {
      return parsed.clientKeys;
    }
  } catch {}
  return {};
}

function loadTokens(req, targetClientKey) {
  let clientKey = targetClientKey;
  if (req) {
    let queryToken = null;
    try {
      const rawUrl = req.headers['x-invoke-path'] || req.headers['x-forwarded-uri'] || req.headers['x-matched-path'] || req.url;
      const u = new URL(rawUrl, 'http://localhost');
      clientKey = clientKey || u.searchParams.get('clientKey') || u.searchParams.get('client_key');
      queryToken = u.searchParams.get('token');
    } catch {}

    clientKey = clientKey || req.headers['x-client-key'];

    if (clientKey) {
      if (CLIENT_KEY_TOKENS.has(clientKey)) {
        return CLIENT_KEY_TOKENS.get(clientKey);
      }
      const fileKeys = loadClientKeysFile();
      if (fileKeys[clientKey]) {
        CLIENT_KEY_TOKENS.set(clientKey, fileKeys[clientKey]);
        return fileKeys[clientKey];
      }
    }

    if (queryToken) {
      const resolved = parseTokenString(queryToken);
      if (resolved) return resolved;
    }

    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.toLowerCase().startsWith('bearer ')) {
      const tokenVal = authHeader.slice(7).trim();
      if (CLIENT_KEY_TOKENS.has(tokenVal)) {
        return CLIENT_KEY_TOKENS.get(tokenVal);
      }
      const fileKeys = loadClientKeysFile();
      if (fileKeys[tokenVal]) {
        CLIENT_KEY_TOKENS.set(tokenVal, fileKeys[tokenVal]);
        return fileKeys[tokenVal];
      }
      const resolved = parseTokenString(tokenVal);
      if (resolved) return resolved;
    }

    const cookies = parseCookies(req);
    if (cookies.google_health_tokens) {
      const resolved = parseTokenString(cookies.google_health_tokens);
      if (resolved) return resolved;
    }
  }

  try {
    const text = fs.readFileSync(TOKENS_FILE, 'utf8').trim();
    if (!text) return null;
    const parsed = JSON.parse(text);
    if (parsed.access_token || parsed.refresh_token) return parsed;
  } catch {}

  return null;
}

function saveTokens(res, t, clientKey) {
  if (clientKey) {
    CLIENT_KEY_TOKENS.set(clientKey, t);
  }

  if (res) {
    const val = Buffer.from(JSON.stringify(t)).toString('base64url');
    const maxAge = 365 * 24 * 3600; // 1 year
    appendCookie(res, `google_health_tokens=${val}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}`);
    if (clientKey) {
      appendCookie(res, `google_client_key=${encodeURIComponent(clientKey)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}`);
    }
  }

  try {
    let current = {};
    try {
      const text = fs.readFileSync(TOKENS_FILE, 'utf8').trim();
      if (text) current = JSON.parse(text);
    } catch {}

    current.access_token = t.access_token;
    current.refresh_token = t.refresh_token;
    current.expires_at = t.expires_at;
    current.scope = t.scope;
    current.token_type = t.token_type;

    if (clientKey) {
      if (!current.clientKeys) current.clientKeys = {};
      current.clientKeys[clientKey] = t;
    }

    fs.writeFileSync(TOKENS_FILE, JSON.stringify(current, null, 2) + '\n', { mode: 0o600 });
  } catch {}

  return t;
}

function clearTokens(res) {
  if (res) {
    appendCookie(res, 'google_health_tokens=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT');
    appendCookie(res, 'google_client_key=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT');
    appendCookie(res, 'google_state=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT');
  }
  try {
    if (fs.existsSync(TOKENS_FILE)) {
      fs.truncateSync(TOKENS_FILE, 0);
      fs.unlinkSync(TOKENS_FILE);
    }
  } catch {}
}

function appendCookie(res, cookieStr) {
  const existing = res.getHeader('Set-Cookie');
  if (!existing) {
    res.setHeader('Set-Cookie', [cookieStr]);
  } else if (Array.isArray(existing)) {
    res.setHeader('Set-Cookie', [...existing, cookieStr]);
  } else {
    res.setHeader('Set-Cookie', [existing, cookieStr]);
  }
}

async function tokenRequest(cfg, body) {
  const res = await fetch(TOKEN_URL, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ client_id: cfg.clientId, client_secret: cfg.clientSecret, ...body }),
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`Google token endpoint returned ${res.status}: ${text}`);
  return JSON.parse(text);
}

async function refresh(cfg, res, tokens, clientKey) {
  const fresh = await tokenRequest(cfg, {
    grant_type: 'refresh_token',
    refresh_token: tokens.refresh_token,
  });
  return saveTokens(res, normalize(fresh, tokens), clientKey);
}

// ---------- html ----------

const esc = (s) =>
  String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const CSS = `
  :root { color-scheme: light dark; --g: #1a73e8; }
  body { font: 15px/1.5 -apple-system, system-ui, sans-serif; max-width: 46rem; margin: 3rem auto; padding: 0 1.25rem; }
  h1 { font-size: 1.4rem; }
  a.btn, button { background: var(--g); color: #fff; border: 0; border-radius: 6px;
    padding: .6rem 1rem; font: inherit; cursor: pointer; text-decoration: none; display: inline-block; }
  button.ghost { background: transparent; color: inherit; border: 1px solid currentColor; opacity: .7; }
  .row { display: flex; gap: .5rem; align-items: center; margin: .35rem 0 1rem; flex-wrap: wrap; }
  code, pre { font-family: ui-monospace, Menlo, monospace; font-size: 13px; }
  code.tok { background: rgba(127,127,127,.18); padding: .5rem .6rem; border-radius: 6px;
    flex: 1; overflow-wrap: anywhere; }
  pre { background: rgba(127,127,127,.12); padding: .8rem; border-radius: 6px; overflow: auto; max-height: 24rem; }
  label { font-weight: 600; font-size: .85rem; text-transform: uppercase; letter-spacing: .04em; opacity: .65; }
  .err { border-left: 3px solid #c00; padding-left: .8rem; }
`;

const page = (body) => `<!doctype html><html><head><meta charset="utf-8">
<title>Google Health token</title><style>${CSS}</style></head><body>${body}</body></html>`;

function connectPage(cfg, state, error, clientKey) {
  return page(`
    <h1>Google Health access token</h1>
    ${error ? `<p class="err">${esc(error)}</p>` : ''}
    ${clientKey ? `<p>Linking Client Key: <code>${esc(clientKey)}</code></p>` : ''}
    <p>Scope: <code>${esc(cfg.scope)}</code></p>
    <p><a class="btn" href="${esc(authorizeUrl(cfg, state))}">Sign in with Google</a></p>
  `);
}

function tokensPage(t, error, clientKey) {
  const field = (label, value) => `
    <label>${label}</label>
    <div class="row">
      <code class="tok" id="${label.replace(/\W/g, '')}">${esc(value || '(none)')}</code>
      <button class="ghost" onclick="copy('${label.replace(/\W/g, '')}', this)">Copy</button>
    </div>`;
  const disconnectUrl = `/disconnect${clientKey ? '?clientKey=' + encodeURIComponent(clientKey) : ''}`;
  return page(`
    <h1>Connected</h1>
    ${error ? `<p class="err">${esc(error)}</p>` : ''}
    ${clientKey ? field('Client Key', clientKey) : ''}
    <p><a class="btn" href="${esc(disconnectUrl)}">Disconnect</a></p>
    ${clientKey ? `<script>
      function copy(id, btn) {
        navigator.clipboard.writeText(document.getElementById(id).textContent);
        btn.textContent = 'Copied'; setTimeout(() => btn.textContent = 'Copy', 1200);
      }
    </script>` : ''}
  `);
}

// ---------- handler ----------

function send(res, status, body, headers = {}) {
  res.writeHead(status, { 'content-type': 'text/html; charset=utf-8', ...headers });
  res.end(body);
}

const redirect = (res, to) => send(res, 302, '', { location: to });

async function handler(req, res) {
  const cfg = loadConfig(req);
  if (!cfg.clientId || !cfg.clientSecret) {
    return send(res, 500, page('<p class="err">Missing <code>GOOGLE_CLIENT_ID</code> or <code>GOOGLE_CLIENT_SECRET</code> environment variables.</p>'));
  }

  // Parse original URL from Vercel proxy headers or req.url
  const rawUrl = req.headers['x-invoke-path'] || req.headers['x-forwarded-uri'] || req.headers['x-matched-path'] || req.url;
  const url = new URL(rawUrl, cfg.baseUrl);
  const cookies = parseCookies(req);
  const clientKey = url.searchParams.get('clientKey') || url.searchParams.get('client_key') || cookies.google_client_key;

  // Extract normalized pathname
  let pathname = url.searchParams.get('__path') || url.pathname;
  if (pathname === '/api/index' || pathname === '/api') {
    pathname = '/';
  } else if (pathname.startsWith('/api/index/')) {
    pathname = pathname.replace('/api/index', '');
  } else if (pathname.startsWith('/api/')) {
    pathname = pathname.replace('/api', '');
  }

  // Detect OAuth callback
  const isCallback = pathname === '/callback' || (url.searchParams.has('code') && url.searchParams.has('state')) || url.searchParams.has('error');

  try {
    if (req.method === 'POST' && pathname === '/refresh') {
      const tokens = loadTokens(req, clientKey);
      if (!tokens) return redirect(res, '/');
      try {
        const fresh = await refresh(cfg, res, tokens, clientKey);
        return send(res, 200, tokensPage(fresh, null, clientKey));
      } catch (e) {
        return send(res, 200, tokensPage(tokens, `Refresh failed: ${e.message}`, clientKey));
      }
    }

    if (pathname === '/disconnect') {
      clearTokens(res);
      return redirect(res, clientKey ? `/?clientKey=${encodeURIComponent(clientKey)}` : '/');
    }

    if (isCallback) {
      const err = url.searchParams.get('error');
      const stateParam = url.searchParams.get('state');
      const { csrf: stateCsrf, clientKey: stateClientKey } = decodeState(stateParam);
      const expectedState = cookies.google_state;

      if (err) {
        const newCsrf = crypto.randomBytes(16).toString('hex');
        const effectiveClientKey = stateClientKey || clientKey;
        const newState = encodeState(newCsrf, effectiveClientKey);
        appendCookie(res, `google_state=${newCsrf}; Path=/; HttpOnly; SameSite=Lax; Max-Age=600`);
        return send(res, 400, connectPage(cfg, newState, `Google said: ${err}`, effectiveClientKey));
      }

      if (expectedState && stateCsrf !== expectedState) {
        return send(res, 400, page('<p class="err">Bad or stale <code>state</code> parameter. Start again at <a href="/">/</a>.</p>'));
      }

      appendCookie(res, 'google_state=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0');

      const granted = await tokenRequest(cfg, {
        grant_type: 'authorization_code',
        code: url.searchParams.get('code'),
        redirect_uri: cfg.redirectUri,
      });
      const resolvedClientKey = stateClientKey || clientKey;
      saveTokens(res, normalize(granted), resolvedClientKey);
      return redirect(res, resolvedClientKey ? `/?clientKey=${encodeURIComponent(resolvedClientKey)}` : '/');
    }

    if (pathname === '/' || pathname === '') {
      let tokens = loadTokens(req, clientKey);
      let error = null;
      if (tokens && isExpired(tokens)) {
        try {
          tokens = await refresh(cfg, res, tokens, clientKey);
        } catch (e) {
          tokens = null;
          error = `Refresh failed, sign in again. ${e.message}`;
        }
      }
      if (!tokens) {
        const csrf = cookies.google_state || crypto.randomBytes(16).toString('hex');
        if (!cookies.google_state) {
          appendCookie(res, `google_state=${csrf}; Path=/; HttpOnly; SameSite=Lax; Max-Age=600`);
        }
        const state = encodeState(csrf, clientKey);
        return send(res, 200, connectPage(cfg, state, error, clientKey));
      }
      return send(res, 200, tokensPage(tokens, error, clientKey));
    }

    if (req.method === 'GET' && (pathname === '/v4/users/me/dataTypes/exercise/dataPoints' || pathname === '/dataPoints')) {
      let tokens = loadTokens(req, clientKey);
      if (!tokens) return send(res, 401, JSON.stringify({ error: 'Not connected.' }), { 'content-type': 'application/json' });
      if (isExpired(tokens)) {
        try {
          tokens = await refresh(cfg, res, tokens, clientKey);
        } catch (e) {
          return send(res, 401, JSON.stringify({ error: `Token refresh failed: ${e.message}` }), { 'content-type': 'application/json' });
        }
      }
      const targetUrl = `${API}/users/me/dataTypes/exercise/dataPoints${cleanSearch(url)}`;
      const r = await fetch(targetUrl, {
        headers: { authorization: `Bearer ${tokens.access_token}` },
      });
      const text = await r.text();
      let body;
      try {
        body = JSON.parse(text);
        if (Array.isArray(body.dataPoints)) {
          body.dataPoints = body.dataPoints
            .filter((dp) => dp?.dataSource?.recordingMethod !== 'MANUAL')
            .map((dp) => {
              const nameParts = (dp.name || '').split('/');
              const recordId = nameParts[nameParts.length - 1] || '';
              const metrics = dp.exercise?.metricsSummary || {};
              return {
                recordId,
                distanceMillimeters: metrics.distanceMillimeters,
                averagePaceSecondsPerMeter: metrics.averagePaceSecondsPerMeter,
              };
            });
        }
      } catch {
        body = { raw: text };
      }
      return send(res, r.status, JSON.stringify(body), { 'content-type': 'application/json' });
    }

    if (pathname === '/test') {
      let tokens = loadTokens(req, clientKey);
      if (!tokens) return send(res, 200, JSON.stringify({ status: 0, body: 'Not connected.' }), { 'content-type': 'application/json' });
      if (isExpired(tokens)) tokens = await refresh(cfg, res, tokens, clientKey);
      const r = await fetch(`${API}/users/me/dataTypes/exercise/dataPoints`, {
        headers: { authorization: `Bearer ${tokens.access_token}` },
      });
      const body = await r.json().catch(() => null);
      return send(res, 200, JSON.stringify({ status: r.status, body }), { 'content-type': 'application/json' });
    }

    send(res, 404, page('<p>Not found. <a href="/">Home</a></p>'));
  } catch (e) {
    send(res, 500, page(`<p class="err">${esc(e.message)}</p><p><a href="/">Back</a></p>`));
  }
}

module.exports = handler;
