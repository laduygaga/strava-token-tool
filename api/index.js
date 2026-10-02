'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { Redis } = require('@upstash/redis');

const TOKENS_FILE = path.join(process.cwd(), 'tokens.json');
const AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth';
const TOKEN_URL = 'https://oauth2.googleapis.com/token';
const API = 'https://health.googleapis.com/v4';
const DEFAULT_SCOPE = 'https://www.googleapis.com/auth/googlehealth.activity_and_fitness.readonly';
const SKEW_SECONDS = 60; // refresh a minute early rather than racing expiry

const CLIENT_KEY_TOKENS = new Map();
let redisClient = null;

function getRedis(cfg) {
  const url = cfg?.upstashRedisRestUrl || process.env.UPSTASH_REDIS_REST_URL || process.env.KV_REST_API_URL;
  const token = cfg?.upstashRedisRestToken || process.env.UPSTASH_REDIS_REST_TOKEN || process.env.KV_REST_API_TOKEN;
  if (!url || !token) return null;
  if (!redisClient) {
    try {
      redisClient = new Redis({ url, token });
    } catch (e) {
      console.error('Upstash Redis client initialization error:', e);
      return null;
    }
  }
  return redisClient;
}

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
    upstashRedisRestUrl: get('UPSTASH_REDIS_REST_URL') || get('KV_REST_API_URL'),
    upstashRedisRestToken: get('UPSTASH_REDIS_REST_TOKEN') || get('KV_REST_API_TOKEN'),
  };

  if (cfg.upstashRedisRestUrl) process.env.UPSTASH_REDIS_REST_URL = cfg.upstashRedisRestUrl;
  if (cfg.upstashRedisRestToken) process.env.UPSTASH_REDIS_REST_TOKEN = cfg.upstashRedisRestToken;

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

// Server-authoritative conversion: the game client only triggers a sync and never
// computes or reports stats, so these formulas cannot be tampered with client-side.
const STAT_RULES = {
  distanceMmPerStr: 100000,
  maxStatsPerRecord: 50,
  maxStatsPerSync: 500,
};

// Physical sanity bounds: real Google Health data can still be gamed (e.g. a car
// ride logged as a run), so implausible values are rejected before granting stats.
const SANITY = {
  minDistanceMm: 1,
  maxDistanceMm: 500 * 1000 * 1000,
  minPaceSecPerMeter: 0.1, // < 0.1 implies > 10 m/s (36 km/h) sustained — not human running
  maxPaceSecPerMeter: 600, // > 600 implies slower than a slow walk — not a real run
};

function isPlausibleRecord(rec) {
  const dist = Number(rec.distanceMillimeters);
  const pace = Number(rec.averagePaceSecondsPerMeter);
  if (!Number.isFinite(dist) || dist < SANITY.minDistanceMm || dist > SANITY.maxDistanceMm) {
    return false;
  }
  if (rec.averagePaceSecondsPerMeter != null) {
    if (!Number.isFinite(pace) || pace < SANITY.minPaceSecPerMeter || pace > SANITY.maxPaceSecPerMeter) {
      return false;
    }
  }
  return true;
}

function statsForRecord(rec) {
  const str = Math.floor(Number(rec.distanceMillimeters) / STAT_RULES.distanceMmPerStr);

  let agi = 0;
  const pace = Number(rec.averagePaceSecondsPerMeter);
  if (Number.isFinite(pace) && pace > 0) {
    agi = Math.floor(pace);
  }

  const clamp = (v) => Math.max(0, Math.min(STAT_RULES.maxStatsPerRecord, v));
  return { str: clamp(str), agi: clamp(agi) };
}

// Reserves a recordId per clientKey exactly once (replay / double-count protection,
// scoped so one user cannot claim another user's recordId). Returns true only the
// first time a record is seen. The in-memory fallback is best-effort and does not
// survive restarts or serverless instances; production must configure Upstash Redis.
async function reserveRecord(redis, clientKey, recordId) {
  if (!redis) {
    const key = `${clientKey}:${recordId}`;
    if (PROCESSED_RECORDS_MEM.has(key)) return false;
    PROCESSED_RECORDS_MEM.add(key);
    return true;
  }
  try {
    // Redis SET NX writes only if the key is absent, giving an atomic first-seen check.
    const res = await redis.set(`game:processed:${clientKey}:${recordId}`, 1, { nx: true });
    return res === 'OK' || res === true;
  } catch (e) {
    // On storage failure, refuse to grant stats rather than risk double-counting.
    console.error('Error reserving record in Redis:', e);
    throw new Error('record-store-unavailable');
  }
}

const PROCESSED_RECORDS_MEM = new Set();

async function loadGameStats(redis, clientKey) {
  const empty = { str: 0, agi: 0, recordCount: 0 };
  if (!redis) return { ...(GAME_STATS_MEM.get(clientKey) || empty) };
  try {
    const val = await redis.get(`game:stats:${clientKey}`);
    if (val) {
      const parsed = typeof val === 'string' ? JSON.parse(val) : val;
      return { ...empty, ...parsed };
    }
  } catch (e) {
    console.error('Error reading game stats from Redis:', e);
  }
  return { ...empty };
}

async function saveGameStats(redis, clientKey, stats) {
  if (!redis) {
    GAME_STATS_MEM.set(clientKey, stats);
    return;
  }
  try {
    await redis.set(`game:stats:${clientKey}`, JSON.stringify(stats));
  } catch (e) {
    console.error('Error saving game stats to Redis:', e);
  }
}

const GAME_STATS_MEM = new Map();

// Single source of truth for exercise records, shared by the read-only /dataPoints
// view and the stat-granting /sync path. MANUAL (self-reported) entries are dropped
// here because they are trivially forgeable and must never grant stats.
function normalizeDataPoints(body) {
  if (!body || !Array.isArray(body.dataPoints)) return [];
  return body.dataPoints
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

async function fetchExerciseRecords(url, tokens) {
  const targetUrl = `${API}/users/me/dataTypes/exercise/dataPoints${cleanSearch(url)}`;
  const r = await fetch(targetUrl, {
    headers: { authorization: `Bearer ${tokens.access_token}` },
  });
  const text = await r.text();
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    return { status: r.status, records: null, raw: text };
  }
  return { status: r.status, records: normalizeDataPoints(body), raw: body };
}

// ---------- quiz bank ----------

const QUIZ_CSV_FILE = path.join(process.cwd(), 'quiz-bank.csv');
const QUIZ_REDIS_KEY = 'quiz:bank';
const QUIZ_BANK_MEM = { data: null };

// Column order in quiz-bank.csv mapped to the normalized question shape.
const QUIZ_COLUMNS = [
  'id', 'context', 'question',
  'choiceA', 'choiceB', 'choiceC', 'choiceD',
  'correctAnswer', 'deltaStr', 'deltaInt', 'deltaAgi', 'deltaCha',
  'feedbackCorrect', 'feedbackWrong', 'learning',
];

const QUIZ_NUMERIC_FIELDS = new Set(['deltaStr', 'deltaInt', 'deltaAgi', 'deltaCha']);

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', (chunk) => {
      raw += chunk;
      if (raw.length > 1_000_000) {
        reject(new Error('body-too-large'));
        req.destroy();
      }
    });
    req.on('end', () => resolve(raw));
    req.on('error', reject);
  });
}

async function readJsonBody(req) {
  const raw = await readRawBody(req);
  if (!raw.trim()) return {};
  try {
    return JSON.parse(raw);
  } catch {
    throw new Error('invalid-json');
  }
}

// RFC-4180 CSV parser: handles quoted fields containing commas, newlines, and
// escaped double-quotes (""). The quiz source has commas inside quoted cells.
function parseCsvRows(text) {
  const rows = [];
  let row = [];
  let field = '';
  let inQuotes = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inQuotes) {
      if (c === '"') {
        if (text[i + 1] === '"') { field += '"'; i++; }
        else inQuotes = false;
      } else {
        field += c;
      }
    } else if (c === '"') {
      inQuotes = true;
    } else if (c === ',') {
      row.push(field); field = '';
    } else if (c === '\n' || c === '\r') {
      if (c === '\r' && text[i + 1] === '\n') i++;
      row.push(field); field = '';
      if (row.length > 1 || row[0] !== '') rows.push(row);
      row = [];
    } else {
      field += c;
    }
  }
  if (field !== '' || row.length) { row.push(field); rows.push(row); }
  return rows;
}

function rowToQuestion(row) {
  const q = {};
  QUIZ_COLUMNS.forEach((key, i) => {
    const val = row[i] != null ? row[i] : '';
    q[key] = QUIZ_NUMERIC_FIELDS.has(key) ? Number(val) || 0 : val;
  });
  return q;
}

function parseQuizCsv(text) {
  const rows = parseCsvRows(text);
  const bank = {};
  for (let i = 1; i < rows.length; i++) {
    const q = rowToQuestion(rows[i]);
    if (q.id) bank[q.id] = q;
  }
  return bank;
}

async function loadQuizBank(cfg) {
  const redis = getRedis(cfg);
  if (redis) {
    try {
      const val = await redis.get(QUIZ_REDIS_KEY);
      if (val) return typeof val === 'string' ? JSON.parse(val) : val;
    } catch (e) {
      console.error('Error reading quiz bank from Redis:', e);
    }
  } else if (QUIZ_BANK_MEM.data) {
    return QUIZ_BANK_MEM.data;
  }

  // First use: seed from the CSV that ships with the app.
  let seeded = {};
  try {
    seeded = parseQuizCsv(fs.readFileSync(QUIZ_CSV_FILE, 'utf8'));
  } catch (e) {
    console.error('Error seeding quiz bank from CSV:', e);
  }
  await saveQuizBank(cfg, seeded);
  return seeded;
}

async function saveQuizBank(cfg, bank) {
  const redis = getRedis(cfg);
  if (redis) {
    try {
      await redis.set(QUIZ_REDIS_KEY, JSON.stringify(bank));
      return;
    } catch (e) {
      console.error('Error saving quiz bank to Redis:', e);
    }
  }
  QUIZ_BANK_MEM.data = bank;
}

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

async function loadTokens(req, targetClientKey, cfg) {
  let clientKey = targetClientKey;
  const redis = getRedis(cfg);

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
      if (redis) {
        try {
          const redisVal = await redis.get(`oauth:client:${clientKey}`);
          if (redisVal) {
            const parsed = typeof redisVal === 'string' ? JSON.parse(redisVal) : redisVal;
            CLIENT_KEY_TOKENS.set(clientKey, parsed);
            return parsed;
          }
        } catch (e) {
          console.error('Error reading from Upstash Redis:', e);
        }
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
      if (redis) {
        try {
          const redisVal = await redis.get(`oauth:client:${tokenVal}`);
          if (redisVal) {
            const parsed = typeof redisVal === 'string' ? JSON.parse(redisVal) : redisVal;
            CLIENT_KEY_TOKENS.set(tokenVal, parsed);
            return parsed;
          }
        } catch (e) {
          console.error('Error reading bearer token from Upstash Redis:', e);
        }
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

  if (redis) {
    try {
      const redisVal = await redis.get('oauth:default_tokens');
      if (redisVal) {
        return typeof redisVal === 'string' ? JSON.parse(redisVal) : redisVal;
      }
    } catch (e) {
      console.error('Error reading default tokens from Upstash Redis:', e);
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

async function saveTokens(res, t, clientKey, cfg) {
  if (clientKey) {
    CLIENT_KEY_TOKENS.set(clientKey, t);
  }

  const redis = getRedis(cfg);
  if (redis) {
    try {
      if (clientKey) {
        await redis.set(`oauth:client:${clientKey}`, t);
      }
      await redis.set('oauth:default_tokens', t);
    } catch (e) {
      console.error('Error saving to Upstash Redis:', e);
    }
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

async function clearTokens(res, clientKey, cfg) {
  if (clientKey) {
    CLIENT_KEY_TOKENS.delete(clientKey);
  } else {
    CLIENT_KEY_TOKENS.clear();
  }

  const redis = getRedis(cfg);
  if (redis) {
    try {
      if (clientKey) {
        await redis.del(`oauth:client:${clientKey}`);
      }
      await redis.del('oauth:default_tokens');
    } catch (e) {
      console.error('Error deleting from Upstash Redis:', e);
    }
  }

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
  return await saveTokens(res, normalize(fresh, tokens), clientKey, cfg);
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
  res.writeHead(status, {
    'content-type': 'text/html; charset=utf-8',
    'access-control-allow-origin': '*',
    'access-control-allow-methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'access-control-allow-headers': '*',
    ...headers,
  });
  res.end(body);
}

const redirect = (res, to) => send(res, 302, '', { location: to });

async function handler(req, res) {
  if (req.method === 'OPTIONS') {
    return send(res, 204, '');
  }

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
      const tokens = await loadTokens(req, clientKey, cfg);
      if (!tokens) return redirect(res, '/');
      try {
        const fresh = await refresh(cfg, res, tokens, clientKey);
        return send(res, 200, tokensPage(fresh, null, clientKey));
      } catch (e) {
        return send(res, 200, tokensPage(tokens, `Refresh failed: ${e.message}`, clientKey));
      }
    }

    if (pathname === '/disconnect') {
      await clearTokens(res, clientKey, cfg);
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
      await saveTokens(res, normalize(granted), resolvedClientKey, cfg);
      return redirect(res, resolvedClientKey ? `/?clientKey=${encodeURIComponent(resolvedClientKey)}` : '/');
    }

    if (pathname === '/' || pathname === '') {
      let tokens = await loadTokens(req, clientKey, cfg);
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
      let tokens = await loadTokens(req, clientKey, cfg);
      if (!tokens) return send(res, 401, JSON.stringify({ error: 'Not connected.' }), { 'content-type': 'application/json' });
      if (isExpired(tokens)) {
        try {
          tokens = await refresh(cfg, res, tokens, clientKey);
        } catch (e) {
          return send(res, 401, JSON.stringify({ error: `Token refresh failed: ${e.message}` }), { 'content-type': 'application/json' });
        }
      }
      const { status, records, raw } = await fetchExerciseRecords(url, tokens);
      const body = records === null ? { raw } : { dataPoints: records };
      return send(res, status, JSON.stringify(body), { 'content-type': 'application/json' });
    }

    if (req.method === 'POST' && pathname === '/sync') {
      if (!clientKey) {
        return send(res, 400, JSON.stringify({ error: 'Missing clientKey.' }), { 'content-type': 'application/json' });
      }
      let tokens = await loadTokens(req, clientKey, cfg);
      if (!tokens) return send(res, 401, JSON.stringify({ error: 'Not connected.' }), { 'content-type': 'application/json' });
      if (isExpired(tokens)) {
        try {
          tokens = await refresh(cfg, res, tokens, clientKey);
        } catch (e) {
          return send(res, 401, JSON.stringify({ error: `Token refresh failed: ${e.message}` }), { 'content-type': 'application/json' });
        }
      }

      const { status, records } = await fetchExerciseRecords(url, tokens);
      if (!Array.isArray(records)) {
        return send(res, 502, JSON.stringify({ error: 'Upstream data unavailable.' }), { 'content-type': 'application/json' });
      }

      const redis = getRedis(cfg);
      const totalStats = await loadGameStats(redis, clientKey);
      let awardedCount = 0;
      let syncStr = 0;
      let syncAgi = 0;

      try {
        for (const rec of records) {
          if (!rec.recordId) continue;
          if (!isPlausibleRecord(rec)) continue;
          if (syncStr + syncAgi >= STAT_RULES.maxStatsPerSync) continue;

          const isNew = await reserveRecord(redis, clientKey, rec.recordId);
          if (!isNew) continue;

          const delta = statsForRecord(rec);
          syncStr += delta.str;
          syncAgi += delta.agi;
          awardedCount++;
        }
      } catch (e) {
        if (e.message === 'record-store-unavailable') {
          return send(res, 503, JSON.stringify({ error: 'Record store unavailable, try again.' }), { 'content-type': 'application/json' });
        }
        throw e;
      }

      totalStats.str += syncStr;
      totalStats.agi += syncAgi;
      totalStats.recordCount += awardedCount;
      await saveGameStats(redis, clientKey, totalStats);

      return send(res, status, JSON.stringify({
        stats: { str: syncStr, agi: syncAgi },
        awardedCount,
      }), { 'content-type': 'application/json' });
    }

    if (pathname === '/quiz/import' && (req.method === 'POST' || req.method === 'PUT')) {
      let raw;
      try {
        raw = await readRawBody(req);
      } catch (e) {
        const msg = e.message === 'body-too-large' ? 'Request body too large.' : 'Could not read body.';
        return send(res, 400, JSON.stringify({ error: msg }), { 'content-type': 'application/json' });
      }

      const incoming = parseQuizCsv(raw);
      const ids = Object.keys(incoming);
      if (ids.length === 0) {
        return send(res, 400, JSON.stringify({ error: 'No valid rows found. Expected CSV with a header row and an ID column.' }), { 'content-type': 'application/json' });
      }

      const bank = await loadQuizBank(cfg);
      const created = [];
      const updated = [];
      for (const id of ids) {
        if (id in bank) updated.push(id);
        else created.push(id);
        bank[id] = incoming[id];
      }
      await saveQuizBank(cfg, bank);

      return send(res, 200, JSON.stringify({
        imported: ids.length,
        created,
        updated,
        total: Object.keys(bank).length,
      }), { 'content-type': 'application/json' });
    }

    if (pathname === '/quiz' && req.method === 'GET') {
      const bank = await loadQuizBank(cfg);
      const questions = Object.values(bank);
      if (questions.length === 0) {
        return send(res, 404, JSON.stringify({ error: 'Quiz bank is empty.' }), { 'content-type': 'application/json' });
      }
      const question = questions[Math.floor(Math.random() * questions.length)];
      return send(res, 200, JSON.stringify({ question }), { 'content-type': 'application/json' });
    }

    if (pathname === '/quiz' && (req.method === 'POST' || req.method === 'PUT')) {
      let payload;
      try {
        payload = await readJsonBody(req);
      } catch (e) {
        const msg = e.message === 'body-too-large' ? 'Request body too large.' : 'Invalid JSON body.';
        return send(res, 400, JSON.stringify({ error: msg }), { 'content-type': 'application/json' });
      }

      const id = typeof payload.id === 'string' ? payload.id.trim() : '';
      if (!id) {
        return send(res, 400, JSON.stringify({ error: 'Missing question id.' }), { 'content-type': 'application/json' });
      }

      const question = { id };
      for (const key of QUIZ_COLUMNS) {
        if (key === 'id') continue;
        if (QUIZ_NUMERIC_FIELDS.has(key)) {
          question[key] = Number(payload[key]) || 0;
        } else {
          question[key] = payload[key] != null ? String(payload[key]) : '';
        }
      }

      const bank = await loadQuizBank(cfg);
      const created = !(id in bank);
      bank[id] = question;
      await saveQuizBank(cfg, bank);

      return send(res, created ? 201 : 200, JSON.stringify({ created, question }), { 'content-type': 'application/json' });
    }

    if (pathname === '/test') {
      let tokens = await loadTokens(req, clientKey, cfg);
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
