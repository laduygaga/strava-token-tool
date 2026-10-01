#!/usr/bin/env node
'use strict';

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const handler = require('./api/index.js');

function parseEnv(text) {
  const out = {};
  for (const line of text.split('\n')) {
    if (/^\s*(#|$)/.test(line)) continue;
    const m = line.match(/^\s*([\w.-]+)\s*=\s*(.*)$/);
    if (m) out[m[1]] = m[2].trim().replace(/^(['"])(.*)\1$/, '$2');
  }
  return out;
}

function getPort() {
  let file = {};
  try {
    file = parseEnv(fs.readFileSync(path.join(__dirname, '.env'), 'utf8'));
  } catch {}
  return Number(process.env.PORT || file.PORT || 8080);
}

function start() {
  const port = getPort();
  const server = http.createServer(handler);

  server.listen(port, () => {
    console.log(`Google Health token tool running locally: http://localhost:${port}`);
    console.log(`OAuth callback URL: http://localhost:${port}/callback`);
  });
}

function selfCheck() {
  const assert = require('node:assert');
  console.log('Running selfcheck...');
  assert.strictEqual(typeof handler, 'function');
  console.log('selfcheck ok');
}

if (process.argv.includes('--selfcheck')) selfCheck();
else start();
