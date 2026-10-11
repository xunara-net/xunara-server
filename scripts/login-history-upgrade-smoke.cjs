const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const net = require('node:net');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');
const { DatabaseSync } = require('node:sqlite');

const previous = process.env.SMOKE_PREVIOUS_XUNARAD;
const current = process.env.SMOKE_XUNARAD;
const previousIdentity = Number(process.env.SMOKE_PREVIOUS_IDENTITY || 17);
assert.equal([17, 18].includes(previousIdentity), true);
assert.equal(!!previous && fs.existsSync(previous) && !!current && fs.existsSync(current), true);
process.umask(0o077);
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'xunara-login-history-upgrade-'));
const state = path.join(root, 'state');
const backup = path.join(root, 'previous');
let daemon, origin;
let stage = 'startup';
function mark(value) { stage = value; console.log(JSON.stringify({ stage })); }
const delay = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));
async function stop() {
  if (daemon && daemon.exitCode === null) {
    const stopped = new Promise((resolve) => daemon.once('exit', resolve));
    daemon.kill('SIGTERM'); await stopped;
  }
}
function start(binary) {
  const log = fs.openSync(path.join(root, 'daemon.log'), 'a', 0o600);
  daemon = spawn(binary, ['-listen', new URL(origin).host, '-server-url', origin, '-state-dir', state,
    '-grpc-listen', '127.0.0.1:0', '-log-level', 'error', '-allow-local-login'], { stdio: ['ignore', log, log] });
  fs.closeSync(log);
}
async function ready() {
  for (let attempt = 0; attempt < 100; attempt++) {
    try { if ((await fetch(origin + '/health', { signal: AbortSignal.timeout(1000) })).ok) return; } catch {}
    if (daemon.exitCode !== null) throw new Error('upgrade smoke daemon exited');
    await delay(100);
  }
  throw new Error('upgrade smoke daemon did not become healthy');
}
function quoted(name) { return '"' + name.replaceAll('"', '""') + '"'; }
function snapshot(shape) {
  const database = new DatabaseSync(path.join(state, 'state.db'), { readOnly: true });
  try {
    const tables = shape ? Object.keys(shape) : database.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").all().map((table) => table.name);
    return Object.fromEntries(tables.map((table) => {
      const columns = shape ? shape[table].columns : database.prepare('PRAGMA table_info(' + quoted(table) + ')').all().map((column) => column.name);
      const statement = database.prepare('SELECT ' + columns.map(quoted).join(',') + ' FROM ' + quoted(table));
      statement.setReadBigInts(true);
      const rows = statement.all().map((row) => {
        if (table === 'schema_migrations' && row.module === 'identity') row.version = BigInt(previousIdentity);
        return JSON.stringify(row, (_key, value) => typeof value === 'bigint' ? String(value) : value);
      }).sort();
      return [table, { columns, rows }];
    }));
  } finally { database.close(); }
}
function version() {
  const database = new DatabaseSync(path.join(state, 'state.db'), { readOnly: true });
  try { return database.prepare("SELECT version FROM schema_migrations WHERE module = 'identity'").get().version; }
  finally { database.close(); }
}
async function main() {
  const listener = net.createServer();
  await new Promise((resolve) => listener.listen(0, '127.0.0.1', resolve));
  origin = 'http://127.0.0.1:' + listener.address().port;
  await new Promise((resolve) => listener.close(resolve));
  mark(`released-v${previousIdentity}-initializes-an-isolated-owner-and-human-session`);
  start(previous); await ready(); assert.equal(version(), previousIdentity);
  const markup = await fetch(origin + '/setup').then((response) => response.text());
  const proof = fs.readFileSync(path.join(state, 'setup-token'), 'utf8').trim();
  const csrf = /name="_csrf" value="([^"]+)"/.exec(markup)[1];
  const password = crypto.randomBytes(24).toString('base64url');
  const initialized = await fetch(origin + '/setup', { method: 'POST', redirect: 'manual',
    body: new URLSearchParams({ token: proof, _csrf: csrf, login: 'upgrade-owner', password, confirm: password }), signal: AbortSignal.timeout(20000) });
  assert.equal(initialized.status, 302);
  const cookie = initialized.headers.get('set-cookie').split(';')[0];
  assert.equal((await fetch(origin + '/api/v1/auth/session', { headers: { Cookie: cookie } }).then((response) => response.json())).authenticated, true);
  const previousHistory = previousIdentity === 18 ? await fetch(origin + '/api/v1/account/login-history', { headers: { Cookie: cookie } }).then((response) => response.json()) : null;
  await stop(); fs.cpSync(state, backup, { recursive: true });
  const before = snapshot();

  mark(previousIdentity === 17 ? 'v18-appends-history-without-changing-existing-table-facts-or-credentials' : 'v18-compatible-upgrade-preserves-existing-tables-and-original-human-session');
  start(current); await ready(); assert.equal(version(), 18);
  assert.deepEqual(snapshot(before), before);
  const history = await fetch(origin + '/api/v1/account/login-history', { headers: { Cookie: cookie } }).then((response) => response.json());
  assert.equal(history.records.length, 1);
  if (previousIdentity === 17) {
    assert.equal(history.records[0].kind, 'legacy');
    assert.equal(history.records[0].client_ip, undefined); assert.equal(history.records[0].user_agent, undefined);
  } else {
    assert.deepEqual(history.records, previousHistory.records);
    const account = await fetch(origin + '/api/v1/account', { headers: { Cookie: cookie } }).then((response) => response.json());
    const exported = await fetch(origin + '/api/v1/account/export', { method: 'POST',
      headers: { Cookie: cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': account.csrf_token }, body: JSON.stringify({ format: 'json' }) });
    assert.equal(exported.status, 200);
    const data = await exported.text();
    assert.equal(JSON.parse(data).account.id, account.user.id);
    assert.equal(data.includes(account.csrf_token) || data.includes(cookie.split('=')[1]), false);
    const unchanged = Object.fromEntries(Object.entries(before).filter(([table]) => !['audit_events', 'rate_limits'].includes(table)));
    assert.deepEqual(snapshot(unchanged), unchanged);
  }
  assert.equal((await fetch(origin + '/api/v1/auth/session', { headers: { Cookie: cookie } }).then((response) => response.json())).authenticated, true);
  await stop();
  mark(previousIdentity === 17 ? 'v17-refuses-new-identity-schema-without-rewriting-original-tables' : 'released-v18-reads-prepared-export-state-and-preserves-original-login');
  start(previous);
  if (previousIdentity === 17) {
    await new Promise((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error('old daemon did not reject the schema')), 15000);
      daemon.once('exit', (code) => { clearTimeout(timeout); assert.notEqual(code, 0); resolve(); });
    });
    assert.deepEqual(snapshot(before), before);
  } else {
    await ready(); assert.equal(version(), 18);
    assert.equal((await fetch(origin + '/api/v1/auth/session', { headers: { Cookie: cookie } }).then((response) => response.json())).authenticated, true);
    assert.equal((await fetch(origin + '/api/v1/account/export', { method: 'POST', headers: { Cookie: cookie, 'Content-Type': 'application/json' }, body: '{}' })).status, 404);
    await stop();
  }
  mark(`complete-v${previousIdentity}-state-and-binary-rollback-restores-the-original-login`);
  fs.rmSync(state, { recursive: true, force: true });
  fs.cpSync(backup, state, { recursive: true });
  start(previous); await ready(); assert.equal(version(), previousIdentity);
  assert.deepEqual(snapshot(before), before);
  assert.equal((await fetch(origin + '/api/v1/auth/session', { headers: { Cookie: cookie } }).then((response) => response.json())).authenticated, true);
  console.log(JSON.stringify({ result: 'passed', previousIdentity, currentIdentity: 18, originalTablesPreserved: Object.keys(before).length, productionTouched: false }));
}
main().catch((error) => {
  console.error(JSON.stringify({ result: 'failed', stage, errorType: error.name, locations: error.stack?.split('\n').filter((line) => line.includes(__filename)) }));
  process.exitCode = 1;
}).finally(async () => { await stop(); fs.rmSync(root, { recursive: true, force: true }); });
