import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes, createHash } from 'node:crypto';
import { createServer, request as httpRequest } from 'node:http';
import { mkdtempSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { once } from 'node:events';
import { spawn } from 'node:child_process';
import express from 'express';
import { installAuth, readAuthConfig, MCP_SCOPE, AUTHORIZATION_TTL } from '../auth.js';
import { createOAuthStore } from '../oauth-store.js';

// Ephemeral test-only credentials. None are printed or written into tracked files.
const secret = () => randomBytes(32).toString('base64url');
const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const key = { ...privateKey.export({ format: 'jwk' }), kid: 'ephemeral-test-key', use: 'sig', alg: 'RS256' };
// This is only a logical origin: every request is sent to the local test server.
const issuer = 'https://zhangxinchuang-mcp-74l0.onrender.com';
const resource = `${issuer}/mcp`;
const redirectUri = 'https://chatgpt.com/connector_platform_oauth_redirect';
const temp = mkdtempSync(path.join(os.tmpdir(), 'palm-oauth-test-'));
const env = { MCP_PUBLIC_URL: issuer, MCP_OWNER_SECRET: secret(), MCP_COOKIE_SECRET: secret(), MCP_CLIENT_SECRET: secret(),
  MCP_OAUTH_JWKS: JSON.stringify({ keys: [key] }), MCP_OAUTH_REDIRECT_URIS: JSON.stringify([redirectUri]),
  MCP_OAUTH_DB_PATH: path.join(temp, 'oauth.sqlite'), LINJIAN_TOKEN: secret() };
let server, auth, base;

before(async () => {
  const app = express();
  app.set('trust proxy', 1);
  auth = installAuth(app, readAuthConfig(env));
  app.use(['/mcp', '/mcp-wallet'], (_req, res) => res.json({ protected: true }));
  app.use((_err, _req, res, _next) => res.status(400).json({ error: 'request_rejected' }));
  server = app.listen(0, '127.0.0.1'); await once(server, 'listening');
  base = `http://127.0.0.1:${server.address().port}`;
});
after(async () => {
  await new Promise((resolve) => server?.close(resolve)); auth?.close();
  assert.equal(path.dirname(path.resolve(temp)), path.resolve(os.tmpdir()));
  assert.ok(path.basename(temp).startsWith('palm-oauth-test-'));
  rmSync(temp, { recursive: true, force: true });
});

function browser(targetBase = () => base) {
  const cookies = new Map();
  return async (url, init = {}) => {
    const logical = new URL(url, issuer);
    assert.equal(logical.origin, issuer, 'Tests must never call an external service');
    const headers = { host: new URL(issuer).host, 'x-forwarded-proto': 'https', ...init.headers };
    const cookie = [...cookies].filter(([, c]) => logical.pathname.startsWith(c.path)).map(([name, c]) => `${name}=${c.value}`).join('; ');
    if (cookie) headers.cookie = cookie;
    const response = await new Promise((resolve, reject) => {
      const req = httpRequest(`${targetBase()}${logical.pathname}${logical.search}`, { method: init.method || 'GET', headers }, (res) => {
        const chunks = []; res.on('data', (data) => chunks.push(data)); res.on('end', () => {
          const h = new Headers();
          for (let i = 0; i < res.rawHeaders.length; i += 2) h.append(res.rawHeaders[i], res.rawHeaders[i + 1]);
          resolve(new Response([204, 304].includes(res.statusCode) || init.method === 'HEAD' ? null : Buffer.concat(chunks), { status: res.statusCode, headers: h }));
        });
      });
      req.on('error', reject); req.end(init.body?.toString());
    });
    for (const line of response.headers.getSetCookie()) {
      const [pair, ...attrs] = line.split(';'); const pos = pair.indexOf('=');
      const name = pair.slice(0, pos), value = pair.slice(pos + 1);
      const cookiePath = attrs.find((x) => x.trim().toLowerCase().startsWith('path='))?.trim().slice(5) || '/';
      cookies.set(name, { value, path: cookiePath });
    }
    return response;
  };
}
const form = (values) => ({ method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', origin: issuer }, body: new URLSearchParams(values) });
function authParams(extra = {}) {
  const verifier = secret();
  const params = { client_id: 'zhangxinchuang-chatgpt', redirect_uri: redirectUri, response_type: 'code', scope: MCP_SCOPE,
    resource, state: secret(), code_challenge_method: 'S256', code_challenge: createHash('sha256').update(verifier).digest('base64url'), ...extra };
  return { verifier, params };
}
async function authorize(request = browser()) {
  const { verifier, params } = authParams();
  let url = `/auth?${new URLSearchParams(params)}`;
  let forms = 0;
  for (let i = 0; i < 12; i++) {
    let response = await request(url);
    if (response.status === 200) {
      assert.equal(response.headers.get('referrer-policy'), 'same-origin',
        'Native form POST must retain its HTTPS Origin; no-referrer produces Origin: null');
      const html = await response.text();
      const csrf = html.match(/name="csrf" value="([^"]+)"/)?.[1];
      assert.ok(csrf, 'Expected an authorization form');
      const action = html.match(/action="([^"]+)"/)[1];
      forms++;
      response = await request(action, form({ csrf, decision: 'allow', password: env.MCP_OWNER_SECRET }));
    }
    assert.equal(response.status, 303, `Expected redirect, got ${response.status}`);
    url = new URL(response.headers.get('location'), issuer).href;
    if (url.startsWith(redirectUri + '?')) {
      const callback = new URL(url);
      assert.equal(callback.searchParams.get('state'), params.state);
      assert.equal(callback.searchParams.get('iss'), issuer);
      assert.ok(callback.searchParams.get('code'), 'Expected authorization code');
      assert.equal(forms, 2, 'Owner must log in and explicitly consent');
      return { code: callback.searchParams.get('code'), verifier };
    }
  }
  throw new Error('Authorization did not finish');
}
async function exchange({ code, verifier }, extra = {}, request = browser()) {
  const init = form({ grant_type: 'authorization_code', client_id: 'zhangxinchuang-chatgpt',
    client_secret: env.MCP_CLIENT_SECRET, redirect_uri: redirectUri, resource, code, code_verifier: verifier, ...extra });
  delete init.headers.origin;
  return request('/token', init);
}
async function tokens(request = browser()) {
  const response = await exchange(await authorize(request), {}, request);
  if (response.status !== 200) {
    const failure = await response.json(); assert.fail(`Token exchange: ${failure.error} / ${failure.error_description}`);
  }
  return response.json();
}
function refresh(token, request = browser()) {
  const init = form({ grant_type: 'refresh_token', client_id: 'zhangxinchuang-chatgpt',
    client_secret: env.MCP_CLIENT_SECRET, resource, refresh_token: token });
  delete init.headers.origin;
  return request('/token', init);
}
async function pendingForm(request) {
  const { params } = authParams();
  const start = await request(`/auth?${new URLSearchParams(params)}`);
  const url = start.headers.get('location');
  const page = await request(url);
  const csrf = (await page.text()).match(/name="csrf" value="([^"]+)"/)[1];
  return { url, init: form({ csrf, decision: 'allow', password: env.MCP_OWNER_SECRET }) };
}

test('Render configuration refuses an implicit or relative ephemeral database', () => {
  for (const MCP_OAUTH_DB_PATH of ['', ':memory:', '.oauth-state/oauth.sqlite']) {
    assert.throws(() => readAuthConfig({ ...env, RENDER: 'true', MCP_OAUTH_DB_PATH }));
  }
  assert.ok(readAuthConfig({ ...env, RENDER: 'true' }).storePath);
});

test('expired access and deleted owner Session do not prevent refresh', async () => {
  const token = await tokens();
  const rt = await auth.provider.RefreshToken.find(token.refresh_token);
  assert.ok(!rt.expiresWithSession);
  const session = await auth.provider.Session.findByUid(rt.sessionUid);
  assert.ok(session);
  await session.destroy();
  const access = await auth.provider.AccessToken.adapter.find(token.access_token);
  access.exp = 1;
  await auth.provider.AccessToken.adapter.upsert(token.access_token, access, 600);
  assert.equal((await browser()('/mcp', { headers: { authorization: `Bearer ${token.access_token}` } })).status, 401);
  const response = await refresh(token.refresh_token);
  assert.equal(response.status, 200);
  const replacement = await response.json();
  assert.equal((await browser()('/mcp', { headers: { authorization: `Bearer ${replacement.access_token}` } })).status, 200);
});

test('90-day absolute authorization survives Session expiry and rotation never extends it', async (t) => {
  t.mock.timers.enable({ apis: ['Date'], now: Date.now() });
  const token = await tokens();
  const original = await auth.provider.RefreshToken.find(token.refresh_token);
  const grant = await auth.provider.Grant.find(original.grantId);
  assert.equal(grant.exp - grant.iat, AUTHORIZATION_TTL);
  assert.ok(original.exp <= grant.exp);
  t.mock.timers.tick(2 * 3600 * 1000);
  assert.equal(await auth.provider.Session.findByUid(original.sessionUid), undefined);
  let response = await refresh(token.refresh_token);
  assert.equal(response.status, 200);
  let current = await response.json();
  t.mock.timers.tick(88 * 24 * 3600 * 1000);
  response = await refresh(current.refresh_token);
  assert.equal(response.status, 200);
  current = await response.json();
  const rotated = await auth.provider.RefreshToken.find(current.refresh_token);
  assert.equal(rotated.iiat, original.iiat);
  assert.ok(rotated.exp <= original.exp);
  assert.ok(rotated.exp <= grant.exp);
  t.mock.timers.tick(2 * 24 * 3600 * 1000);
  assert.equal((await refresh(current.refresh_token)).status, 400);
});

test('independent Connector grants refresh independently; explicit revoke blocks only its grant', async () => {
  const first = await tokens(), second = await tokens();
  const a = await auth.provider.RefreshToken.find(first.refresh_token);
  const b = await auth.provider.RefreshToken.find(second.refresh_token);
  assert.notEqual(a.grantId, b.grantId);
  await (await auth.provider.Grant.find(a.grantId)).destroy();
  assert.equal((await refresh(first.refresh_token)).status, 400);
  assert.equal((await refresh(second.refresh_token)).status, 200);
});

test('standard revocation endpoint revokes refresh authorization', async () => {
  const token = await tokens();
  const init = form({ client_id: 'zhangxinchuang-chatgpt', client_secret: env.MCP_CLIENT_SECRET,
    token: token.refresh_token, token_type_hint: 'refresh_token' });
  delete init.headers.origin;
  assert.equal((await browser()('/token/revocation', init)).status, 200);
  assert.equal((await refresh(token.refresh_token)).status, 400);
  assert.equal((await browser()('/mcp', { headers: { authorization: `Bearer ${token.access_token}` } })).status, 401);
});

test('expired Interaction and missing or mismatched cookies show a safe restart prompt', async () => {
  const request = browser();
  const pending = await pendingForm(request);
  const uid = pending.url.split('/').at(-1);
  const interaction = await auth.provider.Interaction.adapter.find(uid);
  assert.ok(interaction);
  await auth.provider.Interaction.adapter.upsert(uid, interaction, -1);
  for (const response of [await request(pending.url, pending.init), await browser()(pending.url)]) {
    assert.equal(response.status, 400);
    assert.match(await response.text(), /返回 ChatGPT 重新发起/);
  }
  const other = await pendingForm(request);
  const response = await request(other.url + '-wrong', other.init);
  assert.equal(response.status, 400);
  assert.match(await response.text(), /返回 ChatGPT 重新发起/);
});

test('configuration fails closed and rejects unsafe URLs / reused credentials', () => {
  for (const change of [ { MCP_OWNER_SECRET: '' }, { MCP_PUBLIC_URL: 'http://example.test' },
    { MCP_OAUTH_REDIRECT_URIS: '["https://chatgpt.com.evil.test/cb"]' },
    { MCP_OAUTH_REDIRECT_URIS: '["https://chatgpt.com/connector/oauth/*"]' },
    { MCP_CLIENT_SECRET: env.LINJIAN_TOKEN }, { MCP_COOKIE_SECRET: env.MCP_OWNER_SECRET }, { MCP_OAUTH_JWKS: '{}' } ]) {
    assert.throws(() => readAuthConfig({ ...env, ...change }));
  }
});
test('discovery advertises code + S256, exact resource and no public registration', async () => {
  const request = browser();
  const metadata = await (await request('/.well-known/oauth-protected-resource')).json();
  assert.equal(metadata.resource, resource); assert.deepEqual(metadata.authorization_servers, [issuer]);
  const discovery = await (await request('/.well-known/oauth-authorization-server')).json();
  assert.equal(discovery.issuer, issuer); assert.deepEqual(discovery.response_types_supported, ['code']);
  assert.deepEqual(discovery.code_challenge_methods_supported, ['S256']);
  assert.equal(discovery.authorization_response_iss_parameter_supported, true);
  assert.equal(discovery.registration_endpoint, undefined);
  assert.ok(discovery.token_endpoint_auth_methods_supported.includes('client_secret_post'));
});

test('Render URL fallback is canonical; explicit public URL takes precedence', () => {
  assert.equal(readAuthConfig({ ...env, MCP_PUBLIC_URL: '', RENDER_EXTERNAL_URL: issuer + '/' }).issuer, issuer);
  assert.equal(readAuthConfig({ ...env, RENDER_EXTERNAL_URL: 'https://other.example.test' }).issuer, issuer);
});

test('proxy headers cannot replace the canonical HTTPS host or issuer', async () => {
  const request = browser();
  for (const headers of [ { 'x-forwarded-proto': 'http' }, { 'x-forwarded-proto': '' },
    { host: 'evil.test', 'x-forwarded-host': new URL(issuer).host } ]) {
    assert.equal((await request('/.well-known/oauth-authorization-server', { headers })).status, 400);
  }
  const response = await request('/.well-known/oauth-authorization-server', {
    headers: { 'x-forwarded-host': 'evil.test', forwarded: 'host=evil.test;proto=http' },
  });
  assert.equal(response.status, 200);
  const metadata = await response.json();
  assert.equal(metadata.issuer, issuer);
  assert.equal(new URL(metadata.authorization_endpoint).origin, issuer);
  assert.equal(new URL(metadata.token_endpoint).origin, issuer);
});

test('native form policy preserves origin; missing/null/cross-site origins fail even with a valid nonce', async () => {
  const request = browser(); const { params } = authParams();
  const start = await request(`/auth?${new URLSearchParams(params)}`);
  const url = start.headers.get('location'); const page = await request(url);
  assert.equal(page.headers.get('referrer-policy'), 'same-origin');
  const csrf = (await page.text()).match(/name="csrf" value="([^"]+)"/)[1];
  for (const origin of [undefined, 'null', 'https://evil.test', issuer + '.evil.test',
    issuer.replace('https:', 'http:'), issuer + '/', issuer + ', https://evil.test']) {
    const init = form({ csrf, password: env.MCP_OWNER_SECRET, decision: 'allow' });
    init.headers['x-forwarded-for'] = '192.0.2.10';
    init.headers['x-forwarded-host'] = new URL(issuer).host;
    init.headers.referer = issuer + url;
    if (origin === undefined) delete init.headers.origin;
    else init.headers.origin = origin;
    const response = await request(url, init);
    assert.equal(response.status, 403);
    assert.equal(await response.text(), 'Invalid form origin');
  }
  // Rejected origins must not consume the real owner's valid form nonce.
  const valid = form({ csrf, password: env.MCP_OWNER_SECRET, decision: 'allow' });
  valid.headers['x-forwarded-for'] = '192.0.2.10';
  assert.equal((await request(url, valid)).status, 303);
});
test('every MCP route rejects anonymous, backend token and query token access', async () => {
  const request = browser();
  for (const route of ['/mcp', '/mcp-wallet', '/sse', '/messages?sessionId=guess', '/MCP', '/mcp/']) {
    for (const method of ['GET', 'POST', 'DELETE']) {
      const r = await request(route, { method }); assert.equal(r.status, 401);
      assert.ok(r.headers.get('www-authenticate').includes('resource_metadata='));
    }
  }
  assert.equal((await request('/mcp', { headers: { authorization: `Bearer ${env.LINJIAN_TOKEN}` } })).status, 401);
  assert.equal((await request('/mcp?token=not-a-token')).status, 401);
  assert.equal((await request('/mcp', { headers: { host: 'evil.test' } })).status, 400);
});
test('invalid redirect, resource, PKCE and client are rejected before login', async () => {
  for (const extra of [{ redirect_uri: 'https://evil.test/cb' }, { redirect_uri: redirectUri + '/extra' },
    { resource: 'https://evil.test/mcp' }, { code_challenge_method: 'plain' }, { code_challenge: '' }, { client_id: 'unregistered' }]) {
    const { params } = authParams(extra);
    const r = await browser()(`/auth?${new URLSearchParams(params)}`);
    assert.ok(r.status >= 400 || (r.headers.get('location') || '').includes('error='));
    assert.ok(!(r.headers.get('location') || '').includes('/interaction/'));
    assert.ok(!(r.headers.get('location') || '').startsWith('https://evil.test'));
  }
});
test('complete login + consent + PKCE flow; access works and SSE stays closed', async () => {
  const token = await tokens(); const request = browser();
  assert.equal(token.token_type, 'Bearer'); assert.equal(token.expires_in, 600); assert.ok(token.refresh_token);
  for (const route of ['/mcp', '/mcp-wallet']) assert.equal((await request(route, { headers: { authorization: `Bearer ${token.access_token}` } })).status, 200);
  for (const route of ['/sse', '/messages']) assert.equal((await request(route, { method: 'POST', headers: { authorization: `Bearer ${token.access_token}` } })).status, 410);
});
test('codes reject bad verifier/client secret/redirect and cannot be reused', async () => {
  for (const extra of [{ code_verifier: secret() }, { code_verifier: '' }, { client_secret: secret() }, { redirect_uri: redirectUri + '/wrong' }, { resource: 'https://wrong.test' }]) {
    const code = await authorize(); assert.ok((await exchange(code, extra)).status >= 400);
  }
  const code = await authorize(); const response = await exchange(code); assert.equal(response.status, 200);
  const token = await response.json(); assert.equal((await exchange(code)).status, 400);
  assert.equal((await browser()('/mcp', { headers: { authorization: `Bearer ${token.access_token}` } })).status, 401, 'code replay revokes its grant tokens');
});
test('missing CSRF, wrong owner secret, cross-origin POST and denial do not grant access', async () => {
  for (const mode of ['csrf', 'password', 'origin', 'deny']) {
    const request = browser(); const { params } = authParams();
    const start = await request(`/auth?${new URLSearchParams(params)}`);
    const url = start.headers.get('location'); const page = await request(url); const html = await page.text();
    const csrf = html.match(/name="csrf" value="([^"]+)"/)[1];
    const init = form({ csrf: mode === 'csrf' ? 'bad' : csrf, password: mode === 'password' ? 'bad' : env.MCP_OWNER_SECRET, decision: mode === 'deny' ? 'deny' : 'allow' });
    if (mode === 'origin') init.headers.origin = 'https://evil.test';
    const response = await request(url, init);
    if (mode === 'deny') {
      assert.equal(response.status, 303); const resumed = await request(response.headers.get('location'));
      assert.equal(new URL(resumed.headers.get('location')).searchParams.get('error'), 'access_denied');
    } else assert.equal(response.status, mode === 'password' ? 401 : 403);
  }
});
test('SQLite adapter atomically consumes once and enforces expiration and namespace isolation', async () => {
  const store = createOAuthStore(':memory:', 'unit'); const adapter = new store.adapter('AuthorizationCode');
  await adapter.upsert('code', { grantId: 'grant' }, 60);
  const results = await Promise.allSettled([adapter.consume('code'), adapter.consume('code')]);
  assert.equal(results.filter((x) => x.status === 'fulfilled').length, 1);
  await adapter.upsert('old', {}, -1); assert.equal(await adapter.find('old'), undefined);
  await adapter.revokeByGrantId('grant'); assert.equal(await adapter.find('code'), undefined); store.close();
});

test('access tokens enforce expiry, audience, scope and owner', async () => {
  for (const [field, value, expected] of [['exp', 1, 401], ['aud', 'https://another.test/mcp', 401], ['scope', 'other:scope', 403], ['accountId', 'someone-else', 401]]) {
    const token = await tokens();
    const payload = await auth.provider.AccessToken.adapter.find(token.access_token);
    assert.ok(payload);
    payload[field] = value;
    await auth.provider.AccessToken.adapter.upsert(token.access_token, payload, 60);
    assert.equal((await browser()('/mcp', { headers: { authorization: `Bearer ${token.access_token}` } })).status, expected);
  }
});
test('refresh rotates tokens, refresh replay revokes the grant, revocation works', async () => {
  const request = browser();
  const post = (url, values) => {
    const init = form({ client_id: 'zhangxinchuang-chatgpt', client_secret: env.MCP_CLIENT_SECRET, ...values });
    delete init.headers.origin; return request(url, init);
  };
  const token = await tokens();
  const refreshed = await post('/token', { grant_type: 'refresh_token', refresh_token: token.refresh_token, resource });
  assert.equal(refreshed.status, 200);
  const replacement = await refreshed.json();
  assert.ok(replacement.refresh_token !== token.refresh_token, 'Refresh token must rotate');
  assert.equal((await request('/mcp', { headers: { authorization: `Bearer ${replacement.access_token}` } })).status, 200);
  assert.equal((await post('/token', { grant_type: 'refresh_token', refresh_token: token.refresh_token, resource })).status, 400);
  assert.equal((await request('/mcp', { headers: { authorization: `Bearer ${replacement.access_token}` } })).status, 401);
  const another = await tokens();
  assert.equal((await post('/token/revocation', { token: another.access_token, token_type_hint: 'access_token' })).status, 200);
  assert.equal((await request('/mcp', { headers: { authorization: `Bearer ${another.access_token}` } })).status, 401);
});
test('expired authorization codes cannot be exchanged', async () => {
  const code = await authorize();
  const payload = await auth.provider.AuthorizationCode.adapter.find(code.code);
  assert.ok(payload); assert.ok(payload.exp - payload.iat <= 60);
  payload.exp = 1; await auth.provider.AuthorizationCode.adapter.upsert(code.code, payload, 60);
  assert.equal((await exchange(code)).status, 400);
});
test('SQLite state survives reopening but never crosses configuration namespaces', async () => {
  const filename = path.join(temp, 'persistence.sqlite');
  let store = createOAuthStore(filename, 'first');
  await new store.adapter('AccessToken').upsert('fixture', { grantId: 'test-grant' }, 60); store.close();
  store = createOAuthStore(filename, 'first'); assert.ok(await new store.adapter('AccessToken').find('fixture')); store.close();
  store = createOAuthStore(filename, 'rotated'); assert.equal(await new store.adapter('AccessToken').find('fixture'), undefined); store.close();
});

async function launchRealServer(t, overrides = {}) {
  const portHolder = createServer(); portHolder.listen(0, '127.0.0.1'); await once(portHolder, 'listening');
  const port = portHolder.address().port; await new Promise((resolve) => portHolder.close(resolve));
  const child = spawn(process.execPath, ['server.js'], { cwd: path.resolve(import.meta.dirname, '..'),
    env: { ...process.env, ...env, MCP_OAUTH_DB_PATH: path.join(temp, `child-${port}.sqlite`), PORT: String(port), ...overrides }, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
  // Drain output without displaying credentials or request data even on a test failure.
  child.stdout.resume(); child.stderr.resume();
  t.after(async () => { if (child.exitCode === null && child.signalCode === null) { const exited = once(child, 'exit'); child.kill(); await exited; } });
  const childBase = `http://127.0.0.1:${port}`;
  let ready = false;
  for (let i = 0; i < 100; i++) {
    try { if ((await fetch(childBase + '/health')).ok) { ready = true; break; } } catch {}
    await new Promise((resolve) => setTimeout(resolve, 30));
  }
  assert.ok(ready, 'Real MCP process must become ready');
  const request = browser(() => childBase);
  request.base = childBase;
  request.stop = async () => {
    if (child.exitCode === null && child.signalCode === null) { const exited = once(child, 'exit'); child.kill(); await exited; }
  };
  return request;
}

test('real process restart reopens SQLite: refresh survives, lost CSRF safely requires new authorization', async (t) => {
  const database = path.join(temp, 'restart.sqlite');
  let running = await launchRealServer(t, { MCP_OAUTH_DB_PATH: database });
  const request = browser(() => running.base);
  const token = await tokens(running);
  const pending = await pendingForm(request);
  await running.stop();
  running = await launchRealServer(t, { MCP_OAUTH_DB_PATH: database });
  const rejected = await request(pending.url, pending.init);
  assert.equal(rejected.status, 403);
  assert.match(await rejected.text(), /返回 ChatGPT 重新发起/);
  const response = await refresh(token.refresh_token, running);
  assert.equal(response.status, 200);
  const replacement = await response.json();
  assert.notEqual(replacement.refresh_token, token.refresh_token);
  // A fresh browser can complete a new login and consent after the failed old form.
  assert.ok((await tokens(running)).refresh_token);
  // Consumed-token state also survives the next process restart.
  await running.stop();
  running = await launchRealServer(t, { MCP_OAUTH_DB_PATH: database });
  assert.equal((await refresh(token.refresh_token, running)).status, 400);
  assert.equal((await refresh(replacement.refresh_token, running)).status, 400);
});
test('real MCP: OAuth -> initialize -> tools/list -> read-only tool; backend credential remains separate', async (t) => {
  let backendCalls = 0, badBackendCredential = false;
  const backend = createServer((req, res) => {
    backendCalls++;
    if (req.headers['x-auth-token'] !== env.LINJIAN_TOKEN) badBackendCredential = true;
    res.setHeader('content-type', 'application/json'); res.end(JSON.stringify({ ok: true }));
  });
  backend.listen(0, '127.0.0.1'); await once(backend, 'listening');
  t.after(() => new Promise((resolve) => backend.close(resolve)));
  const request = await launchRealServer(t, { LINJIAN_URL: `http://127.0.0.1:${backend.address().port}` });
  const health = await (await request('/health')).json(); assert.deepEqual(health, { ok: true, service: 'linjian-private-mcp' });
  assert.equal((await request('/mcp', { method: 'OPTIONS' })).status, 204, 'CORS preflight can succeed without granting tool access');
  for (const route of ['/mcp', '/mcp-wallet', '/sse', '/messages?sessionId=anything']) assert.equal((await request(route, { method: 'POST' })).status, 401);
  assert.equal(backendCalls, 0, 'Anonymous requests never reach backend');
  const token = await tokens(request);
  async function rpc(route, method, params, id) {
    const response = await request(route, { method: 'POST', headers: { authorization: `Bearer ${token.access_token}`, 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
      body: JSON.stringify({ jsonrpc: '2.0', id, method, params }) });
    assert.equal(response.status, 200); const text = await response.text();
    const result = response.headers.get('content-type').includes('text/event-stream') ? JSON.parse(text.split('\n').find((line) => line.startsWith('data: ')).slice(6)) : JSON.parse(text);
    assert.equal(result.error, undefined); return result.result;
  }
  const initialized = await rpc('/mcp', 'initialize', { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 'oauth-integration-test', version: '1' } }, 1);
  assert.ok(initialized.serverInfo);
  const list = await rpc('/mcp', 'tools/list', {}, 2); assert.ok(list.tools.some((x) => x.name === 'linjian_status'));
  const result = await rpc('/mcp', 'tools/call', { name: 'linjian_status', arguments: {} }, 3); assert.notEqual(result.isError, true);
  assert.ok(backendCalls > 0); assert.equal(badBackendCredential, false);
  assert.ok(!JSON.stringify(result).includes(env.LINJIAN_TOKEN));
  const wallet = await rpc('/mcp-wallet', 'tools/list', {}, 4); assert.ok(wallet.tools.length);
  assert.equal((await request('/sse', { headers: { authorization: `Bearer ${token.access_token}` } })).status, 410);
  assert.equal((await request('/messages', { method: 'POST', headers: { authorization: `Bearer ${token.access_token}` } })).status, 410);
});
test('real MCP remains closed when OAuth configuration is missing', async (t) => {
  const request = await launchRealServer(t, { MCP_OWNER_SECRET: '' });
  assert.equal((await request('/health')).status, 200);
  for (const route of ['/mcp', '/mcp-wallet', '/sse', '/messages']) assert.equal((await request(route, { method: 'POST' })).status, 503);
});
test('repeated invalid owner authentication is rate limited', async () => {
  const request = browser(); const { params } = authParams();
  const start = await request(`/auth?${new URLSearchParams(params)}`);
  const url = start.headers.get('location');
  let status;
  for (let i = 0; i < 11; i++) status = (await request(url, form({ csrf: 'invalid', decision: 'allow', password: 'invalid' }))).status;
  assert.equal(status, 429);
});
