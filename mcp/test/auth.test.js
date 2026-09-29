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
import { installAuth, readAuthConfig, MCP_SCOPE } from '../auth.js';
import { createOAuthStore } from '../oauth-store.js';

// Ephemeral test-only credentials. None are printed or written into tracked files.
const secret = () => randomBytes(32).toString('base64url');
const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const key = { ...privateKey.export({ format: 'jwk' }), kid: 'ephemeral-test-key', use: 'sig', alg: 'RS256' };
const issuer = 'https://mcp.example.test';
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
    const headers = { host: 'mcp.example.test', 'x-forwarded-proto': 'https', ...init.headers };
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
  t.after(async () => { if (child.exitCode === null) { const exited = once(child, 'exit'); child.kill(); await exited; } });
  const childBase = `http://127.0.0.1:${port}`;
  let ready = false;
  for (let i = 0; i < 100; i++) {
    try { if ((await fetch(childBase + '/health')).ok) { ready = true; break; } } catch {}
    await new Promise((resolve) => setTimeout(resolve, 30));
  }
  assert.ok(ready, 'Real MCP process must become ready');
  return browser(() => childBase);
}
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
