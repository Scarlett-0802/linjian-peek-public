import { test } from 'node:test';
import assert from 'node:assert/strict';
import { BrowserCookieJar } from './browser-cookie-jar.js';

test('cookie identity includes Name, Domain, Path; specific paths sort first', async () => {
  const jar = new BrowserCookieJar();
  const origin = 'https://auth.example.test';
  await jar.store(origin, ['item=root; Path=/; Secure; SameSite=Lax',
    'item=interaction; Path=/interaction/new; Secure; SameSite=Lax',
    'item=old; Path=/interaction/old; Secure; SameSite=Lax',
    'domain=shared; Domain=example.test; Path=/', 'invalid=x; Domain=evil.test']);
  assert.equal(await jar.header(origin + '/interaction/new'), 'item=interaction; item=root; domain=shared');
  assert.equal(await jar.header(origin + '/interaction/new-other'), 'item=root; domain=shared');
  assert.equal(await jar.header('https://other.example.test/'), 'domain=shared');
  await jar.store(origin, ['item=; Path=/interaction/new; Max-Age=0']);
  assert.equal(await jar.header(origin + '/interaction/new'), 'item=root; domain=shared');
  assert.match(await jar.header(origin + '/interaction/old'), /item=old/);
});

test('Secure and SameSite=Lax honor logical HTTPS and navigation context', async () => {
  const jar = new BrowserCookieJar();
  await jar.store('https://auth.example.test', ['s=value; Secure; SameSite=Lax; Path=/']);
  assert.equal(await jar.header('http://auth.example.test/'), '');
  assert.equal(await jar.header('https://auth.example.test/', { method: 'POST' }), 's=value');
  assert.equal(await jar.header('https://auth.example.test/', { sameSite: false, method: 'GET' }), 's=value');
  assert.equal(await jar.header('https://auth.example.test/', { sameSite: false, method: 'POST' }), '');
  assert.equal(await jar.header('https://auth.example.test/', { sameSite: false, topLevel: false }), '');
});

test('Max-Age / Expires and session-cookie lifetimes are respected', async (t) => {
  t.mock.timers.enable({ apis: ['Date'], now: Date.now() });
  const jar = new BrowserCookieJar(), url = 'https://auth.example.test/';
  await jar.store(url, ['age=a; Max-Age=1; Expires=Thu, 01 Jan 2099 00:00:00 GMT',
    `expiry=e; Expires=${new Date(Date.now() + 1000).toUTCString()}`, 'session=s']);
  assert.match(await jar.header(url), /age=a/);
  t.mock.timers.tick(2000);
  assert.equal(await jar.header(url), 'session=s');
});
