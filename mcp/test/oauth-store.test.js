import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createOAuthStore, OAuthStorageError } from '../oauth-store.js';
import { libsqlFixture } from './libsql-fixture.js';

async function setup(t, options) {
  const remote = await libsqlFixture();
  const first = createOAuthStore(remote.config, 'unit', options);
  const second = createOAuthStore(remote.config, 'unit', options);
  t.after(async () => { first.close(); second.close(); await remote.close(); });
  return { remote, first, second };
}

test('two independent HTTP clients consume each AuthorizationCode / RefreshToken exactly once', async (t) => {
  const { remote, first, second } = await setup(t);
  for (const model of ['AuthorizationCode', 'RefreshToken']) {
    const a = new first.adapter(model), b = new second.adapter(model);
    await a.upsert('same-token', { grantId: 'grant' }, 60);
    const results = await Promise.allSettled(Array.from({ length: 20 }, (_, index) =>
      (index % 2 ? a : b).consume('same-token')));
    assert.equal(results.filter((r) => r.status === 'fulfilled').length, 1);
    for (const r of results.filter((r) => r.status === 'rejected')) assert.equal(r.reason.error, 'invalid_grant');
    assert.ok((await b.find('same-token')).consumed);
  }
  assert.equal(remote.state.consumes, 40);
  assert.equal(remote.state.bareReads, 0, 'Token validation must use primary-routed write transactions');
  assert.ok(remote.state.primaryReads > 0);
});

test('parameterized values and indexes preserve artifact semantics and namespace isolation', async (t) => {
  const { first, remote } = await setup(t);
  const model = "Session' OR 1=1 --", id = "id'); DROP TABLE artifacts; --";
  const adapter = new first.adapter(model);
  const payload = { uid: "主人'😀", userCode: 'abc', grantId: "g'", note: '中文' };
  await adapter.upsert(id, payload, 60);
  assert.deepEqual(await adapter.find(id), payload);
  assert.deepEqual(await adapter.findByUid(payload.uid), payload);
  assert.deepEqual(await adapter.findByUserCode('abc'), payload);
  const isolated = createOAuthStore(remote.config, 'other');
  try { assert.equal(await new isolated.adapter(model).find(id), undefined); } finally { isolated.close(); }
  await adapter.revokeByGrantId(payload.grantId);
  assert.equal(await adapter.find(id), undefined);
  await adapter.upsert('expired', {}, -1);
  assert.equal(await adapter.find('expired'), undefined);
});

test('database unavailable during initialization fails closed and recovers on a new call', async (t) => {
  const { remote, first } = await setup(t);
  const adapter = new first.adapter('AccessToken');
  remote.state.mode = 'offline';
  await assert.rejects(adapter.find('absent'), OAuthStorageError);
  assert.equal(remote.state.requests, 1, 'No retry on failed initialization request');
  remote.state.mode = 'online';
  await adapter.upsert('new', { scope: 'phone:control' }, 60);
  assert.equal((await adapter.find('new')).scope, 'phone:control');
});

test('network disconnect and timeout fail closed; client recovers without restart', async (t) => {
  const { remote, first } = await setup(t, { timeoutMs: 300 });
  const adapter = new first.adapter('AccessToken');
  await adapter.upsert('token', {}, 60);
  for (const mode of ['disconnect', 'timeout', 'body-timeout']) {
    remote.state.mode = mode;
    const before = remote.state.requests;
    const started = performance.now();
    await assert.rejects(adapter.find('token'), OAuthStorageError);
    assert.ok(performance.now() - started < 2000);
    assert.equal(remote.state.requests - before, 1, 'Do not replay the HTTP request');
    remote.state.mode = 'online';
    assert.deepEqual(await adapter.find('token'), {});
  }
});

test('lost acknowledgement after committed consume is never retried or reported successful', async (t) => {
  const { remote, first, second } = await setup(t);
  const a = new first.adapter('RefreshToken'), b = new second.adapter('RefreshToken');
  await a.upsert('token', {}, 60);
  remote.state.mode = 'drop-after-consume';
  await assert.rejects(a.consume('token'), OAuthStorageError);
  assert.equal(remote.state.consumes, 1);
  remote.state.mode = 'online';
  assert.ok((await b.find('token')).consumed);
  await assert.rejects(b.consume('token'), (error) => error.error === 'invalid_grant');
});
