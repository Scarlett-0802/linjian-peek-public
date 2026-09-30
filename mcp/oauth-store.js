import { createClient } from '@libsql/client/http';
import { errors } from 'oidc-provider';

export class OAuthStorageError extends Error {
  constructor() { super('OAuth storage temporarily unavailable'); }
}

export function readStoreConfig(env) {
  let url;
  try { url = new URL(env.TURSO_DATABASE_URL); } catch { throw new Error('Configure Turso database URL'); }
  const testLoopback = env.NODE_ENV === 'test' && env.RENDER !== 'true' &&
    url.protocol === 'http:' && url.hostname === '127.0.0.1';
  if ((!testLoopback && !['libsql:', 'https:'].includes(url.protocol)) ||
      url.username || url.password || url.search || url.hash || !['', '/'].includes(url.pathname) ||
      typeof env.TURSO_AUTH_TOKEN !== 'string' || !env.TURSO_AUTH_TOKEN.trim()) {
    throw new Error('Configure remote TLS libSQL URL and database credential');
  }
  // Force HTTPS rather than WebSocket transport. No local replicas or syncUrl.
  return { url: url.href.replace(/^libsql:/, 'https:'), authToken: env.TURSO_AUTH_TOKEN };
}

// Remote authoritative state. No application/SDK retry of SQL operations.
// A timed-out write may have committed: return failure, never resubmit it.
export function createOAuthStore(config, namespace, { timeoutMs = 5000 } = {}) {
  const origin = new URL(config.url).origin;
  const client = createClient({ url: config.url, authToken: config.authToken, fetch: async (input, init) => {
    const request = new Request(input, init);
    if (new URL(request.url).origin !== origin) throw new OAuthStorageError();
    const response = await fetch(request, { redirect: 'error',
      signal: AbortSignal.any([request.signal, AbortSignal.timeout(timeoutMs)]) });
    // Include body delivery in the deadline, not just receipt of response headers.
    const body = await response.arrayBuffer();
    return new Response(response.status === 204 ? null : body,
      { status: response.status, headers: response.headers });
  } });
  const raw = async (sql, args = []) => {
    try {
      // libSQL write transactions route to the primary, including their SELECTs.
      // Never validate a grant/token against a potentially lagging read replica.
      if (sql.startsWith('SELECT')) return (await client.batch([{ sql, args }], 'write'))[0];
      return await client.execute({ sql, args });
    }
    catch { throw new OAuthStorageError(); } // Never expose SQL, credentials or token payloads.
  };
  let initialized;
  const initialize = () => initialized ||= (async () => {
    await raw(`CREATE TABLE IF NOT EXISTS artifacts (
      namespace TEXT NOT NULL, model TEXT NOT NULL, id TEXT NOT NULL,
      payload TEXT NOT NULL, expires INTEGER NOT NULL,
      PRIMARY KEY(namespace, model, id)
    )`);
    await raw('CREATE INDEX IF NOT EXISTS artifacts_expires ON artifacts(expires)');
  })().catch((error) => { initialized = undefined; throw error; });
  const execute = async (sql, args) => { await initialize(); return raw(sql, args); };
  const now = () => Math.floor(Date.now() / 1000);
  const read = (result) => result.rows[0] ? JSON.parse(result.rows[0].payload) : undefined;
  class Adapter {
    constructor(model) { this.model = model; }
    async upsert(id, payload, expiresIn) {
      await execute('DELETE FROM artifacts WHERE expires <= ?', [now()]);
      await execute('INSERT OR REPLACE INTO artifacts VALUES (?, ?, ?, ?, ?)',
        [namespace, this.model, id, JSON.stringify(payload), now() + expiresIn]);
    }
    async find(id) {
      return read(await execute('SELECT payload FROM artifacts WHERE namespace=? AND model=? AND id=? AND expires>?',
        [namespace, this.model, id, now()]));
    }
    async findByUid(uid) {
      return read(await execute("SELECT payload FROM artifacts WHERE namespace=? AND model=? AND json_extract(payload, '$.uid')=? AND expires>?",
        [namespace, this.model, uid, now()]));
    }
    async findByUserCode(code) {
      return read(await execute("SELECT payload FROM artifacts WHERE namespace=? AND model=? AND json_extract(payload, '$.userCode')=? AND expires>?",
        [namespace, this.model, code, now()]));
    }
    async destroy(id) {
      await execute('DELETE FROM artifacts WHERE namespace=? AND model=? AND id=?', [namespace, this.model, id]);
    }
    async consume(id) {
      // The database performs compare-and-set atomically, including across clients.
      const result = await execute(`UPDATE artifacts SET payload=json_set(payload, '$.consumed', ?)
        WHERE namespace=? AND model=? AND id=? AND expires>?
        AND json_extract(payload, '$.consumed') IS NULL`, [now(), namespace, this.model, id, now()]);
      if (result.rowsAffected !== 1) throw new errors.InvalidGrant('Credential already consumed or expired');
    }
    async revokeByGrantId(grantId) {
      await execute("DELETE FROM artifacts WHERE namespace=? AND json_extract(payload, '$.grantId')=?", [namespace, grantId]);
    }
  }
  return { adapter: Adapter, close: () => client.close() };
}
