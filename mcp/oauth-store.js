import { DatabaseSync } from 'node:sqlite';
import { mkdirSync, chmodSync } from 'node:fs';
import path from 'node:path';
import { errors } from 'oidc-provider';

// Single-instance adapter. OAuth state is runtime data, never source/configuration.
// In Render, filename must reside on the configured persistent disk (see render.yaml).
export function createOAuthStore(filename, namespace) {
  if (filename !== ':memory:') mkdirSync(path.dirname(filename), { recursive: true, mode: 0o700 });
  const db = new DatabaseSync(filename);
  if (filename !== ':memory:' && process.platform !== 'win32') chmodSync(filename, 0o600);
  db.exec(`CREATE TABLE IF NOT EXISTS artifacts (
    namespace TEXT NOT NULL, model TEXT NOT NULL, id TEXT NOT NULL,
    payload TEXT NOT NULL, expires INTEGER NOT NULL,
    PRIMARY KEY(namespace, model, id)
  )`);
  const now = () => Math.floor(Date.now() / 1000);
  const clean = db.prepare('DELETE FROM artifacts WHERE expires <= ?');
  const read = (row) => row ? JSON.parse(row.payload) : undefined;
  class Adapter {
    constructor(model) { this.model = model; }
    async upsert(id, payload, expiresIn) {
      clean.run(now());
      db.prepare('INSERT OR REPLACE INTO artifacts VALUES (?, ?, ?, ?, ?)')
        .run(namespace, this.model, id, JSON.stringify(payload), now() + expiresIn);
    }
    async find(id) {
      return read(db.prepare('SELECT payload FROM artifacts WHERE namespace=? AND model=? AND id=? AND expires>?')
        .get(namespace, this.model, id, now()));
    }
    async findByUid(uid) {
      return read(db.prepare("SELECT payload FROM artifacts WHERE namespace=? AND model=? AND json_extract(payload, '$.uid')=? AND expires>?")
        .get(namespace, this.model, uid, now()));
    }
    async findByUserCode(code) {
      return read(db.prepare("SELECT payload FROM artifacts WHERE namespace=? AND model=? AND json_extract(payload, '$.userCode')=? AND expires>?")
        .get(namespace, this.model, code, now()));
    }
    async destroy(id) {
      db.prepare('DELETE FROM artifacts WHERE namespace=? AND model=? AND id=?').run(namespace, this.model, id);
    }
    async consume(id) {
      // Atomic compare-and-set: two simultaneous code exchanges cannot both succeed.
      const result = db.prepare(`UPDATE artifacts SET payload=json_set(payload, '$.consumed', ?)
        WHERE namespace=? AND model=? AND id=? AND expires>?
        AND json_extract(payload, '$.consumed') IS NULL`).run(now(), namespace, this.model, id, now());
      if (result.changes !== 1) throw new errors.InvalidGrant('Credential already consumed or expired');
    }
    async revokeByGrantId(grantId) {
      db.prepare("DELETE FROM artifacts WHERE namespace=? AND json_extract(payload, '$.grantId')=?")
        .run(namespace, grantId);
    }
  }
  return { adapter: Adapter, close: () => db.close() };
}
