import { createServer } from 'node:http';
import { DatabaseSync } from 'node:sqlite';
import { once } from 'node:events';
import { randomBytes } from 'node:crypto';

// Test-only Hrana v2 HTTP subset. Production uses the official SDK, not this code.
// Executes real SQLite SQL, allowing separate SDK clients and MCP processes to
// share authoritative state without a cloud account or production credentials.
export async function libsqlFixture(filename = ':memory:') {
  const db = new DatabaseSync(filename);
  const authToken = randomBytes(32).toString('base64url');
  const state = { mode: 'online', consumes: 0, requests: 0, primaryReads: 0, bareReads: 0 };
  const decode = (value) => value.type === 'null' ? null : value.type === 'integer' ? Number(value.value) : value.value;
  const encode = (value) => value === null ? { type: 'null' } :
    typeof value === 'number' ? { type: 'integer', value: String(value) } : { type: 'text', value };
  const server = createServer(async (req, res) => {
    if (req.headers.authorization !== `Bearer ${authToken}`) { res.writeHead(401).end(); return; }
    if (req.url !== '/v2/pipeline') { res.writeHead(404).end(); return; }
    state.requests++;
    if (state.mode === 'offline') { res.writeHead(503).end('unavailable'); return; }
    if (state.mode === 'disconnect') { req.socket.destroy(); return; }
    if (state.mode === 'timeout') return;
    if (state.mode === 'body-timeout') {
      res.writeHead(200, { 'content-type': 'application/json' }); res.write('{'); return;
    }
    try {
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      const body = JSON.parse(Buffer.concat(chunks));
      let drop = false;
      let writeTransaction = false;
      const sqlCache = new Map();
      const execute = (input) => {
        const sql = input.sql ?? sqlCache.get(input.sql_id);
        const args = input.args || [];
        if (sql === 'BEGIN IMMEDIATE') writeTransaction = true;
        if (sql.startsWith('SELECT')) state[writeTransaction ? 'primaryReads' : 'bareReads']++;
        const consume = sql.startsWith('UPDATE artifacts SET');
        if (consume) state.consumes++;
        const stmt = db.prepare(sql);
        const columns = stmt.columns();
        let rows = [], changes = 0;
        if (columns.length) rows = stmt.all(...args.map(decode)).map((row) => columns.map((col) => encode(row[col.name])));
        else changes = Number(stmt.run(...args.map(decode)).changes);
        if (consume && state.mode === 'drop-after-consume') drop = true;
        return {
          cols: columns.map((col) => ({ name: col.name, decltype: col.type })), rows,
          affected_row_count: changes, last_insert_rowid: null,
        };
      };
      const results = body.requests.map((operation) => {
        const ok = (response) => ({ type: 'ok', response });
        if (operation.type === 'close') return ok({ type: 'close' });
        if (operation.type === 'store_sql') {
          sqlCache.set(operation.sql_id, operation.sql); return ok({ type: 'store_sql' });
        }
        if (operation.type === 'close_sql') return ok({ type: 'close_sql' });
        if (operation.type === 'execute') return ok({ type: 'execute', result: execute(operation.stmt) });
        if (operation.type !== 'batch') throw new Error('Unsupported fixture operation');
        const step_results = [], step_errors = [];
        const condition = (c) => !c || (c.type === 'ok' ? !!step_results[c.step] :
          c.type === 'not' ? !condition(c.cond) : c.type === 'and' ? c.conds.every(condition) : false);
        for (const step of operation.batch.steps) {
          if (!condition(step.condition)) { step_results.push(null); step_errors.push(null); continue; }
          try { step_results.push(execute(step.stmt)); step_errors.push(null); }
          catch { step_results.push(null); step_errors.push({ message: 'SQL failed', code: 'SQLITE_ERROR' }); }
        }
        return ok({ type: 'batch', result: { step_results, step_errors } });
      });
      // Simulates a committed write whose acknowledgement is lost.
      if (drop) { req.socket.destroy(); return; }
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ baton: null, results }));
    } catch {
      res.writeHead(500).end('fixture request failed');
    }
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const config = { url: `http://127.0.0.1:${server.address().port}`, authToken };
  return { config, state, env: { NODE_ENV: 'test', RENDER: '',
    TURSO_DATABASE_URL: config.url, TURSO_AUTH_TOKEN: authToken },
    close: async () => { server.closeAllConnections(); await new Promise((resolve) => server.close(resolve)); db.close(); } };
}
