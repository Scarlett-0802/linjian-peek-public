import express from 'express';
import Provider, { errors } from 'oidc-provider';
import { rateLimit } from 'express-rate-limit';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { createOAuthStore, readStoreConfig, OAuthStorageError } from './oauth-store.js';

export const MCP_SCOPE = 'phone:control';
export const AUTHORIZATION_TTL = 90 * 24 * 60 * 60;
const OWNER = 'owner';
const CLIENT_ID = 'zhangxinchuang-chatgpt';
const diagnosticBoot = { process_start_id: randomBytes(8).toString('hex'), process_started_at: new Date().toISOString() };
const diagnosticStages = new Set(['process_start', 'interaction_get_enter', 'interaction_post_enter',
  'interaction_details_ok', 'interaction_details_failed', 'interaction_finished_failed',
  'login_post_details_ok', 'password_verified', 'login_finished_before', 'login_finished_after',
  'consent_get_enter', 'consent_details_ok', 'provider_interaction_started', 'provider_interaction_ended',
  'provider_authorization_error', 'restart_authorization']);
const diagnosticReasons = new Set(['session_not_found', 'uid_mismatch', 'csrf_missing', 'csrf_expired', 'csrf_mismatch']);
const diagnosticPrompts = new Map();
const uidFingerprint = (uid) => typeof uid === 'string'
  ? createHash('sha256').update(uid).digest('hex').slice(0, 16) : null;
// Strict whitelist: never serialize request, provider objects, errors or their messages.
function diagnostic(stage, uid, details, { error, reason, session = 'unknown', grant = 'unknown' } = {}) {
  try {
    if (!diagnosticStages.has(stage)) return;
    const uidFp = uidFingerprint(uid);
    const prompt = ['login', 'consent'].includes(details?.prompt?.name)
      ? details.prompt.name : diagnosticPrompts.get(uidFp) || 'unknown';
    const candidateErrorClass = error?.constructor?.name;
    const errorClass = typeof candidateErrorClass === 'string' && /^[A-Za-z][A-Za-z0-9]{0,63}$/.test(candidateErrorClass)
      ? candidateErrorClass : error ? 'Error' : null;
    console.info('[oauth_browser]', JSON.stringify({ ...diagnosticBoot, stage,
      uid_fp: uidFp, prompt,
      session_exists: typeof session === 'boolean' ? session : 'unknown',
      grant_exists: typeof grant === 'boolean' ? grant : 'unknown',
      error_class: errorClass,
      restart: stage === 'restart_authorization', reason: diagnosticReasons.has(reason) ? reason : null,
    }));
  } catch { /* Diagnostics must never change authorization behavior. */ }
}
diagnostic('process_start');
const digest = (value) => createHash('sha256').update(value).digest();
const same = (a, b) => typeof a === 'string' && typeof b === 'string' && timingSafeEqual(digest(a), digest(b));
const escape = (value) => String(value).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch((error) => {
  if (error instanceof OAuthStorageError && !res.headersSent) {
    return res.status(503).json({ error: 'oauth_storage_unavailable' });
  }
  next(error);
});

export function readAuthConfig(env = process.env) {
  const issuer = new URL(env.MCP_PUBLIC_URL || env.RENDER_EXTERNAL_URL || '');
  if (issuer.protocol !== 'https:' || issuer.username || issuer.password || issuer.search || issuer.hash || issuer.pathname !== '/') {
    throw new Error('MCP public URL must be an HTTPS origin');
  }
  const ownerSecret = env.MCP_OWNER_SECRET;
  const cookieSecret = env.MCP_COOKIE_SECRET;
  const clientSecret = env.MCP_CLIENT_SECRET;
  const secrets = [ownerSecret, cookieSecret, clientSecret];
  if (secrets.some((s) => typeof s !== 'string' || s.length < 32) || new Set(secrets).size !== 3 || secrets.includes(env.LINJIAN_TOKEN)) {
    throw new Error('Configure distinct OAuth secrets (at least 32 characters)');
  }
  const redirectUris = JSON.parse(env.MCP_OAUTH_REDIRECT_URIS || '[]');
  if (!Array.isArray(redirectUris) || redirectUris.length !== 1 || typeof redirectUris[0] !== 'string') {
    throw new Error('Configure exactly one ChatGPT redirect URI');
  }
  const redirect = new URL(redirectUris[0]);
  if (redirect.origin !== 'https://chatgpt.com' || redirect.username || redirect.password || redirect.search || redirect.hash ||
      !(/^\/connector_platform_oauth_redirect$|^\/connector\/oauth\/[A-Za-z0-9_-]+$/).test(redirect.pathname) || redirect.href !== redirectUris[0]) {
    throw new Error('Invalid ChatGPT redirect URI');
  }
  const jwks = JSON.parse(env.MCP_OAUTH_JWKS || '{}');
  if (!Array.isArray(jwks.keys) || !jwks.keys.length || jwks.keys.some((key) => !key.d || !key.kid)) {
    throw new Error('Configure a private signing JWKS');
  }
  return { issuer: issuer.origin, ownerSecret, cookieSecret, clientSecret, redirectUris, jwks,
    store: readStoreConfig(env) };
}

export function installAuth(app, config) {
  const { issuer, ownerSecret, cookieSecret, clientSecret, redirectUris, jwks } = config;
  // One canonical resource covers both MCP tool sets. Never derive it from a request Host header.
  const resource = `${issuer}/mcp`;
  const metadataUrl = `${issuer}/.well-known/oauth-protected-resource`;
  // Rotating any configured credential invalidates old grants, sessions and tokens.
  const namespace = digest(JSON.stringify([issuer, ownerSecret, cookieSecret, clientSecret, redirectUris, jwks])).toString('hex');
  const store = createOAuthStore(config.store, namespace);
  const provider = new Provider(issuer, {
    adapter: store.adapter,
    clients: [{ client_id: CLIENT_ID, client_secret: clientSecret, client_name: 'ChatGPT · 掌心窗',
      redirect_uris: redirectUris, response_types: ['code'], grant_types: ['authorization_code', 'refresh_token'],
      token_endpoint_auth_method: 'client_secret_post' }],
    jwks,
    cookies: { keys: [cookieSecret], long: { secure: true, httpOnly: true, sameSite: 'lax' }, short: { secure: true, httpOnly: true, sameSite: 'lax' } },
    responseTypes: ['code'],
    clientAuthMethods: ['client_secret_post'],
    clockTolerance: 0,
    scopes: [MCP_SCOPE],
    clientBasedCORS: () => false, // ChatGPT exchanges codes server-to-server.
    pkce: { required: () => true },
    features: {
      devInteractions: { enabled: false }, registration: { enabled: false },
      userinfo: { enabled: false }, revocation: { enabled: true,
        allowedPolicy: (_ctx, client, token) => client.clientId === CLIENT_ID && token.clientId === CLIENT_ID },
      resourceIndicators: { enabled: true,
        defaultResource: () => resource,
        useGrantedResource: () => true,
        getResourceServerInfo: (_ctx, target) => {
          if (target !== resource) throw new errors.InvalidTarget();
          return { scope: MCP_SCOPE, audience: resource, accessTokenTTL: 600, accessTokenFormat: 'opaque' };
        } },
    },
    ttl: { AuthorizationCode: 60, AccessToken: 600, Interaction: 300, Session: 3600,
      Grant: AUTHORIZATION_TTL,
      // Rotation must not extend the original authorization's absolute lifetime.
      RefreshToken: (ctx, token) => Math.max(0, Math.min(AUTHORIZATION_TTL - token.totalLifetime(),
        ctx.oidc.entities.Grant.remainingTTL)) },
    issueRefreshToken: (_ctx, client) => client.grantTypeAllowed('refresh_token'),
    // Explicit owner consent authorizes this private client beyond the browser login.
    // oidc-provider 9.12.2 otherwise binds phone:control tokens to the login session.
    expiresWithSession: (_ctx, source) => source.clientId !== CLIENT_ID,
    rotateRefreshToken: true,
    findAccount: (_ctx, id) => id === OWNER ? { accountId: OWNER, claims: () => ({ sub: OWNER }) } : undefined,
    interactions: { url: (_ctx, interaction) => `/interaction/${interaction.uid}` },
    renderError: (ctx) => { ctx.type = 'text/plain'; ctx.body = 'Authorization request rejected. Please restart the connection in ChatGPT.'; },
  });
  provider.proxy = true; // Render terminates HTTPS before forwarding to this process.
  // Do not log provider error objects: they may contain request or credential details.
  provider.on('server_error', () => console.error('OAuth server error'));
  for (const [event, stage] of [['interaction.started', 'provider_interaction_started'],
    ['interaction.ended', 'provider_interaction_ended'], ['authorization.error', 'provider_authorization_error']]) {
    provider.on(event, (ctx, error) => {
      const interaction = ctx?.oidc?.entities?.Interaction;
      const uidFp = uidFingerprint(interaction?.uid);
      if (event === 'interaction.started' && uidFp && ['login', 'consent'].includes(interaction?.prompt?.name)) {
        if (diagnosticPrompts.size >= 1000) diagnosticPrompts.clear();
        diagnosticPrompts.set(uidFp, interaction.prompt.name);
      }
      diagnostic(stage, interaction?.uid, interaction, { error: event === 'authorization.error' ? error : undefined });
      if (event === 'interaction.ended' && uidFp) diagnosticPrompts.delete(uidFp);
    });
  }

  const challenge = (res, status = 401) => res.status(status).set({
    'WWW-Authenticate': `Bearer resource_metadata="${metadataUrl}", scope="${MCP_SCOPE}"`,
    'Cache-Control': 'no-store',
  }).json({ error: status === 403 ? 'insufficient_scope' : 'invalid_token' });

  const requireAuth = wrap(async (req, res, next) => {
    // No query-string tokens, cookies or backend LINJIAN_TOKEN accepted here.
    const header = req.headers.authorization;
    if (typeof header !== 'string' || !/^Bearer [A-Za-z0-9._~-]+$/i.test(header) || header.length > 4096) return challenge(res);
    const token = await provider.AccessToken.find(header.slice(7));
    const grant = token?.grantId && await provider.Grant.find(token.grantId);
    if (!token || token.isExpired || !grant || grant.isExpired || token.accountId !== OWNER || token.clientId !== CLIENT_ID ||
        token.aud !== resource || token.tokenType !== 'Bearer') return challenge(res);
    if (!token.scope?.split(' ').includes(MCP_SCOPE)) return challenge(res, 403);
    req.auth = { accountId: OWNER, clientId: CLIENT_ID };
    next();
  });

  app.use((req, res, next) => {
    res.set({ 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer', 'X-Content-Type-Options': 'nosniff',
      'Content-Security-Policy': "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'" });
    if (req.headers.host !== new URL(issuer).host || !req.secure) return res.status(400).json({ error: 'invalid_origin' });
    req.headers['x-forwarded-host'] = new URL(issuer).host;
    next();
  });
  const metadata = { resource, authorization_servers: [issuer], scopes_supported: [MCP_SCOPE], bearer_methods_supported: ['header'] };
  app.get(['/.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource/mcp', '/.well-known/oauth-protected-resource/mcp-wallet'],
    (_req, res) => res.json(metadata));

  // Install before body parsing and before every MCP handler.
  app.use(['/mcp', '/mcp-wallet', '/sse', '/messages'], requireAuth);
  app.all(['/sse', '/messages'], (_req, res) => res.status(410).json({ error: 'legacy_sse_disabled', endpoint: '/mcp' }));

  const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, skipSuccessfulRequests: true, standardHeaders: 'draft-8', legacyHeaders: false,
    message: { error: 'too_many_login_attempts' } });
  // Global owner limit also bounds distributed password guessing and expensive provider work.
  const ownerLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 30, skipSuccessfulRequests: true, keyGenerator: () => OWNER,
    standardHeaders: 'draft-8', legacyHeaders: false, message: { error: 'too_many_login_attempts' } });
  const csrf = new Map();
  const restartAuthorization = (res, state, reason, status = 400, error) => {
    diagnostic('restart_authorization', state.uid, state.details, { ...state, reason, error });
    return res.status(status).type('html').send(
    '<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>请重新授权</title>' +
    '<h1>授权页面已失效</h1><p>页面已过期、浏览器会话不匹配或服务刚刚重启。' +
    '请关闭此页，返回 ChatGPT 重新发起掌心窗连接授权。不要重复提交旧表单。</p></html>');
  };
  const interactionRoute = (fn) => wrap(async (req, res) => {
    const state = { uid: req.params.uid, details: undefined, phase: 'interaction_details_failed' };
    diagnostic(req.method === 'GET' ? 'interaction_get_enter' : 'interaction_post_enter', state.uid);
    if (req.method === 'GET' && diagnosticPrompts.get(uidFingerprint(state.uid)) === 'consent') {
      diagnostic('consent_get_enter', state.uid);
    }
    try { await fn(req, res, state); }
    catch (error) {
      diagnostic(state.phase, state.uid, state.details, { ...state, error });
      if (error instanceof errors.SessionNotFound) return restartAuthorization(res, state, 'session_not_found', 400, error);
      throw error;
    }
  });
  const interactionDetails = async (req, res, state) => {
    const details = await provider.interactionDetails(req, res);
    state.details = details;
    // interactionDetails verified a referenced Session via findByUid. Grant IDs
    // alone do not establish existence; do not add DB reads just for logging.
    state.session = !!details.session?.uid;
    state.grant = details.grantId ? 'unknown' : false;
    state.phase = 'interaction_finished_failed';
    diagnostic('interaction_details_ok', state.uid, details, state);
    if (details.prompt.name === 'login' && req.method === 'POST') diagnostic('login_post_details_ok', state.uid, details, state);
    if (details.prompt.name === 'consent') {
      diagnostic('consent_details_ok', state.uid, details, state);
    }
    return details;
  };
  const prune = () => { for (const [key, value] of csrf) if (value.expires < Date.now()) csrf.delete(key); };
  app.get('/interaction/:uid', interactionRoute(async (req, res, state) => {
    const details = await interactionDetails(req, res, state);
    if (details.uid !== req.params.uid) return restartAuthorization(res, state, 'uid_mismatch');
    if (!['login', 'consent'].includes(details.prompt.name)) return res.status(400).send('Unsupported authorization request');
    prune();
    if (csrf.size >= 1000) return res.status(503).send('Please try again later');
    const nonce = randomBytes(32).toString('base64url');
    csrf.set(details.uid, { nonce, expires: Date.now() + 300000 });
    const login = details.prompt.name === 'login';
    // no-referrer makes browsers send Origin: null on native form POSTs.
    // Keep same-origin form origins while suppressing cross-origin referrers.
    // The strict Origin comparison and one-time CSRF nonce below remain required.
    res.set('Referrer-Policy', 'same-origin').type('html').send(`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>掌心窗授权</title>
      <h1>允许 ChatGPT 访问你的掌心窗？</h1><p>授权后可读取手机屏幕与状态、点击、输入及使用掌心窗工具。仅为你自己的 ChatGPT 连接授权。</p>
      <form method="post" action="/interaction/${escape(details.uid)}"><input type="hidden" name="csrf" value="${nonce}">
      ${login ? '<label>掌心窗专用登录密钥（不是手机 Token）<input name="password" type="password" autocomplete="current-password" required maxlength="1024"></label>' : '<p>你已登录为设备主人。</p>'}
      <button name="decision" value="allow">${login ? '登录并继续' : '允许访问'}</button><button name="decision" value="deny" formnovalidate>取消</button></form></html>`);
  }));
  app.post('/interaction/:uid', loginLimiter, ownerLimiter, express.urlencoded({ extended: false, limit: '4kb' }), interactionRoute(async (req, res, state) => {
    if (req.headers.origin !== issuer) return res.status(403).send('Invalid form origin');
    const details = await interactionDetails(req, res, state);
    if (details.uid !== req.params.uid) return restartAuthorization(res, state, 'uid_mismatch');
    const entry = csrf.get(details.uid);
    if (!entry || entry.expires < Date.now() || !same(req.body.csrf, entry.nonce)) {
      const reason = !entry || !req.body.csrf ? 'csrf_missing' : entry.expires < Date.now() ? 'csrf_expired' : 'csrf_mismatch';
      return restartAuthorization(res, state, reason, 403);
    }
    csrf.delete(details.uid);
    if (req.body.decision === 'deny') return provider.interactionFinished(req, res, { error: 'access_denied' }, { mergeWithLastSubmission: false });
    if (req.body.decision !== 'allow') return res.status(400).send('Invalid decision');
    if (details.prompt.name === 'login') {
      if (!same(req.body.password, ownerSecret)) return res.status(401).send('Login failed. Reopen the authorization page to retry.');
      diagnostic('password_verified', state.uid, details, state);
      diagnostic('login_finished_before', state.uid, details, state);
      const result = await provider.interactionFinished(req, res, { login: { accountId: OWNER, remember: false } }, { mergeWithLastSubmission: false });
      diagnostic('login_finished_after', state.uid, details, state);
      return result;
    }
    if (details.prompt.name !== 'consent' || details.session?.accountId !== OWNER || details.params.client_id !== CLIENT_ID) return res.status(403).send('Authorization denied');
    const grant = details.grantId ? await provider.Grant.find(details.grantId) : new provider.Grant({ accountId: OWNER, clientId: CLIENT_ID });
    if (!grant || grant.accountId !== OWNER || grant.clientId !== CLIENT_ID) return res.status(400).send('Restart authorization');
    const { missingOIDCScope, missingOIDCClaims, missingResourceScopes } = details.prompt.details;
    if (missingOIDCScope?.length) grant.addOIDCScope(missingOIDCScope.join(' '));
    if (missingOIDCClaims?.length) grant.addOIDCClaims(missingOIDCClaims);
    for (const [target, scopes] of Object.entries(missingResourceScopes || {})) {
      if (target !== resource || scopes.some((s) => s !== MCP_SCOPE)) return res.status(403).send('Unsupported permission');
      grant.addResourceScope(target, scopes.join(' '));
    }
    return provider.interactionFinished(req, res, { consent: { grantId: await grant.save() } }, { mergeWithLastSubmission: true });
  }));
  // Mount provider only on its own paths, before Express consumes its request bodies.
  const oauthHandler = provider.callback();
  const oauthLimiter = rateLimit({ windowMs: 60 * 1000, limit: 120, keyGenerator: () => 'oauth',
    standardHeaders: 'draft-8', legacyHeaders: false, message: { error: 'too_many_oauth_requests' } });
  app.use(['/auth', '/token'], oauthLimiter);
  app.use((req, res, next) => {
    const roots = ['/.well-known/oauth-authorization-server', '/.well-known/openid-configuration', '/auth', '/token', '/jwks', '/session'];
    if (roots.some((root) => req.path === root || req.path.startsWith(root + '/'))) return oauthHandler(req, res);
    next();
  });
  return { provider, close: store.close };
}

export function installConfiguredAuth(app, env = process.env) {
  app.set('trust proxy', 1);
  try { return installAuth(app, readAuthConfig(env)); }
  catch {
    // Initial Render setup may not yet have its signing key / callback. Never serve tools anonymously.
    console.error('OAuth configuration incomplete or invalid; protected endpoints are unavailable');
    app.use((_req, res) => res.status(503).json({ error: 'oauth_not_configured' }));
    return null;
  }
}
