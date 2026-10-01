import { CookieJar } from 'tough-cookie';

// Browser-cookie semantics for HTTP integration tests; transport stays loopback.
// Navigation context is explicit, not inferred from the network transport URL.
export class BrowserCookieJar {
  constructor() { this.jar = new CookieJar(undefined, { allowSecureOnLocal: false }); }
  async store(url, lines) {
    for (const line of lines) await this.jar.setCookie(line, url, { ignoreError: true });
  }
  async header(url, { sameSite = true, topLevel = true, method = 'GET' } = {}) {
    const sameSiteContext = sameSite ? 'strict' : topLevel && ['GET', 'HEAD'].includes(method) ? 'lax' : 'none';
    return this.jar.getCookieString(url, { sameSiteContext });
  }
}
