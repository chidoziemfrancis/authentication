type Headers = Record<string, string | string[] | undefined>;

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);
const DEFAULT_PORTS: Record<string, string> = { 'http:': '80', 'https:': '443' };

/**
 * Whether a request would change state from another origin. It is the
 * decision `app.enableCsrfProtection()` makes from Nest 12.1 on (after Go's
 * `net/http.CrossOriginProtection`), so the two never disagree:
 *
 * 1. `GET`, `HEAD` and `OPTIONS` never are.
 * 2. With `Sec-Fetch-Site`, anything but `same-origin` and `none` is.
 * 3. Without it, a request with no `Origin` is not: it comes from a
 *    non-browser client.
 * 4. Otherwise `Origin` must name the request's host (`:authority` on
 *    HTTP/2, else `Host`), ignoring case and the scheme's default port.
 *
 * A request whose `Origin` is one of `trusted` never is. A WebSocket
 * handshake (no method here, or a GET with `Upgrade: websocket`) opens a
 * channel that carries writes, so steps 2 to 4 apply to it (cross-site
 * WebSocket hijacking).
 */
export function isCrossOriginWrite(
  request: { headers: Headers; method?: string },
  trusted: ReadonlySet<string>,
): boolean {
  // A GET that upgrades to a WebSocket (graphql-ws hands resolvers its upgrade request) opens a
  // channel that carries writes: a handshake, not a safe request.
  const upgrade = header(request.headers, 'upgrade')?.toLowerCase() === 'websocket';
  if (request.method !== undefined && SAFE_METHODS.has(request.method) && !upgrade) {
    return false;
  }

  const origin = header(request.headers, 'origin');
  const site = header(request.headers, 'sec-fetch-site');
  if (site !== undefined) {
    if (site === 'same-origin' || site === 'none') {
      return false;
    }
    return !(origin !== undefined && trusted.has(origin));
  }

  if (origin === undefined) {
    return false;
  }

  const host = header(request.headers, ':authority') ?? header(request.headers, 'host');
  if (host !== undefined && originMatchesHost(origin, host)) {
    return false;
  }

  return !trusted.has(origin);
}

/**
 * A trusted origin as browsers serialize `Origin`: lower-case scheme and
 * host, no default port. Fails at startup, naming `option`, for anything
 * that is not `scheme://host[:port]`.
 */
export function normalizeOrigin(origin: unknown, option: string): string {
  const fail = (): never => {
    throw new TypeError(
      `${option}: ${JSON.stringify(origin)} is not an origin. Write it as scheme://host[:port], without a path.`,
    );
  };

  if (typeof origin !== 'string' || !/^[a-z][a-z0-9+.-]*:\/\/[^/?#\\*]+$/i.test(origin)) {
    return fail();
  }

  let url: URL;
  try {
    url = new URL(origin);
  } catch {
    return fail();
  }
  if (!url.host || url.username || url.password) {
    fail();
  }

  return `${url.protocol}//${url.host}`;
}

function originMatchesHost(origin: string, host: string): boolean {
  let url: URL;
  try {
    url = new URL(origin); // `null` (sandboxed frames) and non-URLs never match
  } catch {
    return false;
  }
  if (!url.host) {
    return false;
  }

  const authority = host.toLowerCase();
  if (url.host === authority) {
    return true;
  }

  const port = DEFAULT_PORTS[url.protocol];
  return !url.port && port !== undefined && `${url.hostname}:${port}` === authority;
}

/** Repeated headers are joined, so conflicting values never equal `same-origin` or a trusted origin. */
function header(headers: Headers, name: string): string | undefined {
  const value = headers[name];
  return Array.isArray(value) ? value.join(', ') : value;
}
