/**
 * Reads one cookie from a raw `Cookie` header (RFC 6265 §5.4), so neither
 * `cookie-parser` nor `@fastify/cookie` is needed. The first occurrence
 * wins, as browsers send the most specific path first.
 */
export function readCookie(header: string | undefined, name: string): string | undefined {
  if (!header) {
    return undefined;
  }

  for (const pair of header.split(';')) {
    const eq = pair.indexOf('=');
    if (eq === -1) {
      continue;
    }
    if (pair.slice(0, eq).trim() !== name) {
      continue;
    }

    let value = pair.slice(eq + 1).trim();
    if (value.length >= 2 && value.startsWith('"') && value.endsWith('"')) {
      value = value.slice(1, -1);
    }
    try {
      return decodeURIComponent(value);
    } catch {
      return value;
    }
  }

  return undefined;
}

export interface CookieAttributes {
  /** Defaults to `true`. Turn off only for plain-HTTP development on a host other than `localhost`. */
  secure?: boolean;
  /** Defaults to `lax`. */
  sameSite?: 'lax' | 'strict' | 'none';
  /** Defaults to `/`. */
  path?: string;
  domain?: string;
}

/**
 * Whether browsers accept a `__Host-` cookie with these attributes: Secure,
 * `Path=/` and no `Domain`. Such a cookie can only be set by the host
 * itself, so a sibling subdomain cannot plant one (cookie tossing).
 */
export function allowsHostPrefix(attributes: CookieAttributes = {}): boolean {
  return (attributes.secure ?? true) && (attributes.path ?? '/') === '/' && !attributes.domain;
}

/** `__Host-<name>` when the attributes allow it, `<name>` otherwise. */
export function defaultCookieName(name: string, attributes: CookieAttributes = {}): string {
  return allowsHostPrefix(attributes) ? `__Host-${name}` : name;
}

/**
 * Fails at startup on a cookie browsers would silently drop: a prefixed name
 * its attributes break, or `SameSite=None` without `Secure` (rejected by
 * every browser: the cookie is never stored, so every sign-in looks like it
 * worked and nothing stays signed in). `option` is the options object the
 * message names (`session`).
 */
export function assertCookieAttributes(name: string, attributes: CookieAttributes = {}, option: string): void {
  if (name.startsWith('__Host-') && !allowsHostPrefix(attributes)) {
    throw new TypeError(`${option}.cookieName: browsers drop a __Host- cookie unless it is Secure, with Path=/ and no Domain.`);
  }
  if (name.startsWith('__Secure-') && !(attributes.secure ?? true)) {
    throw new TypeError(`${option}.cookieName: browsers drop a __Secure- cookie unless it is Secure.`);
  }
  if (attributes.sameSite === 'none' && !(attributes.secure ?? true)) {
    throw new TypeError(
      `${option}.cookie: browsers drop a SameSite=None cookie unless it is Secure. Keep \`secure\` on (the default), or ` +
        "use sameSite 'lax' for plain-HTTP development.",
    );
  }
}

export function serializeCookie(
  name: string,
  value: string,
  attributes: CookieAttributes & { maxAge: number },
): string {
  const parts = [`${name}=${encodeURIComponent(value)}`, `Max-Age=${Math.max(0, Math.floor(attributes.maxAge))}`];
  parts.push(`Path=${attributes.path ?? '/'}`);
  if (attributes.domain) {
    parts.push(`Domain=${attributes.domain}`);
  }
  parts.push('HttpOnly');
  if (attributes.secure ?? true) {
    parts.push('Secure');
  }
  const sameSite = attributes.sameSite ?? 'lax';
  parts.push(`SameSite=${sameSite[0].toUpperCase()}${sameSite.slice(1)}`);

  return parts.join('; ');
}
