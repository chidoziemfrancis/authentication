/**
 * The internal helpers that hold the package's parsing and comparison rules: durations, cookies,
 * cross-origin writes, tokens, option checks, `amr` values and addresses.
 */
import { createHash } from 'node:crypto';
import { hasMfaAmr, MFA_AMR_VALUES } from '../lib/jwt/amr.util.js';
import { hasVerifiedEmail, normalizeEmail } from '../lib/account/email.util.js';
import {
  allowsHostPrefix,
  assertCookieAttributes,
  defaultCookieName,
  readCookie,
  serializeCookie,
} from '../lib/session/cookies.util.js';
import { isCrossOriginWrite, normalizeOrigin } from '../lib/utils/cross-origin.util.js';
import { TOKEN_PATTERN, randomToken, safeEqual, sha256 } from '../lib/utils/crypto.util.js';
import { durationOr, toMs } from '../lib/utils/duration.util.js';
import { requireOption, requireUrlOption } from '../lib/utils/options.util.js';

describe('durations', () => {
  it('reads every unit, fractions rounded to the millisecond', () => {
    expect([toMs('250ms'), toMs('0s'), toMs('1w'), toMs('0.5s'), toMs('1.0004s'), toMs('2h')]).toEqual([
      250, 0, 604_800_000, 500, 1_000, 7_200_000,
    ]);
    expect(toMs(0)).toBe(0);
  });

  it('rejects infinity, surrounding spaces, upper-case units and bare fractions', () => {
    for (const bad of [Number.POSITIVE_INFINITY, ' 5m', '5m ', '5M', '1.5', '.5s', '-1s', '1e3ms'] as never[]) {
      expect(() => toMs(bad)).toThrow(TypeError);
    }
    expect(() => toMs(-1)).toThrow('Invalid duration -1. Use a non-negative number of milliseconds.');
    expect(() => toMs('soon' as never)).toThrow('Invalid duration "soon". Use milliseconds or a string such as "15m" or "3d".');
  });

  it('durationOr() takes the fallback for undefined only: 0 is a value (it disables idle timeouts)', () => {
    expect(durationOr(undefined, '1h')).toBe(3_600_000);
    expect(durationOr(0, '1h')).toBe(0);
    expect(durationOr('2m', '1h')).toBe(120_000);
    expect(() => durationOr(undefined, 'never' as never)).toThrow(TypeError);
  });
});

describe('cookies', () => {
  it('readCookie() tolerates pairs without a value, spaces, `=` in values and broken percent-encoding', () => {
    expect(readCookie('flag; sid=abc', 'sid')).toBe('abc');
    expect(readCookie('  sid  =  abc  ; b=2', 'sid')).toBe('abc');
    expect(readCookie('sid=a=b=c', 'sid')).toBe('a=b=c');
    expect(readCookie('sid=%E0%A4%A', 'sid')).toBe('%E0%A4%A'); // kept raw instead of throwing
    expect(readCookie('sid="', 'sid')).toBe('"'); // a lone quote is not a quoted value
    expect(readCookie('sid=', 'sid')).toBe('');
    expect(readCookie('', 'sid')).toBeUndefined();
    expect(readCookie('other=1', 'sid')).toBeUndefined();
  });

  it('serializeCookie() is HttpOnly, Secure and SameSite=Lax at Path=/ by default', () => {
    expect(serializeCookie('sid', 'a b;c', { maxAge: 60 })).toBe('sid=a%20b%3Bc; Max-Age=60; Path=/; HttpOnly; Secure; SameSite=Lax');
  });

  it('serializeCookie() floors Max-Age, never writes a negative one, and writes every attribute it is given', () => {
    expect(serializeCookie('sid', 'v', { maxAge: 59.9 })).toContain('Max-Age=59;');
    expect(serializeCookie('sid', '', { maxAge: -10 })).toContain('Max-Age=0;');
    expect(
      serializeCookie('sid', 'v', { maxAge: 1, secure: false, sameSite: 'strict', path: '/app', domain: 'example.com' }),
    ).toBe('sid=v; Max-Age=1; Path=/app; Domain=example.com; HttpOnly; SameSite=Strict');
    expect(serializeCookie('sid', 'v', { maxAge: 1, sameSite: 'none' })).toMatch(/; Secure; SameSite=None$/);
  });

  it('allows the __Host- prefix only for Secure cookies at Path=/ without a Domain', () => {
    expect(allowsHostPrefix()).toBe(true);
    expect(allowsHostPrefix({ secure: true, path: '/' })).toBe(true);
    expect(allowsHostPrefix({ secure: false })).toBe(false);
    expect(allowsHostPrefix({ path: '/api' })).toBe(false);
    expect(allowsHostPrefix({ domain: 'example.com' })).toBe(false);

    expect(defaultCookieName('sid')).toBe('__Host-sid');
    expect(defaultCookieName('sid', { domain: 'example.com' })).toBe('sid');
  });

  it('refuses at startup the prefixed names and SameSite=None cookies browsers would drop', () => {
    expect(() => assertCookieAttributes('__Host-sid', { path: '/api' }, 'session')).toThrow(
      'session.cookieName: browsers drop a __Host- cookie unless it is Secure, with Path=/ and no Domain.',
    );
    expect(() => assertCookieAttributes('__Secure-sid', { secure: false }, 'session')).toThrow(
      'session.cookieName: browsers drop a __Secure- cookie unless it is Secure.',
    );
    expect(() => assertCookieAttributes('sid', { sameSite: 'none', secure: false }, 'magicLink')).toThrow(/^magicLink\.cookie: /);

    // A __Secure- cookie may carry a Domain and a Path; plain names may be anything.
    expect(() => assertCookieAttributes('__Secure-sid', { domain: 'example.com', path: '/api' }, 'session')).not.toThrow();
    expect(() => assertCookieAttributes('sid', { secure: false, sameSite: 'strict' }, 'session')).not.toThrow();
  });
});

describe('cross-origin writes', () => {
  const none = new Set<string>();
  const write = (headers: Record<string, string | string[]>, method: string | undefined = 'POST', trusted = none) =>
    isCrossOriginWrite({ headers, method }, trusted);

  it('never counts safe methods, whatever the headers say', () => {
    for (const method of ['GET', 'HEAD', 'OPTIONS']) {
      expect(write({ origin: 'https://evil.test', 'sec-fetch-site': 'cross-site', host: 'api.test' }, method)).toBe(false);
    }
    for (const method of ['POST', 'PUT', 'PATCH', 'DELETE']) {
      expect(write({ origin: 'https://evil.test', host: 'api.test' }, method)).toBe(true);
    }
  });

  it('trusts Sec-Fetch-Site: same-origin and none pass, same-site and cross-site need a trusted Origin', () => {
    expect(write({ 'sec-fetch-site': 'none' })).toBe(false); // typed in the address bar, a bookmark
    expect(write({ 'sec-fetch-site': 'same-origin', origin: 'https://evil.test', host: 'api.test' })).toBe(false);
    expect(write({ 'sec-fetch-site': 'same-site', host: 'api.test' })).toBe(true); // no Origin to trust
    expect(write({ 'sec-fetch-site': 'cross-site', origin: 'https://app.test' }, 'POST', new Set(['https://app.test']))).toBe(false);
  });

  it('matches Origin against the host, the scheme’s default port included, and nothing looser', () => {
    expect(write({ origin: 'http://api.test', host: 'api.test:80' })).toBe(false);
    expect(write({ origin: 'http://api.test:80', host: 'api.test' })).toBe(false); // URL drops the default port
    expect(write({ origin: 'https://api.test', host: 'api.test:8443' })).toBe(true);
    expect(write({ origin: 'https://api.test:8443', host: 'api.test' })).toBe(true);
    expect(write({ origin: 'https://sub.api.test', host: 'api.test' })).toBe(true);
    expect(write({ origin: 'null', host: 'api.test' })).toBe(true); // sandboxed frames
    expect(write({ origin: 'https://api.test' })).toBe(true); // no host to compare with
  });

  it('joins repeated headers, so conflicting values never pass as same-origin or trusted', () => {
    expect(write({ 'sec-fetch-site': ['same-origin', 'cross-site'] })).toBe(true);
    expect(write({ origin: ['https://api.test', 'https://evil.test'], host: 'api.test' })).toBe(true);
    expect(write({ origin: ['https://app.test', 'https://app.test'], host: 'api.test' }, 'POST', new Set(['https://app.test']))).toBe(true);
  });

  it('normalizes trusted origins the way browsers serialize Origin', () => {
    expect(normalizeOrigin('HTTPS://Shop.Example.com:443', 'x')).toBe('https://shop.example.com');
    expect(normalizeOrigin('http://localhost:3000', 'x')).toBe('http://localhost:3000');
    expect(normalizeOrigin('http://[::1]:8080', 'x')).toBe('http://[::1]:8080');
  });

  it('refuses anything that is not scheme://host[:port], naming the option and never guessing', () => {
    for (const bad of ['https://app.test/', 'https://app.test?x=1', 'https://app.test#top', 'app.test', 'https://*.example.com', 'https://u:p@app.test', '', 42, null]) {
      expect(() => normalizeOrigin(bad, 'session.trustedOrigins')).toThrow(/^session\.trustedOrigins: .* is not an origin\./);
    }
  });
});

describe('tokens and hashes', () => {
  it('randomToken() gives 256 random bits as 43 base64url characters by default', () => {
    const tokens = new Set(Array.from({ length: 100 }, () => randomToken()));
    expect(tokens.size).toBe(100);
    for (const token of tokens) {
      expect(token).toMatch(TOKEN_PATTERN);
    }
    expect(randomToken(16)).toMatch(/^[\w-]{22}$/);
    expect(TOKEN_PATTERN.test(randomToken(16))).toBe(false);
  });

  it('sha256() is SHA-256 in base64url, without padding', () => {
    expect(sha256('')).toBe('47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU');
    expect(sha256('token')).toBe(createHash('sha256').update('token').digest('base64url'));
    expect(sha256('token')).toMatch(TOKEN_PATTERN);
  });

  it('safeEqual() compares bytes, so lengths that differ and look-alike characters never match', () => {
    expect(safeEqual('abc', 'abc')).toBe(true);
    expect(safeEqual('abc', 'abd')).toBe(false);
    expect(safeEqual('abc', 'abcd')).toBe(false);
    expect(safeEqual('é', 'é')).toBe(false);
    expect(safeEqual('', '')).toBe(true);
  });
});

describe('required options', () => {
  it('says whether a value is undefined or empty, and hints at the environment variable', () => {
    expect(() => requireOption(undefined, 'accessToken.key', 'a secret')).toThrow(
      'AuthenticationModule: `accessToken.key` is required (a secret), but it is undefined: is the environment variable it reads set?',
    );
    expect(() => requireOption(null, 'accessToken.key', 'a secret')).toThrow(/but it is undefined/);
    expect(() => requireOption('', 'accessToken.key', 'a secret')).toThrow(/but it is empty/);
    expect(() => requireOption(0, 'x', 'y')).not.toThrow();
    expect(() => requireOption(false, 'x', 'y')).not.toThrow();
  });

  it('takes absolute http(s) URLs only, and spots a template string built from an unset variable', () => {
    expect(() => requireUrlOption('https://app.test/verify', 'emailVerification.url', 'the page')).not.toThrow();
    expect(() => requireUrlOption('http://localhost:3000/verify', 'emailVerification.url', 'the page')).not.toThrow();

    expect(() => requireUrlOption('/verify', 'emailVerification.url', 'the page')).toThrow(
      'AuthenticationModule: `emailVerification.url` must be an absolute http(s) URL (the page). Got "/verify".',
    );
    expect(() => requireUrlOption('javascript:alert(1)', 'u', 'w')).toThrow(/must be an absolute http\(s\) URL/);
    expect(() => requireUrlOption('ftp://files.test/x', 'u', 'w')).toThrow(/must be an absolute http\(s\) URL/);
    expect(() => requireUrlOption(new URL('https://app.test'), 'u', 'w')).toThrow(/must be an absolute http\(s\) URL/);
    expect(() => requireUrlOption('undefined/verify-email', 'u', 'w')).toThrow(
      'Got "undefined/verify-email": is the environment variable it reads set?',
    );
    expect(() => requireUrlOption('', 'u', 'w')).toThrow(/is required \(w\), but it is empty/);
  });
});

describe('amr values', () => {
  it('count mfa, otp and hwk as a second factor, in an array of strings only', () => {
    expect(MFA_AMR_VALUES).toEqual(['mfa', 'otp', 'hwk']);
    for (const amr of [['pwd', 'mfa'], ['otp'], ['hwk', 42]]) {
      expect(hasMfaAmr(amr)).toBe(true);
    }
    for (const amr of [['pwd'], ['MFA'], 'mfa', [['mfa']], { 0: 'mfa', length: 1 }, [], undefined, null]) {
      expect(hasMfaAmr(amr)).toBe(false);
    }
  });
});

describe('email addresses', () => {
  it('are trimmed and lower-cased; anything but a string is a TypeError', () => {
    expect(normalizeEmail('  Ada.Lovelace@Example.COM\n')).toBe('ada.lovelace@example.com');
    expect(() => normalizeEmail(undefined as never)).toThrow('An email address must be a string');
    expect(() => normalizeEmail({ email: 'a@b.c' } as never)).toThrow(TypeError);
  });

  it('count as verified by default only when the user says `emailVerified: true`', () => {
    expect(hasVerifiedEmail({ emailVerified: true })).toBe(true);
    for (const user of [{ emailVerified: 'true' }, { emailVerified: 1 }, {}, null, undefined, 'user']) {
      expect(hasVerifiedEmail(user)).toBe(false);
    }
  });
});
