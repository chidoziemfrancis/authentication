/**
 * Startup checks for values that must be there: a `process.env` variable
 * that isn't set reaches the options as `undefined` (or as
 * `"undefined/verify-email"` inside a template string), and would otherwise
 * fail at the first request, or in a constructor with a message about
 * `toString`. Each error names the option.
 */

/** `value` must be set and not empty. `what` describes it: `a secret of at least 32 bytes or a KeyObject`. */
export function requireOption(value: unknown, option: string, what: string): void {
  if (value !== undefined && value !== null && value !== '') {
    return;
  }
  throw new TypeError(
    `AuthenticationModule: \`${option}\` is required (${what}), but it is ${value === '' ? 'empty' : 'undefined'}: ` +
      'is the environment variable it reads set?',
  );
}

/** `value` must be an absolute http(s) URL. `what` describes it: `the page that receives the link`. */
export function requireUrlOption(value: unknown, option: string, what: string): void {
  requireOption(value, option, what);

  let url: URL | undefined;
  try {
    url = typeof value === 'string' ? new URL(value) : undefined;
  } catch {
    url = undefined;
  }

  if (!url || (url.protocol !== 'https:' && url.protocol !== 'http:')) {
    throw new TypeError(
      `AuthenticationModule: \`${option}\` must be an absolute http(s) URL (${what}). Got ${JSON.stringify(value)}` +
        (typeof value === 'string' && value.startsWith('undefined') ? ': is the environment variable it reads set?' : '.'),
    );
  }
}
