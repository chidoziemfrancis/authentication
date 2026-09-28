import type { Duration } from '../interfaces/duration.interface.js';

const UNITS: Record<string, number> = {
  ms: 1,
  s: 1_000,
  m: 60_000,
  h: 3_600_000,
  d: 86_400_000,
  w: 604_800_000,
};

/**
 * The longest duration: 100 years. Longer, a lifetime added to the clock leaves the range of
 * `Date` (an Invalid Date), and every token or session made with it would be born expired.
 */
const MAX_DURATION = 100 * 365.25 * 86_400_000;

export function toMs(duration: Duration): number {
  let ms: number;
  if (typeof duration === 'number') {
    if (!Number.isFinite(duration) || duration < 0) {
      throw new TypeError(`Invalid duration ${duration}. Use a non-negative number of milliseconds.`);
    }
    ms = duration;
  } else {
    const match = /^(\d+(?:\.\d+)?)(ms|s|m|h|d|w)$/.exec(duration);
    if (!match) {
      throw new TypeError(`Invalid duration "${duration}". Use milliseconds or a string such as "15m" or "3d".`);
    }
    ms = Math.round(Number(match[1]) * UNITS[match[2]]);
  }

  if (ms > MAX_DURATION) {
    throw new TypeError(`Invalid duration ${typeof duration === 'string' ? `"${duration}"` : duration}: longer than 100 years.`);
  }
  return ms;
}

export function durationOr(value: Duration | undefined, fallback: Duration): number {
  return toMs(value ?? fallback);
}

/**
 * Whether `expiresAt` has passed at `now` (epoch milliseconds). Fails closed: a date that is not
 * one (`Invalid Date`, from a store that lost or misnamed the column) has passed, where
 * `now >= NaN`, which is always false, would keep a session, token or link alive forever.
 */
export function hasExpired(expiresAt: Date, now: number): boolean {
  return !(now < expiresAt.getTime());
}
