/**
 * `MagicLinkService` inside an HTTP exchange, without a server: the transaction cookie it sets
 * and clears on the response, its attributes, and what each outcome of `consume()` leaves behind.
 */
import { HttpAdapterHost } from '@nestjs/core';
import { ExecutionContextHost } from '@nestjs/core/internal';
import {
  AuthenticationEvents,
  InMemoryMagicLinkStore,
  MagicLinkError,
  MagicLinkHandler,
  MagicLinkService,
  MfaService,
  SessionService,
  SignInService,
  TokenService,
  type AuthenticationEvent,
  type MagicLink,
  type MagicLinkOptions,
} from '../lib/index.js';
import { AuthenticationScope } from '../lib/context/authentication-scope.service.js';
import { registryWith, storageWith } from './fixtures.js';

class Mailer extends MagicLinkHandler {
  readonly sent: MagicLink[] = [];
  readonly known = new Map([['ada@example.com', { id: 'u1' }]]);
  send(link: MagicLink) {
    this.sent.push(link);
  }
  resolveUser(email: string) {
    return this.known.get(email) ?? null;
  }
}

function setup(magicLink: Partial<MagicLinkOptions> = {}) {
  let clock = 1_700_000_000_000;
  const links = new InMemoryMagicLinkStore();
  const storage = storageWith({ magicLinks: links });
  const mailer = new Mailer();
  const events = new AuthenticationEvents();
  const seen: AuthenticationEvent[] = [];
  events.events$.subscribe((event) => seen.push(event));

  const scope = new AuthenticationScope();
  const adapterHost = new HttpAdapterHost();
  adapterHost.httpAdapter = {
    appendHeader: (response: { cookies: string[] }, _name: string, value: string) => response.cookies.push(value),
  } as never;

  const sessions = new SessionService(storage, { session: { cookie: { secure: false } } });
  const signIn = new SignInService(sessions, new MfaService(storage, {}), new TokenService(storage, {}), scope, adapterHost, events);
  const options = { magicLink: { url: 'https://app.test/magic', ttl: '10m' as const, now: () => clock, ...magicLink } };
  const service = new MagicLinkService(storage, registryWith(options, { magicLink: mailer }), signIn, options, scope, adapterHost, events);

  class Handler {
    handle() {}
  }
  /** Runs `fn` as the handler of a POST with these headers; the cookies it set come back. */
  const inRequest = async <R>(headers: Record<string, string>, fn: () => Promise<R>) => {
    const response = { cookies: [] as string[] };
    const context = new ExecutionContextHost([{ headers, method: 'POST' }, response], Handler, Handler.prototype.handle);
    context.setType('http');
    const result: { value?: R; error?: unknown } = await scope.run({ result: null, context }, fn).then(
      (value) => ({ value }),
      (error: unknown) => ({ error }),
    );
    return { ...result, cookies: response.cookies };
  };
  const tokenOf = (link: MagicLink) => new URL(link.url).searchParams.get('token')!;
  const cookieHeader = (setCookie: string) => ({ cookie: setCookie.split(';')[0] });

  return { service, links, mailer, seen, inRequest, tokenOf, cookieHeader, tick: (ms: number) => (clock += ms) };
}

describe('MagicLinkService in an HTTP exchange', () => {
  it('sets the transaction cookie on the response that requested the link, for the link’s lifetime', async () => {
    const { service, inRequest, mailer } = setup();
    const created = await inRequest({}, () => service.create('  ADA@example.com '));

    expect(created.cookies).toEqual([expect.stringMatching(/^__Host-magic_link_tx=[\w-]{43}; Max-Age=600; Path=\/; HttpOnly; Secure; SameSite=Lax$/)]);
    expect(created.value).toEqual({ expiresAt: mailer.sent[0].expiresAt, cookie: created.cookies[0] });
    expect(mailer.sent[0].email).toBe('ada@example.com');
  });

  it('keeps the transaction cookie SameSite=Lax whatever the options say: the link is opened from a mail client', async () => {
    const { service, inRequest } = setup({ cookie: { sameSite: 'strict', domain: 'app.test' } });
    const { cookies } = await inRequest({}, () => service.create('ada@example.com'));
    expect(cookies[0]).toMatch(/^magic_link_tx=[\w-]{43}; Max-Age=600; Path=\/; Domain=app\.test; HttpOnly; Secure; SameSite=Lax$/);
  });

  it('signs in the browser that requested the link, clearing its transaction cookie and setting the session', async () => {
    const { service, inRequest, mailer, tokenOf, cookieHeader, seen } = setup();
    const created = await inRequest({}, () => service.create('ada@example.com', { redirectTo: '/orders' }));

    const consumed = await inRequest(cookieHeader(created.cookies[0]), () => service.consume(tokenOf(mailer.sent[0])));
    expect(consumed.value).toMatchObject({ session: { userId: 'u1' }, redirectTo: '/orders' });
    expect(consumed.cookies).toEqual([
      expect.stringMatching(/^__Host-magic_link_tx=; Max-Age=0; /),
      expect.stringMatching(/^sid=[\w-]{43}; /),
    ]);
    expect(seen).toEqual([expect.objectContaining({ type: 'sign-in', userId: 'u1', method: 'magic-link' })]);
  });

  it('refuses another browser before any lookup, and leaves both its cookie and the link alone', async () => {
    const { service, inRequest, mailer, tokenOf, cookieHeader, links, seen } = setup();
    const mine = await inRequest({}, () => service.create('ada@example.com'));
    const other = await inRequest({}, () => service.create('ada@example.com'));
    const consume = vi.spyOn(links, 'consumeMagicLink');

    const refused = await inRequest(cookieHeader(other.cookies[0]), () => service.consume(tokenOf(mailer.sent[0])));
    expect(refused.error).toBeInstanceOf(MagicLinkError);
    expect(refused.cookies).toEqual([]);
    expect(consume).not.toHaveBeenCalled();
    expect(seen).toEqual([{ type: 'magic-link-refused', reason: 'not-this-browser' }]);

    const opened = await inRequest(cookieHeader(mine.cookies[0]), () => service.consume(tokenOf(mailer.sent[0])));
    expect(opened.value).toMatchObject({ session: { userId: 'u1' } });
  });

  it('burns a link for an address nobody may sign in with, says so in the event, and clears the cookie', async () => {
    const { service, inRequest, mailer, tokenOf, cookieHeader, seen } = setup();
    const created = await inRequest({}, () => service.create('stranger@example.com'));
    const token = tokenOf(mailer.sent[0]);

    const refused = await inRequest(cookieHeader(created.cookies[0]), () => service.consume(token));
    expect(refused).toEqual({ value: null, cookies: [expect.stringMatching(/^__Host-magic_link_tx=; Max-Age=0; /)] });
    expect(seen).toEqual([{ type: 'magic-link-refused', reason: 'refused', email: 'stranger@example.com' }]);

    mailer.known.set('stranger@example.com', { id: 'u9' }); // allowed now, but the link is spent
    const again = await inRequest(cookieHeader(created.cookies[0]), () => service.consume(token));
    expect(again.value).toBeNull();
    expect(seen.at(-1)).toEqual({ type: 'magic-link-refused', reason: 'unknown' });
  });

  it('refuses a malformed token as unknown, before checking the browser', async () => {
    const { service, inRequest, seen } = setup();
    const refused = await inRequest({}, () => service.consume('not a token'));
    expect(refused).toEqual({ value: null, cookies: [] });
    expect(seen).toEqual([{ type: 'magic-link-refused', reason: 'unknown' }]);
  });

  it('with bindToBrowser: false, sets and clears no cookie, and signs in any browser', async () => {
    const { service, inRequest, mailer, tokenOf } = setup({ bindToBrowser: false });
    const created = await inRequest({}, () => service.create('ada@example.com'));
    expect(created).toEqual({ value: { expiresAt: expect.any(Date) }, cookies: [] });

    const consumed = await inRequest({}, () => service.consume(tokenOf(mailer.sent[0])));
    expect(consumed.cookies).toEqual([expect.stringMatching(/^sid=/)]);
  });

  it('prefers the request passed to consume() over the exchange’s', async () => {
    const { service, inRequest, mailer, tokenOf, cookieHeader } = setup();
    const created = await inRequest({}, () => service.create('ada@example.com'));

    const consumed = await inRequest({}, () => service.consume(tokenOf(mailer.sent[0]), { request: { headers: cookieHeader(created.cookies[0]) } }));
    expect(consumed.value).toMatchObject({ session: { userId: 'u1' } });
  });

  it('accepts a link until the millisecond before `ttl` runs out', async () => {
    const { service, inRequest, mailer, tokenOf, cookieHeader, tick, seen } = setup();
    const first = await inRequest({}, () => service.create('ada@example.com'));
    tick(599_999);
    expect((await inRequest(cookieHeader(first.cookies[0]), () => service.consume(tokenOf(mailer.sent[0])))).value).not.toBeNull();

    const second = await inRequest({}, () => service.create('ada@example.com'));
    tick(600_000);
    expect((await inRequest(cookieHeader(second.cookies[0]), () => service.consume(tokenOf(mailer.sent[1])))).value).toBeNull();
    expect(seen.at(-1)).toEqual({ type: 'magic-link-refused', reason: 'expired', email: 'ada@example.com' });
  });
});
