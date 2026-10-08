/**
 * What the READMEs document about using idempotency with the family's other packages, in one
 * app: authentication's global guard signs the caller in (so `scope` reads `req.user`, and an
 * unauthenticated call never consumes a key), authorization's `AuthorizationError` (a 403 by
 * its numeric `status`) is stored and replayed, and resilience's retries run inside the one
 * key a request claimed, as its README's "Composing with packages/idempotency" says.
 */
import {
  Body,
  Controller,
  Injectable,
  Logger,
  Module,
  Param,
  Post,
  type ExecutionContext,
  type INestApplication,
} from '@nestjs/common';
import request from 'supertest';
import {
  AuthenticationError,
  AuthenticationModule,
  AuthenticationProvider,
  AuthenticationRegistry,
  CurrentUser,
} from '../lib/index.js';
import { AuthorizationModule, AuthorizationService, Can, Policy } from '@nestjs/authorization';
import { ResilienceModule, Retry } from '@nestjs/resilience';
import { adapters, createApp, type AdapterName } from './support/adapters.js';
import { IdempotencyModule, Idempotent, InMemoryIdempotencyStore, type IdempotencyModuleOptions } from '@nestjs/idempotency';
import { registered } from './support/idempotency-register.js';

type User = { id: string };
type Order = { id: string; ownerId: string };

const USERS_BY_API_KEY: Record<string, User> = {
  'key-alice': { id: 'usr_alice' },
  'key-bob': { id: 'usr_bob' },
};
const ORDERS: Record<string, Order> = {
  ord_a: { id: 'ord_a', ownerId: 'usr_alice' },
  ord_b: { id: 'ord_b', ownerId: 'usr_bob' },
};

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((r) => (resolve = r));
  return { promise, resolve };
}

const state = {
  policyChecks: 0,
  attempts: 0,
  charges: 0,
  /** The next attempts that fail as the payment provider's outage would. */
  failures: 0,
  gate: undefined as ReturnType<typeof deferred> | undefined,
  started: undefined as ReturnType<typeof deferred> | undefined,
};

@Injectable()
class ApiKeyAuth extends AuthenticationProvider<User, { apiKey: string }> {
  constructor(registry: AuthenticationRegistry) {
    super();
    registry.registerProvider(this);
  }

  authenticate(context: ExecutionContext) {
    const apiKey = this.header(context, 'x-api-key');
    if (!apiKey) {
      return null;
    }

    const user = USERS_BY_API_KEY[apiKey];
    if (!user) {
      throw new AuthenticationError('unknown API key');
    }
    return { user, session: { apiKey } };
  }
}

@Policy()
class OrderPolicy {
  pay(user: User, order: Order) {
    state.policyChecks++;
    return order.ownerId === user.id;
  }
}

@Controller('orders')
class OrdersController {
  constructor(private readonly authorizationService: AuthorizationService) {}

  @Post(':id/pay')
  @Idempotent({ required: true })
  @Retry({ idempotent: true, attempts: 3, backoff: { delay: 1, jitter: 'none' } })
  @Can.Anyone()
  async pay(@Param('id') id: string, @CurrentUser() user: User, @Body() body: { paymentMethod: string }) {
    await this.authorizationService.authorize(OrderPolicy, 'pay', user, ORDERS[id]!);

    state.attempts++;
    const gate = state.gate;
    state.gate = undefined;
    if (gate) {
      state.started?.resolve();
      await gate.promise;
    }
    if (state.failures > 0) {
      state.failures--;
      throw new Error('ECONNRESET from the payment provider');
    }

    state.charges++;
    return { orderId: id, paymentMethod: body.paymentMethod, receipt: `rcpt_${state.charges}` };
  }
}

const store = new InMemoryIdempotencyStore();

function appModule(options: IdempotencyModuleOptions, { authorizationFirst = false } = {}) {
  // Idempotency before the modules whose interceptors a replay must skip.
  const idempotency = IdempotencyModule.forRoot(options);
  const authorization = AuthorizationModule.forRoot();
  @Module({
    imports: [
      AuthenticationModule.forRoot(),
      ...(authorizationFirst ? [authorization, idempotency] : [idempotency, authorization]),
      ResilienceModule.forRoot(),
    ],
    controllers: [OrdersController],
    providers: [ApiKeyAuth, OrderPolicy, registered(store)],
  })
  class AppModule {}
  return AppModule;
}

const boot = (adapter: AdapterName, options: IdempotencyModuleOptions, order?: { authorizationFirst?: boolean }) =>
  createApp(adapter, appModule(options, order), { setup: (app) => app.useLogger(false) });

function pay(app: INestApplication, { apiKey = 'key-alice' as string | null, order = 'ord_a', key = 'k1' } = {}) {
  const r = request(app.getHttpServer())
    .post(`/orders/${order}/pay`)
    .set('Idempotency-Key', key)
    .send({ paymentMethod: 'pm_card_visa' });
  return apiKey ? r.set('x-api-key', apiKey) : r;
}

function reset() {
  store.clear();
  state.policyChecks = 0;
  state.attempts = 0;
  state.charges = 0;
  state.failures = 0;
  state.gate = undefined;
  state.started = undefined;
}

describe.each(adapters.map((a) => a.name))('idempotency with authentication, authorization and resilience (%s)', (adapter) => {
  let app: INestApplication;

  beforeAll(async () => {
    app = await boot(adapter, { scope: (req: { user?: User }) => req.user?.id });
  });
  afterAll(async () => {
    state.gate?.resolve();
    await app.close();
  });
  beforeEach(reset);

  describe('authentication', () => {
    it('scopes records by the user its guard signed in: the same key from two users is two payments', async () => {
      const alice = await pay(app, { apiKey: 'key-alice', order: 'ord_a' });
      const bob = await pay(app, { apiKey: 'key-bob', order: 'ord_b' });
      const aliceAgain = await pay(app, { apiKey: 'key-alice', order: 'ord_a' });

      expect(alice.status).toBe(201);
      expect(bob.status).toBe(201);
      expect(bob.headers['idempotent-replayed']).toBeUndefined();
      expect(aliceAgain.headers['idempotent-replayed']).toBe('true');
      expect(aliceAgain.body).toEqual(alice.body);
      expect(store.peek('usr_alice:k1')?.state).toBe('completed');
      expect(store.peek('usr_bob:k1')?.state).toBe('completed');
      expect(state.charges).toBe(2);
    });

    it('refuses a caller without credentials, or with unknown ones, before the key is consumed', async () => {
      expect((await pay(app, { apiKey: null })).status).toBe(401);
      expect((await pay(app, { apiKey: 'key-mallory' })).status).toBe(401);
      expect(store.size).toBe(0);

      const signedIn = await pay(app);
      expect(signedIn.status).toBe(201);
      expect(signedIn.headers['idempotent-replayed']).toBeUndefined();
      expect(state.charges).toBe(1);
    });
  });

  describe('authorization', () => {
    it("stores a denial from authorize() as Nest's 403, and replays it without checking the policy again", async () => {
      const denied = await pay(app, { apiKey: 'key-bob', order: 'ord_a' });
      const again = await pay(app, { apiKey: 'key-bob', order: 'ord_a' });

      expect(denied.status).toBe(403);
      expect(denied.body).toEqual({ message: 'Forbidden', statusCode: 403 });
      expect(again.status).toBe(403);
      expect(again.body).toEqual(denied.body);
      expect(again.headers['idempotent-replayed']).toBe('true');
      // Neither retried by resilience (a 4xx status) nor checked again on the replay.
      expect(state.policyChecks).toBe(1);
      expect(state.attempts).toBe(0);
    });
  });

  describe('resilience', () => {
    it('runs the retries of one request inside the key it claimed, and stores the final outcome once', async () => {
      state.failures = 2;

      const first = await pay(app);
      expect(first.status).toBe(201);
      expect(state.attempts).toBe(3);
      expect(store.size).toBe(1);

      const replay = await pay(app);
      expect(replay.headers['idempotent-replayed']).toBe('true');
      expect(replay.body).toEqual(first.body);
      expect(state.attempts).toBe(3);
      expect(state.charges).toBe(1);
    });

    it('answers a duplicate with 409 before any retry runs', async () => {
      const gate = (state.gate = deferred());
      state.started = deferred();
      const first = pay(app).then((r) => r);
      await state.started.promise;

      const busy = await pay(app);
      expect(busy.status).toBe(409);
      expect(busy.body.code).toBe('IDEMPOTENCY_KEY_IN_USE');
      expect(state.attempts).toBe(1);

      gate.resolve();
      expect((await first).status).toBe(201);
    });

    it('releases the key once the retries are exhausted, so the client retry runs again', async () => {
      state.failures = 3;

      expect((await pay(app)).status).toBe(500);
      expect(state.attempts).toBe(3);
      expect(store.size).toBe(0);

      const retry = await pay(app);
      expect(retry.status).toBe(201);
      expect(retry.headers['idempotent-replayed']).toBeUndefined();
      expect(state.attempts).toBe(4);
    });
  });
});

describe('an unscoped handler behind authentication', () => {
  it('warns once, naming the handler, when a signed-in user reaches it', async () => {
    reset();
    const warn = vi.spyOn(Logger.prototype, 'warn').mockImplementation(() => {});
    const app = await boot('express', {});
    try {
      await pay(app, { key: 'k1' });
      await pay(app, { key: 'k2' });

      const warnings = warn.mock.calls.map(([message]) => String(message)).filter((m) => m.includes('OrdersController.pay'));
      expect(warnings).toHaveLength(1);
      expect(warnings[0]).toContain('scope');
      expect(store.peek('k1')?.state).toBe('completed');
    } finally {
      warn.mockRestore();
      await app.close();
    }
  });
});

describe('AuthorizationModule imported before IdempotencyModule', () => {
  it("stores the AuthorizationError that reaches it by its 403 status, as Nest's exception, and replays that", async () => {
    reset();
    const warn = vi.spyOn(Logger.prototype, 'warn').mockImplementation(() => {});
    const app = await boot('express', { scope: (req: { user?: User }) => req.user?.id }, { authorizationFirst: true });
    try {
      const denied = await pay(app, { apiKey: 'key-bob', order: 'ord_a' });
      const again = await pay(app, { apiKey: 'key-bob', order: 'ord_a' });

      expect(denied.status).toBe(403);
      expect(again.status).toBe(403);
      expect(again.body).toEqual({ message: 'Forbidden', statusCode: 403 });
      expect(again.headers['idempotent-replayed']).toBe('true');
      expect(state.policyChecks).toBe(1);
      expect(store.peek('usr_bob:k1')).toMatchObject({ state: 'completed', response: { status: 403, error: 'http' } });
      // Its interceptor runs outside idempotency's, which says so at startup.
      expect(warn.mock.calls.some(([message]) => String(message).includes('AuthorizationErrorInterceptor'))).toBe(true);
    } finally {
      warn.mockRestore();
      await app.close();
    }
  });
});
