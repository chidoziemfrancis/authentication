/**
 * `@nestjs/resilience` on the same entrypoints, on Express and Fastify: the package's errors
 * carry a 4xx `status`, so an `AuthenticationError` thrown under a handler (`requireUser()`,
 * a failed refresh) reaches the client as a 401 without being retried or opening a breaker,
 * whichever order the two global interceptors run in. An outage on the same route is retried.
 */
import { Body, Controller, Get, HttpCode, Injectable, Module, Post, type INestApplication } from '@nestjs/common';
import request from 'supertest';
import { adapters, createApp } from './support/adapters.js';
import { CircuitBreaker, ResilienceEvents, ResilienceModule, ResilienceService, Retry, type ResilienceEvent } from '@nestjs/resilience';
import {
  Authenticate,
  AuthenticationContext,
  AuthenticationModule,
  AuthenticationProvider,
  AuthenticationRegistry,
  Public,
  TokenService,
} from '../lib/index.js';

const calls = { mine: 0, flaky: 0, refresh: 0 };
let failuresLeft = 0;

@Injectable()
class HeaderAuth extends AuthenticationProvider<{ id: string }> {
  constructor(registry: AuthenticationRegistry) {
    super();
    registry.registerProvider(this);
  }
  async authenticate(context: Parameters<AuthenticationProvider['authenticate']>[0]) {
    const id = this.header(context, 'x-user');
    return id ? { user: { id } } : null;
  }
}

@Injectable()
class OrdersService {
  constructor(private readonly authenticationContext: AuthenticationContext) {}

  mine() {
    calls.mine++;
    return { owner: this.authenticationContext.requireUser().id };
  }

  flaky() {
    calls.flaky++;
    if (failuresLeft-- > 0) {
      throw new Error('orders database unavailable');
    }
    return { ok: true };
  }
}

@Controller()
@CircuitBreaker({ minimumCalls: 4, slidingWindow: { type: 'count', size: 4 }, failureRateThreshold: 75, openDuration: '1m' })
@Retry({ attempts: 3, backoff: () => 0 })
class OrdersController {
  constructor(
    private readonly ordersService: OrdersService,
    private readonly tokenService: TokenService,
  ) {}

  @Authenticate({ optional: true })
  @Get('orders/mine')
  mine() {
    return this.ordersService.mine();
  }

  @Public()
  @Get('orders/flaky')
  flaky() {
    return this.ordersService.flaky();
  }

  @Public()
  @Post('token/refresh')
  @HttpCode(200)
  @Retry({ attempts: 3, idempotent: true, backoff: () => 0 })
  refresh(@Body('refreshToken') refreshToken: string) {
    calls.refresh++;
    return this.tokenService.refresh(refreshToken);
  }
}

function appModule(order: 'authentication first' | 'resilience first') {
  const authentication = AuthenticationModule.forRoot({ accessToken: { key: 'resilience-test-secret-of-at-least-32-bytes' } });
  const resilience = ResilienceModule.forRoot();

  @Module({
    imports: order === 'authentication first' ? [authentication, resilience] : [resilience, authentication],
    controllers: [OrdersController],
    providers: [HeaderAuth, OrdersService],
  })
  class ResilientAppModule {}
  return ResilientAppModule;
}

describe.each(adapters.map((a) => a.name))('with @nestjs/resilience (%s)', (adapter) => {
  describe.each(['authentication first', 'resilience first'] as const)('%s', (order) => {
    let app: INestApplication;
    const events: ResilienceEvent[] = [];
    const http = () => request(app.getHttpServer());
    const breaker = (handler: string) => app.get(ResilienceService).circuitBreaker(`OrdersController.${handler}`);

    beforeAll(async () => {
      app = await createApp(adapter, appModule(order));
      app.get(ResilienceEvents).events$.subscribe((event) => events.push(event));
    });
    afterAll(() => app.close());
    beforeEach(() => {
      calls.mine = 0;
      calls.flaky = 0;
      calls.refresh = 0;
      failuresLeft = 0;
      events.length = 0;
    });

    it('answers requireUser() on an anonymous call with a 401, once per request: no retry, no open breaker', async () => {
      for (let i = 0; i < 6; i++) {
        const res = await http().get('/orders/mine').expect(401);
        expect(res.body).toEqual({ message: 'Unauthorized', statusCode: 401 });
      }

      expect(calls.mine).toBe(6);
      expect(events).toEqual([]);
      expect(breaker('mine').state).toBe('closed');
      await http().get('/orders/mine').set('x-user', 'u1').expect(200, { owner: 'u1' });
    });

    it('answers a failed refresh with a 401, once: a refresh token is never presented twice by a retry', async () => {
      const res = await http().post('/token/refresh').send({ refreshToken: 'not-a-token' }).expect(401);

      expect(res.body).toMatchObject({ statusCode: 401 });
      expect(calls.refresh).toBe(1);
      expect(events).toEqual([]);
    });

    it('still retries an outage on the same controller, and counts it against the breaker', async () => {
      failuresLeft = 1;
      await http().get('/orders/flaky').expect(200, { ok: true });
      expect(calls.flaky).toBe(2);
      expect(events.map((event) => event.type)).toEqual(['retry']);

      failuresLeft = 6;
      const outage = await http().get('/orders/flaky');
      expect([500, 503]).toContain(outage.status);
      await http().get('/orders/flaky').expect(503);
      expect(breaker('flaky').state).toBe('open');
      expect(events.map((event) => event.type)).toContain('circuit-open');
    });
  });
});
