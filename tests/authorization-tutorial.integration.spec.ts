/**
 * The tutorial's app over HTTP, on Express and Fastify, with the real `@nestjs/authentication`:
 * users sign in through the app's own endpoint and send the JWT it issues, so authentication,
 * handlers and policies all see the same user.
 */
import { subscribe, unsubscribe } from 'node:diagnostics_channel';
import { Controller, Get, Logger, Module, Post, UseGuards, type INestApplication } from '@nestjs/common';
import request from 'supertest';
import { adapters, createApp } from './support/adapters.js';
import { AuthenticationGuard, PasswordHasher, Public } from '../lib/index.js';
import {
  AuthorizationEvents,
  AuthorizationGuard,
  AuthorizationModule,
  Can,
  type AuthorizationDeniedEvent,
} from '@nestjs/authorization';
import {
  ada,
  alice,
  alicePaid,
  aliceShipped,
  AuthModule,
  authenticationModule,
  ProductPolicy,
  ProductsModule,
  bob,
  bobPaid,
  bobPending,
  cheapHasher,
  PASSWORD,
  sam,
  TutorialAppModule,
  UsersRepository,
  type User,
} from './fixtures/authorization-tutorial.js';

const UNAUTHORIZED = { message: 'Unauthorized', statusCode: 401 };
const FORBIDDEN = { message: 'Forbidden', statusCode: 403 };

const boot = (adapter: (typeof adapters)[number]['name'], module: Parameters<typeof createApp>[1]) =>
  createApp(adapter, module, { override: (builder) => builder.overrideProvider(PasswordHasher).useValue(cheapHasher()) });

describe.each(adapters.map((a) => a.name))('the tutorial app with @nestjs/authentication (%s)', (adapter) => {
  let app: INestApplication;
  const tokens = new Map<string, string>();
  const events: AuthorizationDeniedEvent[] = [];
  const http = () => request(app.getHttpServer());

  const signIn = async (user: User) => {
    if (!tokens.has(user.email)) {
      const { body } = await http().post('/auth/token').send({ email: user.email, password: PASSWORD }).expect(200);
      tokens.set(user.email, `Bearer ${body.accessToken}`);
    }
    return tokens.get(user.email)!;
  };
  /** A request as `user`, signed in up front: a supertest request runs when awaited. */
  const as = (user: User | null, method: 'get' | 'post' | 'patch' | 'delete', url: string) => {
    const call = http()[method](url);
    return user ? call.set('Authorization', tokens.get(user.email)!) : call;
  };

  beforeAll(async () => {
    app = await boot(adapter, TutorialAppModule);
    for (const user of [alice, bob, sam, ada]) {
      await signIn(user);
    }
    app.get(AuthorizationEvents).events$.subscribe((event) => events.push(event));
  });
  afterAll(() => app.close());
  beforeEach(() => {
    events.length = 0;
  });

  describe('products: @Can() on routes, authorize() and can() in the service', () => {
    it('shows guests and customers the published products, and staff the drafts too (can(), no event)', async () => {
      const ids = (body: { id: string }[]) => body.map(({ id }) => id);

      expect(ids((await as(null, 'get', '/products').expect(200)).body)).toEqual(['scratching-post', 'cat-tree']);
      expect(ids((await as(alice, 'get', '/products').expect(200)).body)).toEqual(['scratching-post', 'cat-tree']);
      expect(ids((await as(sam, 'get', '/products').expect(200)).body)).toEqual([
        'scratching-post',
        'cat-tree',
        'heated-cat-bed',
      ]);
      expect(events).toEqual([]);
    });

    it('answers a draft with 401 for a guest (optional authentication gave the policy null), 403 for a customer, 200 for staff', async () => {
      const guest = await as(null, 'get', '/products/heated-cat-bed').expect(401, UNAUTHORIZED);
      expect(guest.headers['www-authenticate']).toBeUndefined();

      await as(alice, 'get', '/products/heated-cat-bed').expect(403, FORBIDDEN);
      await as(sam, 'get', '/products/heated-cat-bed').expect(200);
      await as(null, 'get', '/products/cat-tree').expect(200);
    });

    it('leaves anonymous callers of an authenticated @Can() route to authentication: 401 with its challenge, no denial', async () => {
      const res = await as(null, 'post', '/products').send({ name: 'Anon', price: 1, published: true }).expect(401);
      expect(res.headers['www-authenticate']).toBe('Bearer realm="shop"');
      expect(events).toEqual([]);
    });

    it('rejects an invalid token in authentication, before any policy runs', async () => {
      const res = await http().post('/products').set('Authorization', 'Bearer not-a-jwt').send({}).expect(401);
      expect(res.headers['www-authenticate']).toMatch(/^Bearer realm="shop", error="invalid_token"/);
      expect(events).toEqual([]);
    });

    it('lets staff create and update products, and refuses customers with 403', async () => {
      await as(alice, 'post', '/products').send({ name: 'Denied', price: 1, published: true }).expect(403, FORBIDDEN);
      await as(sam, 'post', '/products')
        .send({ name: 'Cat Tunnel', price: 3999, published: false })
        .expect(201, { name: 'Cat Tunnel', price: 3999, published: false, id: 'cat-tunnel' });

      await as(bob, 'patch', '/products/cat-tunnel').send({ published: true }).expect(403);
      const updated = await as(sam, 'patch', '/products/cat-tunnel').send({ published: true }).expect(200);
      expect(updated.body.published).toBe(true);
    });

    it('lets only admins delete, through before()', async () => {
      await as(sam, 'delete', '/products/cat-tree').expect(403, FORBIDDEN);
      await as(ada, 'delete', '/products/cat-tree').expect(204);
      await as(null, 'get', '/products/cat-tree').expect(404);
    });

    it('reports each denial with the user authentication loaded, and the handler for @Can()', async () => {
      await as(alice, 'post', '/products').send({}).expect(403);
      await as(null, 'get', '/products/heated-cat-bed').expect(401);

      expect(events).toEqual([
        { type: 'denied', policy: 'ProductPolicy', ability: 'create', reason: 'forbidden', user: alice, args: [], handler: 'ProductsController.create' },
        {
          type: 'denied',
          policy: 'ProductPolicy',
          ability: 'view',
          reason: 'unauthenticated',
          user: null,
          args: [expect.objectContaining({ id: 'heated-cat-bed' })],
        },
      ]);
    });

    it('publishes the same denials on the nestjs:authorization:denied diagnostics channel', async () => {
      const published: unknown[] = [];
      const listener = (message: unknown) => published.push(message);
      subscribe('nestjs:authorization:denied', listener);

      try {
        await as(bob, 'delete', '/products/scratching-post').expect(403);
      } finally {
        unsubscribe('nestjs:authorization:denied', listener);
      }

      expect(published).toEqual(events);
      expect(published).toEqual([expect.objectContaining({ policy: 'ProductPolicy', ability: 'delete', user: bob, handler: 'ProductsController.remove' })]);
    });
  });

  describe('orders: record checks in the service', () => {
    it('asks guests to sign in: authentication answers before any policy', async () => {
      await as(null, 'get', '/orders').expect(401);
      expect(events).toEqual([]);
    });

    it("shows customers their own orders (can('viewAll') is false, and not a denial) and refuses someone else's with 403", async () => {
      const { body } = await as(alice, 'get', '/orders').expect(200);
      expect(body).toEqual([
        { ...alicePaid, canRefund: false },
        { ...aliceShipped, canRefund: false },
      ]);
      expect(events).toEqual([]);

      await as(alice, 'get', `/orders/${bobPaid.id}`).expect(403, FORBIDDEN);
      expect(events).toEqual([
        { type: 'denied', policy: 'OrderPolicy', ability: 'view', reason: 'forbidden', user: alice, args: [expect.objectContaining({ id: bobPaid.id })] },
      ]);
    });

    it('flags the orders staff may refund, with the limit the policy injects', async () => {
      const { body } = await as(sam, 'get', '/orders').expect(200);
      expect(body.map(({ id, canRefund }: { id: string; canRefund: boolean }) => [id, canRefund])).toEqual([
        [alicePaid.id, true],
        [aliceShipped.id, false],
        [bobPaid.id, false], // over Sam's limit
        [bobPending.id, false],
      ]);
    });

    it('lets staff refund a paid order once, within their limit, and an admin with a higher limit refund more', async () => {
      const refund = (user: User, id: string) => as(user, 'post', `/orders/${id}/refund`);

      await refund(alice, alicePaid.id).expect(403, FORBIDDEN);
      const refunded = await refund(sam, alicePaid.id).expect(200);
      expect(refunded.body).toMatchObject({ id: alicePaid.id, status: 'refunded', canRefund: false });
      await refund(sam, alicePaid.id).expect(403);
      await refund(sam, aliceShipped.id).expect(403);
      await refund(sam, bobPaid.id).expect(403);
      await refund(ada, bobPaid.id).expect(200);
      await refund(ada, bobPending.id).expect(403);
      await refund(sam, 'no-such-order').expect(404);

      expect(events.map(({ ability, reason, user }) => [ability, reason, (user as User).email])).toEqual([
        ['refund', 'forbidden', alice.email],
        ['refund', 'forbidden', sam.email],
        ['refund', 'forbidden', sam.email],
        ['refund', 'forbidden', sam.email],
        ['refund', 'forbidden', ada.email],
      ]);
    });

    it('rejects the token of a user deleted since, in authentication, with no denial', async () => {
      const token = await signIn(bob);
      await http().get('/orders').set('Authorization', token).expect(200);

      app.get(UsersRepository).delete(bob.id);
      const res = await http().get(`/orders/${bobPaid.id}`).set('Authorization', token).expect(401);
      expect(res.headers['www-authenticate']).toContain('error_description="unknown subject"');
      expect(events).toEqual([]);
    });
  });
});

describe.each(adapters.map((a) => a.name))('@nestjs/authentication with globalGuard: false (%s)', (adapter) => {
  @Controller('catalog')
  class CatalogController {
    @Post()
    @UseGuards(AuthenticationGuard, AuthorizationGuard)
    @Can(ProductPolicy, 'create')
    create() {
      return { created: true };
    }

    @Get('drafts')
    @Public()
    @UseGuards(AuthenticationGuard, AuthorizationGuard)
    @Can(ProductPolicy, 'viewDrafts')
    drafts() {
      return [];
    }
  }

  @Module({
    imports: [authenticationModule({ globalGuard: false }), AuthorizationModule.forRoot({ globalGuard: false }), AuthModule, ProductsModule],
    controllers: [CatalogController],
  })
  class ExplicitGuardsAppModule {}

  let app: INestApplication;
  const http = () => request(app.getHttpServer());
  const tokenOf = async (user: User) =>
    `Bearer ${(await http().post('/auth/token').send({ email: user.email, password: PASSWORD }).expect(200)).body.accessToken}`;

  const errors: string[] = [];

  beforeAll(async () => {
    vi.spyOn(Logger.prototype, 'error').mockImplementation((message: unknown) => void errors.push(String(message)));
    app = await boot(adapter, ExplicitGuardsAppModule);
  });
  afterAll(async () => {
    await app.close();
    vi.restoreAllMocks();
  });

  it('@UseGuards(AuthenticationGuard, AuthorizationGuard) authenticates first, then checks the policy', async () => {
    await http().post('/catalog').expect(401);
    await http().post('/catalog').set('Authorization', await tokenOf(alice)).expect(403, FORBIDDEN);
    await http().post('/catalog').set('Authorization', await tokenOf(sam)).expect(201, { created: true });
  });

  it('gives the policy null on a @Public() route, so a denial is 401 from authorization', async () => {
    const res = await http().get('/catalog/drafts').expect(401, UNAUTHORIZED);
    expect(res.headers['www-authenticate']).toBeUndefined();
  });

  it('leaves the routes without @UseGuards() to their own @Can()s unenforced, as the startup log said', async () => {
    expect(errors).toEqual([
      '@Can() is not enforced on ProductsController.create, ProductsController.update, ProductsController.remove: ' +
        'AuthorizationModule has globalGuard: false, and these handlers have no @UseGuards(AuthorizationGuard).',
    ]);
    await http().post('/products').send({ name: 'Open door', price: 1, published: true }).expect(201);
  });
});
