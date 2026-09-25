/**
 * The README's "Testing" section, applied to the tutorial's app with the real
 * `@nestjs/authentication`: keep the app's configuration and replace what the test needs.
 */
import type { INestApplication } from '@nestjs/common';
import request from 'supertest';
import { adapters, createApp } from './support/adapters.js';
import { PasswordHasher, TokenService } from '../lib/index.js';
import {
  AUTHORIZATION_MODULE_OPTIONS,
  AuthorizationError,
  AuthorizationEvents,
  AuthorizationService,
  type AuthorizationDeniedEvent,
} from '@nestjs/authorization';
import {
  alice,
  alicePaid,
  aliceShipped,
  ProductPolicy,
  bobPaid,
  bobPending,
  cheapHasher,
  OrderPolicy,
  OrdersService,
  sam,
  TutorialAppModule,
  type User,
} from './fixtures/authorization-tutorial.js';

describe.each(adapters.map((a) => a.name))('testing an app that uses authorization (%s)', (adapter) => {
  let app: INestApplication | undefined;
  afterEach(async () => {
    await app?.close();
    app = undefined;
  });

  const bearer = async (user: User) => `Bearer ${(await app!.get(TokenService).issue(user.id)).accessToken}`;

  it('overriding a policy replaces what route and service checks run against', async () => {
    app = await createApp(adapter, TutorialAppModule, {
      override: (builder) =>
        builder
          .overrideProvider(PasswordHasher)
          .useValue(cheapHasher())
          .overrideProvider(OrderPolicy)
          .useValue({ viewAll: () => true, view: () => true, refund: async () => true }),
    });
    const token = await bearer(alice);

    const { body } = await request(app.getHttpServer()).get('/orders').set('Authorization', token).expect(200);
    expect(body.map(({ id, canRefund }: { id: string; canRefund: boolean }) => [id, canRefund])).toEqual([
      [alicePaid.id, true],
      [aliceShipped.id, true],
      [bobPaid.id, true],
      [bobPending.id, true],
    ]);
    await request(app.getHttpServer()).post(`/orders/${bobPending.id}/refund`).set('Authorization', token).expect(200);
  });

  it('fails the startup when a policy override lacks an ability a @Can() names', async () => {
    const booting = createApp(adapter, TutorialAppModule, {
      override: (builder) =>
        builder.overrideProvider(PasswordHasher).useValue(cheapHasher()).overrideProvider(ProductPolicy).useValue({ view: () => true }),
    });

    await expect(booting).rejects.toThrow("@Can(ProductPolicy, 'create') on ProductsController.create: ProductPolicy has no ability 'create'.");
  });

  it('overriding AUTHORIZATION_MODULE_OPTIONS changes only what @Can() sees: authentication still answers 401 first', async () => {
    app = await createApp(adapter, TutorialAppModule, {
      override: (builder) =>
        builder
          .overrideProvider(PasswordHasher)
          .useValue(cheapHasher())
          .overrideProvider(AUTHORIZATION_MODULE_OPTIONS)
          .useValue({ getUser: () => sam }),
    });
    const http = () => request(app!.getHttpServer());
    const draft = { name: 'Override', price: 1, published: false };

    await http().post('/products').send(draft).expect(401);
    await http().post('/products').set('Authorization', await bearer(alice)).send(draft).expect(201);

    // The service check gets @CurrentUser(), which is still authentication's user.
    await http().get('/products/heated-cat-bed').expect(401);
    await http().get('/products/heated-cat-bed').set('Authorization', await bearer(alice)).expect(403);
  });

  it('asserts service denials without HTTP, and records them on events$', async () => {
    app = await createApp(adapter, TutorialAppModule, {
      override: (builder) => builder.overrideProvider(PasswordHasher).useValue(cheapHasher()),
    });
    const events: AuthorizationDeniedEvent[] = [];
    app.get(AuthorizationEvents).events$.subscribe((event) => events.push(event));
    const orders = app.get(OrdersService);

    await expect(orders.refund(sam, bobPaid.id)).rejects.toThrow(AuthorizationError);
    await expect(orders.refund(sam, bobPaid.id)).rejects.toMatchObject({ reason: 'forbidden', ability: 'refund', status: 403 });
    expect(await app.get(AuthorizationService).can(OrderPolicy, 'refund', sam, alicePaid)).toBe(true);
    await expect(orders.refund(sam, alicePaid.id)).resolves.toMatchObject({ status: 'refunded' });

    expect(events.map(({ policy, ability, user }) => [policy, ability, user])).toEqual([
      ['OrderPolicy', 'refund', sam],
      ['OrderPolicy', 'refund', sam],
    ]);
  });
});
