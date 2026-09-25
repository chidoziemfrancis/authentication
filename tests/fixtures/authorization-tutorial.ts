/**
 * The authorization tutorial's app, trimmed to what the integration specs drive: the real
 * `@nestjs/authentication` signs users in with a password and authenticates them with a JWT,
 * and `@nestjs/authorization` checks products on routes and orders in services.
 */
import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  Injectable,
  Module,
  NotFoundException,
  Param,
  Patch,
  Post,
  UnauthorizedException,
  type OnModuleInit,
} from '@nestjs/common';
import {
  Authenticate,
  AuthenticationModule,
  AuthenticationRegistry,
  CurrentUser,
  JwtBearerProvider,
  PasswordHasher,
  Public,
  TokenService,
  type JwtClaims,
} from '../../lib/index.js';
import { AuthorizationModule, AuthorizationService, Can, Policy, type PolicyBefore } from '@nestjs/authorization';

// ---- Users --------------------------------------------------------------

export type Role = 'customer' | 'staff' | 'admin';

export interface User {
  id: string;
  email: string;
  emailVerified: boolean;
  roles: Role[];
}

export const alice: User = { id: '1f794c55-472e-42b9-8913-4114964ed6fb', email: 'alice@example.com', emailVerified: true, roles: ['customer'] };
export const bob: User = { id: 'fc27b5c1-62b5-494e-9924-28a66d387fd1', email: 'bob@example.com', emailVerified: true, roles: ['customer'] };
export const sam: User = { id: '208a223b-3503-4255-83e7-22d290e331c3', email: 'sam@example.com', emailVerified: true, roles: ['staff'] };
export const ada: User = { id: 'ae34ca97-f82b-49ab-b332-8808f3b0e240', email: 'ada@example.com', emailVerified: true, roles: ['staff', 'admin'] };

export const PASSWORD = 'catnip4all';

@Injectable()
export class UsersRepository implements OnModuleInit {
  private readonly rows = new Map<string, User & { passwordHash: string }>();

  constructor(private readonly passwordHasher: PasswordHasher) {}

  async onModuleInit() {
    const passwordHash = await this.passwordHasher.hash(PASSWORD);
    for (const user of [alice, bob, sam, ada]) {
      this.rows.set(user.id, { ...user, passwordHash });
    }
  }

  async findById(id: string): Promise<User | null> {
    const row = this.rows.get(id);
    return row ? toUser(row) : null;
  }

  async findCredentials(email: string) {
    const row = [...this.rows.values()].find((candidate) => candidate.email === email);
    return row ? { user: toUser(row), passwordHash: row.passwordHash } : null;
  }

  delete(id: string) {
    this.rows.delete(id);
  }
}

const toUser = ({ id, email, emailVerified, roles }: User): User => ({ id, email, emailVerified, roles: [...roles] });

// ---- Authentication -----------------------------------------------------

@Injectable()
export class JwtAuth extends JwtBearerProvider<User> {
  constructor(
    private readonly usersRepository: UsersRepository,
    registry: AuthenticationRegistry,
  ) {
    super({ realm: 'shop' });
    registry.registerProvider(this);
  }

  validate({ sub }: JwtClaims) {
    return sub ? this.usersRepository.findById(sub) : null;
  }
}

@Public()
@Controller('auth/token')
export class TokensController {
  constructor(
    private readonly usersRepository: UsersRepository,
    private readonly passwordHasher: PasswordHasher,
    private readonly tokenService: TokenService,
  ) {}

  @Post()
  @HttpCode(200)
  async issue(@Body() body: { email: string; password: string }) {
    const found = await this.usersRepository.findCredentials(body.email);
    const valid = await this.passwordHasher.verify(body.password, found?.passwordHash);
    if (!valid || !found) {
      throw new UnauthorizedException('Invalid email or password');
    }

    return this.tokenService.issue(found.user.id, { method: 'password', claims: { amr: ['pwd'] } });
  }
}

@Module({
  controllers: [TokensController],
  providers: [UsersRepository, JwtAuth],
  exports: [UsersRepository],
})
export class AuthModule {}

// ---- Products: checks on routes -----------------------------------------

export interface Product {
  id: string;
  name: string;
  price: number;
  published: boolean;
}

const isStaff = (user: User | null) => !!user?.roles.includes('staff');

@Policy()
export class ProductPolicy implements PolicyBefore<User> {
  before(user: User | null) {
    if (user?.roles.includes('admin')) {
      return true;
    }
    return undefined;
  }

  view(user: User | null, product: Product) {
    return product.published || isStaff(user);
  }

  viewDrafts(user: User | null) {
    return isStaff(user);
  }

  create(user: User | null) {
    return isStaff(user);
  }

  update(user: User | null) {
    return isStaff(user);
  }

  delete(_user: User | null) {
    return false;
  }
}

@Injectable()
export class ProductsService {
  private readonly products: Product[] = [
    { id: 'scratching-post', name: 'Scratching Post', price: 4299, published: true },
    { id: 'cat-tree', name: 'Cat Tree', price: 4999, published: true },
    { id: 'heated-cat-bed', name: 'Heated Cat Bed', price: 4500, published: false },
  ];

  constructor(private readonly authorizationService: AuthorizationService) {}

  async findAll(user: User | null) {
    const withDrafts = await this.authorizationService.can(ProductPolicy, 'viewDrafts', user);
    return withDrafts ? this.products : this.products.filter((product) => product.published);
  }

  async findOne(user: User | null, id: string) {
    const product = this.find(id);
    await this.authorizationService.authorize(ProductPolicy, 'view', user, product);
    return product;
  }

  create(input: Omit<Product, 'id'>) {
    const product = { ...input, id: input.name.toLowerCase().replace(/[^a-z0-9]+/g, '-') };
    this.products.push(product);
    return product;
  }

  update(id: string, changes: Partial<Product>) {
    return Object.assign(this.find(id), changes);
  }

  remove(id: string) {
    this.products.splice(this.products.indexOf(this.find(id)), 1);
  }

  private find(id: string) {
    const product = this.products.find((candidate) => candidate.id === id);
    if (!product) {
      throw new NotFoundException();
    }
    return product;
  }
}

@Controller('products')
export class ProductsController {
  constructor(private readonly productsService: ProductsService) {}

  @Get()
  @Authenticate({ optional: true })
  findAll(@CurrentUser() user: User | null) {
    return this.productsService.findAll(user);
  }

  @Get(':id')
  @Authenticate({ optional: true })
  findOne(@CurrentUser() user: User | null, @Param('id') id: string) {
    return this.productsService.findOne(user, id);
  }

  @Post()
  @Can(ProductPolicy, 'create')
  create(@Body() input: Omit<Product, 'id'>) {
    return this.productsService.create(input);
  }

  @Patch(':id')
  @Can(ProductPolicy, 'update')
  update(@Param('id') id: string, @Body() changes: Partial<Product>) {
    return this.productsService.update(id, changes);
  }

  @Delete(':id')
  @HttpCode(204)
  @Can(ProductPolicy, 'delete')
  remove(@Param('id') id: string) {
    this.productsService.remove(id);
  }
}

@Module({ controllers: [ProductsController], providers: [ProductsService, ProductPolicy] })
export class ProductsModule {}

// ---- Orders: checks in services -----------------------------------------

export interface Order {
  id: string;
  userId: string;
  total: number;
  status: 'pending' | 'paid' | 'shipped' | 'refunded';
}

export const alicePaid: Order = { id: 'b69f25e7-db50-4abe-86d3-2ef2bd148009', userId: alice.id, total: 4299, status: 'paid' };
export const aliceShipped: Order = { id: 'd626a0c1-4122-4f83-ab7a-b009c26f35c7', userId: alice.id, total: 4999, status: 'shipped' };
export const bobPaid: Order = { id: '0ea8343b-879d-4b83-884b-6d5bb02f802f', userId: bob.id, total: 17196, status: 'paid' };
export const bobPending: Order = { id: '7e7023d3-cb2a-48d2-8c4e-20c07e6b8c06', userId: bob.id, total: 4999, status: 'pending' };

@Injectable()
export class RefundLimitsService {
  private readonly limits = new Map<string, number>([[ada.id, 100_000]]);

  async maxRefundFor(user: User): Promise<number> {
    return this.limits.get(user.id) ?? 10_000;
  }
}

@Policy()
export class OrderPolicy {
  constructor(private readonly refundLimitsService: RefundLimitsService) {}

  viewAll(user: User) {
    return user.roles.includes('staff');
  }

  view(user: User, order: Order) {
    return order.userId === user.id || user.roles.includes('staff');
  }

  async refund(user: User, order: Order) {
    if (!user.roles.includes('staff') || order.status !== 'paid') {
      return false;
    }
    return order.total <= (await this.refundLimitsService.maxRefundFor(user));
  }
}

export type OrderView = Order & { canRefund: boolean };

@Injectable()
export class OrdersService {
  private readonly orders: Order[] = [alicePaid, aliceShipped, bobPaid, bobPending].map((order) => ({ ...order }));

  constructor(private readonly authorizationService: AuthorizationService) {}

  async findAll(user: User): Promise<OrderView[]> {
    const orders = (await this.authorizationService.can(OrderPolicy, 'viewAll', user))
      ? this.orders
      : this.orders.filter((order) => order.userId === user.id);
    return Promise.all(orders.map((order) => this.toView(user, order)));
  }

  async findOne(user: User, id: string): Promise<OrderView> {
    const order = this.find(id);
    await this.authorizationService.authorize(OrderPolicy, 'view', user, order);
    return this.toView(user, order);
  }

  async refund(user: User, id: string): Promise<OrderView> {
    const order = this.find(id);
    await this.authorizationService.authorize(OrderPolicy, 'refund', user, order);
    order.status = 'refunded';
    return this.toView(user, order);
  }

  private async toView(user: User, order: Order): Promise<OrderView> {
    return { ...order, canRefund: await this.authorizationService.can(OrderPolicy, 'refund', user, order) };
  }

  private find(id: string) {
    const order = this.orders.find((candidate) => candidate.id === id);
    if (!order) {
      throw new NotFoundException();
    }
    return order;
  }
}

@Controller('orders')
export class OrdersController {
  constructor(private readonly ordersService: OrdersService) {}

  @Get()
  findAll(@CurrentUser() user: User) {
    return this.ordersService.findAll(user);
  }

  @Get(':id')
  findOne(@CurrentUser() user: User, @Param('id') id: string) {
    return this.ordersService.findOne(user, id);
  }

  @Post(':id/refund')
  @HttpCode(200)
  refund(@CurrentUser() user: User, @Param('id') id: string) {
    return this.ordersService.refund(user, id);
  }
}

@Module({ controllers: [OrdersController], providers: [OrdersService, OrderPolicy, RefundLimitsService] })
export class OrdersModule {}

// ---- The app ------------------------------------------------------------

export const JWT_SECRET = 'authorization-integration-secret-of-32-bytes!';

export const authenticationModule = (options: { globalGuard?: boolean } = {}) =>
  AuthenticationModule.forRoot({
    accessToken: { key: JWT_SECRET, issuer: 'https://api.example.com', audience: 'shop-mobile', ttl: '15m' },
    ...options,
  });

@Module({
  imports: [
    // Authentication first: its guard sets request.user, which authorization reads.
    authenticationModule(),
    AuthorizationModule.forRoot(),
    AuthModule,
    ProductsModule,
    OrdersModule,
  ],
})
export class TutorialAppModule {}

/** scrypt is slow on purpose; the tests don't need it to be. */
export const cheapHasher = () => new PasswordHasher({ logN: 10 });
