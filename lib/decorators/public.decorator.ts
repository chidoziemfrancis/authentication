import { route } from './authenticate.decorator.js';

/**
 * Skips authentication: no provider runs, and `@CurrentUser()` is `null`.
 * For health checks, the public catalog, and the routes that sign users in.
 * To `@nestjs/authorization` it means `@Can.Anyone()`: a `@Public()` method
 * lifts its class's `@Can()`, and a `@Can()` on the method itself still
 * applies, to a guest.
 */
export const Public = () => route({ public: true });
