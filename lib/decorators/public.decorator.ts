import { route } from './authenticate.decorator.js';

/**
 * Skips authentication: no provider runs, and `@CurrentUser()` is `null`.
 * For health checks, the public catalog, and the routes that sign users in.
 */
export const Public = () => route({ public: true });
