import type { ExecutionContext } from '@nestjs/common';

/**
 * The token a bearer provider reads: the `Authorization: Bearer` header's,
 * else, over socket.io, `handshake.auth.token`. `undefined` when there is
 * none, or the header names another scheme (another provider's).
 * `null` for a Bearer header without exactly one token (RFC 6750 §3.1
 * `invalid_request`, answered as `invalid_token` like any bad credential).
 */
export function bearerToken(context: ExecutionContext, authorization: string | undefined): string | null | undefined {
  if (authorization) {
    const [scheme, token, ...rest] = authorization.trim().split(/\s+/);
    if (scheme.toLowerCase() !== 'bearer') {
      return undefined;
    }
    return token && !rest.length ? token : null;
  }

  if (context.getType() === 'ws') {
    const token = context.switchToWs().getClient()?.handshake?.auth?.token;
    return typeof token === 'string' ? token : undefined;
  }

  return undefined;
}
