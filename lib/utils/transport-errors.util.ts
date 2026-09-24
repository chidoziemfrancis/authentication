import { ConflictException, ForbiddenException, UnauthorizedException, type ExecutionContext } from '@nestjs/common';
import type { HttpAdapterHost } from '@nestjs/core';

type ErrorCtor = new (error: string | object) => Error;
const loaded = new Map<string, Promise<ErrorCtor | undefined>>();

/** Lazily loads an optional peer's exception class, once. */
function load(pkg: '@nestjs/websockets' | '@nestjs/microservices', name: string) {
  let pending = loaded.get(pkg);
  if (!pending) {
    pending = import(pkg).then(
      (mod: Record<string, unknown>) => mod[name] as ErrorCtor,
      () => undefined,
    );
    loaded.set(pkg, pending);
  }
  return pending;
}

export interface Refusal {
  /** Default 401. 403 for a user the route refuses (an unverified address), 409 for a conflict (`MfaAlreadyEnrolledError`). */
  status?: 401 | 403 | 409;
  /** Default `Unauthorized`. */
  message?: string;
  /** Machine-readable reason (`mfa_required`), in the body's `error` field. */
  code?: string;
  /** The error behind the refusal, kept as the exception's `cause` for logs. */
  cause?: unknown;
}

const DEFAULT_MESSAGE = 'Unauthorized';

/**
 * The one place this package's refusals become responses, for the guard and
 * for `AuthenticationError`s thrown by handlers: the error each transport's
 * exception filter understands, for the refusal's status.
 *
 * - HTTP and GraphQL: Nest's own `UnauthorizedException` (or
 *   `ForbiddenException` for a 403, `ConflictException` for a 409), so the body is Nest's own:
 *   `{"message":"Unauthorized","statusCode":401}`, or with a message,
 *   `{"message":"Refresh token reused","error":"Unauthorized","statusCode":401}`.
 *   A `code` replaces `error`. Over HTTP, `challenge` becomes the
 *   `WWW-Authenticate` header of a 401.
 * - ws and rpc: a `WsException` / `RpcException` carrying
 *   `{ statusCode, message }` (plus `status: 'error'` for ws, and `error`
 *   with a `code`). Those filters report `HttpException`s as "Internal
 *   server error", hence their own classes, loaded only when the packages
 *   are installed.
 */
export async function refusal(
  context: ExecutionContext,
  { status = 401, message = DEFAULT_MESSAGE, code, cause }: Refusal = {},
  { challenge, adapterHost }: { challenge?: string; adapterHost?: HttpAdapterHost } = {},
): Promise<Error> {
  const payload = { statusCode: status, ...(code && { error: code }), message };
  switch (context.getType<string>()) {
    case 'ws': {
      const WsException = await load('@nestjs/websockets', 'WsException');
      if (WsException) {
        return withCause(new WsException({ status: 'error', ...payload }), cause);
      }
      break;
    }
    case 'rpc': {
      const RpcException = await load('@nestjs/microservices', 'RpcException');
      if (RpcException) {
        return withCause(new RpcException(payload), cause);
      }
      break;
    }
    case 'http':
      if (challenge && status === 401) {
        adapterHost?.httpAdapter?.setHeader(context.switchToHttp().getResponse(), 'WWW-Authenticate', challenge);
      }
      break;
  }

  const options = { cause, ...(code && { description: code }) };
  if (status === 409) {
    return new ConflictException(message, options);
  }
  if (status === 403) {
    return new ForbiddenException(message, options);
  }

  // The default message gives the body of a bare `new UnauthorizedException()`.
  return message === DEFAULT_MESSAGE && !code
    ? new UnauthorizedException(undefined, options)
    : new UnauthorizedException(message, options);
}

function withCause(error: Error, cause: unknown): Error {
  if (cause !== undefined) {
    error.cause = cause;
  }
  return error;
}
