import type { IncomingMessage } from 'node:http';
import { Injectable, Logger, type ExecutionContext } from '@nestjs/common';
import { ExecutionContextHost } from '@nestjs/core/internal';
import { setAuthState } from '../utils/auth-state.util.js';
import { AuthenticationError } from '../errors/authentication.error.js';
import type { AuthenticationResult } from '../interfaces/authentication-result.interface.js';
import { AuthenticationRegistry } from './authentication-registry.service.js';

interface ClosableClient {
  close?(code?: number, reason?: string): void;
  disconnect?(close?: boolean): void;
  [key: PropertyKey]: any;
}

class WsHandshake {
  handleConnection() {}
}

/**
 * Handshake authentication for gateways. Nest does not run guards on
 * `handleConnection`, so the gateway calls this:
 *
 * ```ts
 * async handleConnection(client: WebSocket, request: IncomingMessage) {
 *   await this.wsAuth.authenticateConnection(client, request);
 * }
 * ```
 *
 * It stores the upgrade request on `client.request` (the `ws` library does
 * not), so providers can read headers again for each message; the global
 * guard re-authenticates every message, so a revoked session stops working
 * mid-connection.
 *
 * It never rejects: Nest drops the promise `handleConnection` returns, so a
 * rejection would be unhandled, which ends the Node.js process. A provider
 * or store that fails (a Redis outage) is logged, and the connection is
 * closed with 1011.
 */
@Injectable()
export class WsAuthenticator {
  private static readonly logger = new Logger('WsAuthenticator');

  constructor(private readonly registry: AuthenticationRegistry) {}

  async authenticateConnection(
    client: ClosableClient,
    request?: IncomingMessage,
    { required = true }: { required?: boolean } = {},
  ): Promise<AuthenticationResult<unknown, unknown> | null> {
    if (request && !client.handshake) {
      client.request = request;
    }

    const context = new ExecutionContextHost([client, undefined], WsHandshake, WsHandshake.prototype.handleConnection);
    context.setType('ws');

    let result: AuthenticationResult<unknown, unknown> | null = null;
    try {
      result = await this.run(context);
    } catch (error) {
      if (!(error instanceof AuthenticationError)) {
        WsAuthenticator.logger.error('Authenticating a WebSocket connection failed', (error as Error)?.stack);
        close(client, 1011, 'Internal Error'); // RFC 6455 §7.4.1
        return null;
      }
    }

    if (result?.mfa === 'pending') {
      result = null;
    }

    setAuthState(context, result);
    if (!result && required) {
      close(client, 1008, 'Unauthorized'); // policy violation
    }

    return result;
  }

  private async run(context: ExecutionContext) {
    for (const provider of this.registry.providers) {
      const result = await provider.authenticate(context);
      if (result?.user) {
        return result;
      }
    }
    return null;
  }
}

function close(client: ClosableClient, code: number, reason: string) {
  if (client.close) {
    client.close(code, reason);
  } else {
    client.disconnect?.(true); // socket.io
  }
}
