import { Injectable } from '@nestjs/common';
import type { OidcTransaction } from '../interfaces/oidc.interface.js';
import type { OidcStateStore } from '../interfaces/oidc-state-store.interface.js';

const MAX_PENDING = 10_000;

/**
 * Process-local store: the default when no source is registered, and a
 * test double. Drops expired logins as new ones are saved, and holds at
 * most 10,000, dropping the oldest: anyone can start a login, so the store
 * must not grow with them.
 */
@Injectable()
export class InMemoryOidcStateStore implements OidcStateStore {
  private readonly pending = new Map<string, OidcTransaction>();

  async saveOidcState(transaction: OidcTransaction) {
    const now = transaction.createdAt.getTime();
    // Insertion order is expiry order (one lifetime per service): stop at the first live entry.
    for (const [state, tx] of this.pending) {
      if (tx.expiresAt.getTime() > now) {
        break;
      }
      this.pending.delete(state);
    }

    this.pending.set(transaction.state, { ...transaction });

    for (const state of this.pending.keys()) {
      if (this.pending.size <= MAX_PENDING) {
        break;
      }
      this.pending.delete(state); // insertion order: the oldest first
    }
  }
  async consumeOidcState(state: string) {
    const tx = this.pending.get(state);
    this.pending.delete(state);
    return tx;
  }
}
