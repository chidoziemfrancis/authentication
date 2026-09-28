import { Injectable } from '@nestjs/common';
import type {
  EmailTokenPurpose,
  EmailTokenRecord,
  EmailTokenStore,
} from '../interfaces/email-token-store.interface.js';

const MAX_PENDING = 10_000;

/**
 * Process-local store: the default when no source is registered, and a
 * test double. Drops expired tokens as new ones are saved, and holds at
 * most 10,000, dropping the one that expires first.
 */
@Injectable()
export class InMemoryEmailTokenStore implements EmailTokenStore {
  private readonly tokens = new Map<string, EmailTokenRecord>();

  async saveEmailToken(record: EmailTokenRecord) {
    const now = record.createdAt.getTime();
    // Insertion order is close to expiry order (one lifetime per purpose): stop at the first
    // live entry; the cap bounds whatever that leaves behind.
    for (const [id, token] of this.tokens) {
      if (token.expiresAt.getTime() > now) {
        break;
      }
      this.tokens.delete(id);
    }

    this.tokens.set(record.id, { ...record });
    // Past the cap, the token that expires first goes, not the oldest: purposes have their own
    // lifetimes, and a flood of one-hour reset links must not push out a day-long verification link.
    if (this.tokens.size > MAX_PENDING) {
      let first: EmailTokenRecord | undefined;
      for (const token of this.tokens.values()) {
        if (!first || token.expiresAt.getTime() < first.expiresAt.getTime()) {
          first = token;
        }
      }
      this.tokens.delete(first!.id);
    }
  }

  async consumeEmailToken(id: string, purpose: EmailTokenPurpose) {
    const record = this.tokens.get(id);
    if (record?.purpose !== purpose) {
      return undefined;
    }
    this.tokens.delete(id);
    return record;
  }

  async deleteUserEmailTokens(userId: string, purpose: EmailTokenPurpose) {
    for (const [id, token] of this.tokens) {
      if (token.userId === userId && token.purpose === purpose) {
        this.tokens.delete(id);
      }
    }
  }
}
