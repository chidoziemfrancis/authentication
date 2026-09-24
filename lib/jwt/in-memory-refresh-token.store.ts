import { Injectable } from '@nestjs/common';
import type { RefreshTokenRecord, RefreshTokenStore } from '../interfaces/refresh-token-store.interface.js';

/**
 * Process-local store: the default when no source is registered, and a
 * test double. Families past their absolute expiry are dropped as new
 * tokens are written, so an app that runs for months does not grow without
 * bound.
 */
@Injectable()
export class InMemoryRefreshTokenStore implements RefreshTokenStore {
  private readonly tokens = new Map<string, RefreshTokenRecord>();
  private readonly revoked = new Set<string>();
  private sweepAt = 1_024;

  async getRefreshToken(id: string) {
    const record = this.tokens.get(id);
    return record && { ...record };
  }
  async saveRefreshToken(record: RefreshTokenRecord) {
    this.tokens.set(record.id, { ...record });
    // The new token's own clock, so tests with a fake one agree.
    if (this.tokens.size >= this.sweepAt) {
      this.sweep(record.createdAt.getTime());
    }
  }
  async markRefreshTokenUsed(id: string, at: Date) {
    const record = this.tokens.get(id);
    if (!record || record.usedAt) {
      return false;
    }
    record.usedAt = at;
    return true;
  }
  async revokeRefreshTokenFamily(familyId: string) {
    this.revoked.add(familyId);
  }
  async isRefreshTokenFamilyRevoked(familyId: string) {
    return this.revoked.has(familyId);
  }
  async revokeUserRefreshTokens(userId: string) {
    for (const record of this.tokens.values()) {
      if (record.userId === userId) {
        this.revoked.add(record.familyId);
      }
    }
  }

  /** Drops families past their absolute expiry (every token of a family shares it), and their revocation. */
  private sweep(now: number) {
    for (const [id, record] of this.tokens) {
      if (record.familyExpiresAt.getTime() > now) {
        continue;
      }
      this.tokens.delete(id);
      this.revoked.delete(record.familyId);
    }

    this.sweepAt = Math.max(1_024, this.tokens.size * 2);
  }
}
