import type { EmailTokenPurpose, MfaState } from '../../../lib/index.js';
import { Column, Entity, Index, PrimaryColumn, PrimaryGeneratedColumn } from 'typeorm';

// The authentication tables, read and written by TypeOrmAuthenticationStore: the same
// tables as the Drizzle schema in ../database/schema.ts. Every column states its type, so
// the entities load the same with or without emitted decorator metadata (the TypeORM CLI
// runs them through tsx, which emits none). Tokens, links and sessions are stored by their
// SHA-256; TOTP secrets arrive encrypted.

/** What a `jsonb` column holds: a column typed `unknown` doesn't fit TypeORM's insert types. */
export type Json = object | string | number | boolean | null;

@Entity('sessions')
@Index('sessions_user_id_idx', ['userId'])
@Index('sessions_expires_at_idx', ['expiresAt'])
export class SessionEntity {
  @PrimaryColumn({ type: 'text' })
  id!: string;

  @Column({ type: 'text', name: 'user_id' })
  userId!: string;

  @Column({ type: 'timestamptz', name: 'created_at' })
  createdAt!: Date;

  @Column({ type: 'timestamptz', name: 'expires_at' })
  expiresAt!: Date;

  @Column({ type: 'timestamptz', name: 'last_active_at' })
  lastActiveAt!: Date;

  @Column({ type: 'text', nullable: true })
  mfa!: MfaState | null;

  @Column({ type: 'jsonb', nullable: true })
  metadata!: Record<string, Json> | null;
}

@Entity('refresh_tokens')
@Index('refresh_tokens_family_id_idx', ['familyId'])
@Index('refresh_tokens_user_id_idx', ['userId'])
@Index('refresh_tokens_family_expires_at_idx', ['familyExpiresAt'])
export class RefreshTokenEntity {
  @PrimaryColumn({ type: 'text' })
  id!: string;

  @Column({ type: 'text', name: 'family_id' })
  familyId!: string;

  @Column({ type: 'text', name: 'user_id' })
  userId!: string;

  @Column({ type: 'timestamptz', name: 'created_at' })
  createdAt!: Date;

  @Column({ type: 'timestamptz', name: 'expires_at' })
  expiresAt!: Date;

  @Column({ type: 'timestamptz', name: 'family_expires_at' })
  familyExpiresAt!: Date;

  @Column({ type: 'timestamptz', name: 'used_at', nullable: true })
  usedAt!: Date | null;

  // A family is revoked when any of its tokens is: that covers a successor saved after the revocation.
  @Column({ type: 'boolean', default: false })
  revoked!: boolean;

  @Column({ type: 'jsonb', nullable: true })
  claims!: Record<string, Json> | null;
}

@Entity('mfa_authenticators')
export class MfaAuthenticatorEntity {
  @PrimaryColumn({ type: 'text', name: 'user_id' })
  userId!: string;

  @Column({ type: 'text' })
  secret!: string;

  @Column({ type: 'boolean' })
  confirmed!: boolean;

  @Column({ type: 'text', name: 'pending_secret', nullable: true })
  pendingSecret!: string | null;

  @Column({ type: 'integer', name: 'last_used_step', nullable: true })
  lastUsedStep!: number | null;
}

@Entity('mfa_recovery_codes')
export class MfaRecoveryCodeEntity {
  @PrimaryColumn({ type: 'text', name: 'user_id' })
  userId!: string;

  @PrimaryColumn({ type: 'text', name: 'code_hash' })
  codeHash!: string;
}

@Entity('mfa_failures')
@Index('mfa_failures_user_id_failed_at_idx', ['userId', 'failedAt'])
@Index('mfa_failures_failed_at_idx', ['failedAt'])
export class MfaFailureEntity {
  @PrimaryGeneratedColumn('identity', { type: 'integer', generatedIdentity: 'ALWAYS' })
  id!: number;

  @Column({ type: 'text', name: 'user_id' })
  userId!: string;

  @Column({ type: 'timestamptz', name: 'failed_at' })
  failedAt!: Date;
}

@Entity('magic_links')
@Index('magic_links_expires_at_idx', ['expiresAt'])
export class MagicLinkEntity {
  @PrimaryColumn({ type: 'text' })
  id!: string;

  @Column({ type: 'text' })
  email!: string;

  @Column({ type: 'timestamptz', name: 'created_at' })
  createdAt!: Date;

  @Column({ type: 'timestamptz', name: 'expires_at' })
  expiresAt!: Date;

  @Column({ type: 'text', name: 'redirect_to', nullable: true })
  redirectTo!: string | null;
}

@Entity('oidc_logins')
@Index('oidc_logins_expires_at_idx', ['expiresAt'])
export class OidcLoginEntity {
  @PrimaryColumn({ type: 'text' })
  state!: string;

  @Column({ type: 'text' })
  provider!: string;

  @Column({ type: 'text', name: 'code_verifier' })
  codeVerifier!: string;

  @Column({ type: 'text', nullable: true })
  nonce!: string | null;

  @Column({ type: 'text', name: 'redirect_to', nullable: true })
  redirectTo!: string | null;

  // Set for "connect your Google account" from a signed-in session.
  @Column({ type: 'text', name: 'link_user_id', nullable: true })
  linkUserId!: string | null;

  @Column({ type: 'text', name: 'link_session_id', nullable: true })
  linkSessionId!: string | null;

  @Column({ type: 'timestamptz', name: 'created_at' })
  createdAt!: Date;

  @Column({ type: 'timestamptz', name: 'expires_at' })
  expiresAt!: Date;
}

@Entity('email_tokens')
@Index('email_tokens_user_id_purpose_idx', ['userId', 'purpose'])
@Index('email_tokens_expires_at_idx', ['expiresAt'])
export class EmailTokenEntity {
  @PrimaryColumn({ type: 'text' })
  id!: string;

  @Column({ type: 'text' })
  purpose!: EmailTokenPurpose;

  @Column({ type: 'text', name: 'user_id' })
  userId!: string;

  @Column({ type: 'text' })
  email!: string;

  @Column({ type: 'text', nullable: true })
  fingerprint!: string | null;

  @Column({ type: 'timestamptz', name: 'created_at' })
  createdAt!: Date;

  @Column({ type: 'timestamptz', name: 'expires_at' })
  expiresAt!: Date;
}
