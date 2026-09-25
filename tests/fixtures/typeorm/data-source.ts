import { DataSource, type DataSourceOptions } from 'typeorm';
import {
  EmailTokenEntity,
  MagicLinkEntity,
  MfaAuthenticatorEntity,
  MfaFailureEntity,
  MfaRecoveryCodeEntity,
  OidcLoginEntity,
  RefreshTokenEntity,
  SessionEntity,
} from './authentication.entities.js';
import { Authentication1790235914534 } from './migrations/1790235914534-Authentication.js';

/** What the application's TypeOrmModule and the TypeORM CLI share. */
export const dataSourceOptions = {
  type: 'postgres',
  url: process.env.DATABASE_URL,
  entities: [
    SessionEntity,
    RefreshTokenEntity,
    MfaAuthenticatorEntity,
    MfaRecoveryCodeEntity,
    MfaFailureEntity,
    MagicLinkEntity,
    OidcLoginEntity,
    EmailTokenEntity,
  ],
  migrations: [Authentication1790235914534],
} satisfies DataSourceOptions;

// The TypeORM CLI's data source: `migration:generate` compares the entities with this database.
export default new DataSource(dataSourceOptions);
