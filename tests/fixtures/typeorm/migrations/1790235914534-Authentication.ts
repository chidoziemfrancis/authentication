import { MigrationInterface, QueryRunner } from "typeorm";

export class Authentication1790235914534 implements MigrationInterface {
    name = 'Authentication1790235914534'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`
            CREATE TABLE "sessions" (
                "id" text NOT NULL,
                "user_id" text NOT NULL,
                "created_at" TIMESTAMP WITH TIME ZONE NOT NULL,
                "expires_at" TIMESTAMP WITH TIME ZONE NOT NULL,
                "last_active_at" TIMESTAMP WITH TIME ZONE NOT NULL,
                "mfa" text,
                "metadata" jsonb,
                CONSTRAINT "PK_3238ef96f18b355b671619111bc" PRIMARY KEY ("id")
            )
        `);
        await queryRunner.query(`
            CREATE INDEX "sessions_expires_at_idx" ON "sessions" ("expires_at")
        `);
        await queryRunner.query(`
            CREATE INDEX "sessions_user_id_idx" ON "sessions" ("user_id")
        `);
        await queryRunner.query(`
            CREATE TABLE "refresh_tokens" (
                "id" text NOT NULL,
                "family_id" text NOT NULL,
                "user_id" text NOT NULL,
                "created_at" TIMESTAMP WITH TIME ZONE NOT NULL,
                "expires_at" TIMESTAMP WITH TIME ZONE NOT NULL,
                "family_expires_at" TIMESTAMP WITH TIME ZONE NOT NULL,
                "used_at" TIMESTAMP WITH TIME ZONE,
                "revoked" boolean NOT NULL DEFAULT false,
                "claims" jsonb,
                CONSTRAINT "PK_7d8bee0204106019488c4c50ffa" PRIMARY KEY ("id")
            )
        `);
        await queryRunner.query(`
            CREATE INDEX "refresh_tokens_family_expires_at_idx" ON "refresh_tokens" ("family_expires_at")
        `);
        await queryRunner.query(`
            CREATE INDEX "refresh_tokens_user_id_idx" ON "refresh_tokens" ("user_id")
        `);
        await queryRunner.query(`
            CREATE INDEX "refresh_tokens_family_id_idx" ON "refresh_tokens" ("family_id")
        `);
        await queryRunner.query(`
            CREATE TABLE "mfa_authenticators" (
                "user_id" text NOT NULL,
                "secret" text NOT NULL,
                "confirmed" boolean NOT NULL,
                "pending_secret" text,
                "last_used_step" integer,
                CONSTRAINT "PK_1cd0bf2b8c1623cb3cd0a7e56a3" PRIMARY KEY ("user_id")
            )
        `);
        await queryRunner.query(`
            CREATE TABLE "mfa_recovery_codes" (
                "user_id" text NOT NULL,
                "code_hash" text NOT NULL,
                CONSTRAINT "PK_7456255c55d67d6ec629dc6ea78" PRIMARY KEY ("user_id", "code_hash")
            )
        `);
        await queryRunner.query(`
            CREATE TABLE "mfa_failures" (
                "id" integer GENERATED ALWAYS AS IDENTITY NOT NULL,
                "user_id" text NOT NULL,
                "failed_at" TIMESTAMP WITH TIME ZONE NOT NULL,
                CONSTRAINT "PK_8632655ee5490ea90e7cb81e956" PRIMARY KEY ("id")
            )
        `);
        await queryRunner.query(`
            CREATE INDEX "mfa_failures_failed_at_idx" ON "mfa_failures" ("failed_at")
        `);
        await queryRunner.query(`
            CREATE INDEX "mfa_failures_user_id_failed_at_idx" ON "mfa_failures" ("user_id", "failed_at")
        `);
        await queryRunner.query(`
            CREATE TABLE "magic_links" (
                "id" text NOT NULL,
                "email" text NOT NULL,
                "created_at" TIMESTAMP WITH TIME ZONE NOT NULL,
                "expires_at" TIMESTAMP WITH TIME ZONE NOT NULL,
                "redirect_to" text,
                CONSTRAINT "PK_6c609d48037f164e7ae5b744b18" PRIMARY KEY ("id")
            )
        `);
        await queryRunner.query(`
            CREATE INDEX "magic_links_expires_at_idx" ON "magic_links" ("expires_at")
        `);
        await queryRunner.query(`
            CREATE TABLE "oidc_logins" (
                "state" text NOT NULL,
                "provider" text NOT NULL,
                "code_verifier" text NOT NULL,
                "nonce" text,
                "redirect_to" text,
                "link_user_id" text,
                "link_session_id" text,
                "created_at" TIMESTAMP WITH TIME ZONE NOT NULL,
                "expires_at" TIMESTAMP WITH TIME ZONE NOT NULL,
                CONSTRAINT "PK_d5c06611878638eba14d55eefa1" PRIMARY KEY ("state")
            )
        `);
        await queryRunner.query(`
            CREATE INDEX "oidc_logins_expires_at_idx" ON "oidc_logins" ("expires_at")
        `);
        await queryRunner.query(`
            CREATE TABLE "email_tokens" (
                "id" text NOT NULL,
                "purpose" text NOT NULL,
                "user_id" text NOT NULL,
                "email" text NOT NULL,
                "fingerprint" text,
                "created_at" TIMESTAMP WITH TIME ZONE NOT NULL,
                "expires_at" TIMESTAMP WITH TIME ZONE NOT NULL,
                CONSTRAINT "PK_08abb3fa348e894c274a6730d35" PRIMARY KEY ("id")
            )
        `);
        await queryRunner.query(`
            CREATE INDEX "email_tokens_expires_at_idx" ON "email_tokens" ("expires_at")
        `);
        await queryRunner.query(`
            CREATE INDEX "email_tokens_user_id_purpose_idx" ON "email_tokens" ("user_id", "purpose")
        `);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`
            DROP INDEX "public"."email_tokens_user_id_purpose_idx"
        `);
        await queryRunner.query(`
            DROP INDEX "public"."email_tokens_expires_at_idx"
        `);
        await queryRunner.query(`
            DROP TABLE "email_tokens"
        `);
        await queryRunner.query(`
            DROP INDEX "public"."oidc_logins_expires_at_idx"
        `);
        await queryRunner.query(`
            DROP TABLE "oidc_logins"
        `);
        await queryRunner.query(`
            DROP INDEX "public"."magic_links_expires_at_idx"
        `);
        await queryRunner.query(`
            DROP TABLE "magic_links"
        `);
        await queryRunner.query(`
            DROP INDEX "public"."mfa_failures_user_id_failed_at_idx"
        `);
        await queryRunner.query(`
            DROP INDEX "public"."mfa_failures_failed_at_idx"
        `);
        await queryRunner.query(`
            DROP TABLE "mfa_failures"
        `);
        await queryRunner.query(`
            DROP TABLE "mfa_recovery_codes"
        `);
        await queryRunner.query(`
            DROP TABLE "mfa_authenticators"
        `);
        await queryRunner.query(`
            DROP INDEX "public"."refresh_tokens_family_id_idx"
        `);
        await queryRunner.query(`
            DROP INDEX "public"."refresh_tokens_user_id_idx"
        `);
        await queryRunner.query(`
            DROP INDEX "public"."refresh_tokens_family_expires_at_idx"
        `);
        await queryRunner.query(`
            DROP TABLE "refresh_tokens"
        `);
        await queryRunner.query(`
            DROP INDEX "public"."sessions_user_id_idx"
        `);
        await queryRunner.query(`
            DROP INDEX "public"."sessions_expires_at_idx"
        `);
        await queryRunner.query(`
            DROP TABLE "sessions"
        `);
    }

}
