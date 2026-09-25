CREATE TABLE "email_tokens" (
	"id" text PRIMARY KEY NOT NULL,
	"purpose" text NOT NULL,
	"user_id" text NOT NULL,
	"email" text NOT NULL,
	"fingerprint" text,
	"created_at" timestamp with time zone NOT NULL,
	"expires_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "magic_links" (
	"id" text PRIMARY KEY NOT NULL,
	"email" text NOT NULL,
	"created_at" timestamp with time zone NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"redirect_to" text
);
--> statement-breakpoint
CREATE TABLE "mfa_authenticators" (
	"user_id" text PRIMARY KEY NOT NULL,
	"secret" text NOT NULL,
	"confirmed" boolean NOT NULL,
	"pending_secret" text,
	"last_used_step" integer
);
--> statement-breakpoint
CREATE TABLE "mfa_failures" (
	"id" integer PRIMARY KEY GENERATED ALWAYS AS IDENTITY (sequence name "mfa_failures_id_seq" INCREMENT BY 1 MINVALUE 1 MAXVALUE 2147483647 START WITH 1 CACHE 1),
	"user_id" text NOT NULL,
	"failed_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "mfa_recovery_codes" (
	"user_id" text NOT NULL,
	"code_hash" text NOT NULL,
	CONSTRAINT "mfa_recovery_codes_user_id_code_hash_pk" PRIMARY KEY("user_id","code_hash")
);
--> statement-breakpoint
CREATE TABLE "oidc_logins" (
	"state" text PRIMARY KEY NOT NULL,
	"provider" text NOT NULL,
	"code_verifier" text NOT NULL,
	"nonce" text,
	"redirect_to" text,
	"link_user_id" text,
	"link_session_id" text,
	"created_at" timestamp with time zone NOT NULL,
	"expires_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "refresh_tokens" (
	"id" text PRIMARY KEY NOT NULL,
	"family_id" text NOT NULL,
	"user_id" text NOT NULL,
	"created_at" timestamp with time zone NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"family_expires_at" timestamp with time zone NOT NULL,
	"used_at" timestamp with time zone,
	"revoked" boolean DEFAULT false NOT NULL,
	"claims" jsonb
);
--> statement-breakpoint
CREATE TABLE "sessions" (
	"id" text PRIMARY KEY NOT NULL,
	"user_id" text NOT NULL,
	"created_at" timestamp with time zone NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"last_active_at" timestamp with time zone NOT NULL,
	"mfa" text,
	"metadata" jsonb
);
--> statement-breakpoint
CREATE INDEX "email_tokens_user_id_purpose_idx" ON "email_tokens" USING btree ("user_id","purpose");--> statement-breakpoint
CREATE INDEX "email_tokens_expires_at_idx" ON "email_tokens" USING btree ("expires_at");--> statement-breakpoint
CREATE INDEX "magic_links_expires_at_idx" ON "magic_links" USING btree ("expires_at");--> statement-breakpoint
CREATE INDEX "mfa_failures_user_id_failed_at_idx" ON "mfa_failures" USING btree ("user_id","failed_at");--> statement-breakpoint
CREATE INDEX "mfa_failures_failed_at_idx" ON "mfa_failures" USING btree ("failed_at");--> statement-breakpoint
CREATE INDEX "oidc_logins_expires_at_idx" ON "oidc_logins" USING btree ("expires_at");--> statement-breakpoint
CREATE INDEX "refresh_tokens_family_id_idx" ON "refresh_tokens" USING btree ("family_id");--> statement-breakpoint
CREATE INDEX "refresh_tokens_user_id_idx" ON "refresh_tokens" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "refresh_tokens_family_expires_at_idx" ON "refresh_tokens" USING btree ("family_expires_at");--> statement-breakpoint
CREATE INDEX "sessions_user_id_idx" ON "sessions" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "sessions_expires_at_idx" ON "sessions" USING btree ("expires_at");