-- The common schema createWorkspaceTeam runs over: better-auth's "user" and account tables (with the twoFactorEnabled and
-- closed_at columns both apps use) and Discover's team and operator tables (migrations 0001, 0002, 0007, 0068, 0073, 0075).
CREATE TABLE "user" (id text PRIMARY KEY, name text NOT NULL, email text NOT NULL UNIQUE, "emailVerified" boolean NOT NULL DEFAULT false,
  image text, "createdAt" timestamptz NOT NULL DEFAULT now(), "updatedAt" timestamptz NOT NULL DEFAULT now(),
  "twoFactorEnabled" boolean NOT NULL DEFAULT false, closed_at timestamptz);
CREATE UNIQUE INDEX user_email_normalized_idx ON "user" (lower(email));
CREATE TABLE account (id text PRIMARY KEY, "accountId" text NOT NULL, "providerId" text NOT NULL, "userId" text NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
  password text, "createdAt" timestamptz NOT NULL DEFAULT now(), "updatedAt" timestamptz NOT NULL DEFAULT now());
CREATE TABLE workspace (id text PRIMARY KEY, name text NOT NULL, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE membership (workspace_id text NOT NULL REFERENCES workspace(id) ON DELETE CASCADE, user_id text NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
  role text NOT NULL CHECK (role IN ('owner','admin','editor','viewer')), PRIMARY KEY(workspace_id,user_id));
CREATE TABLE workspace_invitation (
  id uuid PRIMARY KEY,
  workspace_id text NOT NULL REFERENCES workspace(id) ON DELETE CASCADE,
  inviter_id text NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
  email text NOT NULL CHECK (email = lower(email)),
  role text NOT NULL CHECK (role IN ('admin', 'editor', 'viewer')),
  token_hash text NOT NULL UNIQUE CHECK (length(token_hash) = 64),
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, email)
);
CREATE TABLE workspace_two_factor_requirement (workspace_id text PRIMARY KEY REFERENCES workspace(id) ON DELETE CASCADE);
CREATE TABLE instance_operator (user_id text PRIMARY KEY REFERENCES "user"(id) ON DELETE CASCADE, source text NOT NULL CHECK (source IN ('bootstrap','host')),
  granted_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE instance_operator_audit (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, user_id text NOT NULL,
  action text NOT NULL CHECK (action IN ('bootstrap','grant','revoke','paid_work_export','email_suppression_clear')), scope text,
  created_at timestamptz NOT NULL DEFAULT now());
