-- The common schema createWorkspaceTeam (@ten98/runtime) runs over, shipped with the package. Apps apply the equivalent
-- in their own migrations. It is Discover's schema (migrations 0001, 0002, 0007, 0068, 0073, 0075) for these tables,
-- with better-auth's "user" and account tables; "twoFactorEnabled" comes from better-auth's two-factor plugin and
-- closed_at from account closure (#39). Campaign adds those two columns and renames its workspaces, memberships and
-- workspace_invitations tables to these with its better-auth migration (#97).
CREATE TABLE "user" (id text PRIMARY KEY, name text NOT NULL, email text NOT NULL UNIQUE, "emailVerified" boolean NOT NULL DEFAULT false,
  image text, "createdAt" timestamptz NOT NULL DEFAULT now(), "updatedAt" timestamptz NOT NULL DEFAULT now(),
  "twoFactorEnabled" boolean NOT NULL DEFAULT false, closed_at timestamptz);
CREATE UNIQUE INDEX user_email_normalized_idx ON "user" (lower(email));
CREATE TABLE account (id text PRIMARY KEY, "accountId" text NOT NULL, "providerId" text NOT NULL, "userId" text NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
  password text, "createdAt" timestamptz NOT NULL DEFAULT now(), "updatedAt" timestamptz NOT NULL DEFAULT now(), UNIQUE("providerId", "accountId"));
CREATE INDEX account_user_idx ON account("userId");
CREATE TABLE workspace (id text PRIMARY KEY, name text NOT NULL, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE membership (workspace_id text NOT NULL REFERENCES workspace(id) ON DELETE CASCADE, user_id text NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
  role text NOT NULL CHECK (role IN ('owner','admin','editor','viewer')), PRIMARY KEY(workspace_id,user_id));
CREATE INDEX membership_user_idx ON membership(user_id);
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
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT instance_operator_audit_scope_check CHECK ((action = 'paid_work_export') = (scope IS NOT NULL)
    AND (scope IS NULL OR scope ~ '^workspace:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(/website:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})?$')));
