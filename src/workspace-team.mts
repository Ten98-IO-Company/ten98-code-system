// The shared workspace, team, invitation and instance-operator controller (#97), promoted from Discover
// src/server/teams.ts and src/server/instance-operators.ts (dev, 2026-10-25). It runs over the common schema in
// tests/fixtures/workspace-team.sql (better-auth's "user" and account tables plus workspace, membership,
// workspace_invitation, workspace_two_factor_requirement, instance_operator and instance_operator_audit).
// Every method takes the app's client inside the app's transaction, so the app keeps its lock order around it, its
// routes, its rate limits, and how a TeamError becomes its HTTP response. Lock order: workspace -> invitation -> email.
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { mayGrantWorkspaceRole as mayGrant, mayManageWorkspaceMember, workspaceRoles, type WorkspaceRole as Role } from './browser.mjs';
import { isEmailAddress } from './email-message.mjs';

/** The subset of a `pg` client (or pool, for the read-only calls) that the controller uses. */
export interface TeamClient {
  query<R extends Record<string, unknown> = Record<string, unknown>>(sql: string, params?: unknown[]): Promise<{ rows: R[]; rowCount: number | null }>;
}
export type TeamErrorCode =
  | 'INVALID_INPUT' | 'SIGN_IN_REQUIRED' | 'NOT_FOUND' | 'FORBIDDEN' | 'LAST_OWNER' | 'FACTOR_REQUIRED' | 'INVITATION_UNAVAILABLE'
  | 'INVITATION_NOT_PENDING' | 'WRONG_ACCOUNT' | 'CONFIRMATION_MISMATCH' | 'MEMBERSHIP_CHANGED' | 'OIDC_INVITE_EMAIL_MISMATCH'
  | 'OIDC_ACCOUNT_EXISTS' | 'OPERATOR_REQUIRED';
/** Thrown for every refusal: `status` is the HTTP status that fits and `message` is safe to show. */
export type TeamError = Error & { status: 400 | 401 | 403 | 404 | 409 | 410; code: TeamErrorCode };
export type InvitationRole = Exclude<Role, 'owner'>;
export type Invitation = { id: string; email: string; role: InvitationRole; expiresAt: Date };

const fail = (status: TeamError['status'], code: TeamErrorCode, message: string): never => {
  throw Object.assign(new Error(message), { status, code });
};
const invalid = (): never => fail(400, 'INVALID_INPUT', 'Check the submitted fields and try again.');
const unavailable = (): never => fail(410, 'INVITATION_UNAVAILABLE', 'This invitation is unavailable or expired. Ask for a new invitation.');
const notFound = (): never => fail(404, 'NOT_FOUND', 'Workspace not found or unavailable.');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const TOKEN = /^[A-Za-z0-9_-]{43}$/;
const id = (value: unknown): string => typeof value === 'string' && UUID.test(value) ? value : invalid();
const name = (value: unknown): string => typeof value === 'string' && value.trim().length >= 1 && value.trim().length <= 120 ? value.trim() : invalid();
const email = (value: unknown): string => {
  const normalized = typeof value === 'string' ? value.trim().toLowerCase() : '';
  return isEmailAddress(normalized) ? normalized : invalid();
};
const token = (value: unknown): string => typeof value === 'string' && TOKEN.test(value) ? value : invalid();
/** Plain objects with exactly the allowed keys; anything else is refused. */
const fields = (input: unknown, allowed: readonly string[]): Record<string, unknown> => {
  if (input === null || typeof input !== 'object' || Array.isArray(input) || Object.keys(input).some(key => !allowed.includes(key))) invalid();
  return input as Record<string, unknown>;
};
const digest = (value: string) => createHash('sha256').update(value).digest('hex');
const pendingRole = "(m.role='owner' OR (m.role='admin' AND i.role IN ('editor','viewer')))";

/**
 * `hashPassword` hashes the password of an account created by accepting an invitation (better-auth's, so the preset can
 * verify it). `emailLockKey` is the first key of the advisory lock that serialises account creation per email.
 */
export function createWorkspaceTeam({ hashPassword, emailLockKey = 109_859 }: { hashPassword(password: string): Promise<string>; emailLockKey?: number }) {
  if (typeof hashPassword !== 'function' || !Number.isSafeInteger(emailLockKey)) throw new TypeError('createWorkspaceTeam needs hashPassword and an integer emailLockKey.');

  async function lockWorkspace(client: TeamClient, workspaceId: string) {
    const result = await client.query<{ id: string; name: string }>('SELECT id,name FROM workspace WHERE id=$1 FOR UPDATE', [workspaceId]);
    return result.rows[0] ?? notFound();
  }
  async function managerRole(client: TeamClient, workspaceId: string, userId: string): Promise<'owner' | 'admin'> {
    const role = (await client.query<{ role: Role }>('SELECT role FROM membership WHERE workspace_id=$1 AND user_id=$2', [workspaceId, userId])).rows[0]?.role;
    return role === 'owner' || role === 'admin' ? role : notFound();
  }
  const requireGrant = (actor: Role, role: Role) => { if (!mayGrant(actor, role)) fail(403, 'FORBIDDEN', 'Only an owner can manage owners and administrators.'); };
  async function preserveOwner(client: TeamClient, workspaceId: string, previous: Role, next?: Role) {
    if (previous !== 'owner' || next === 'owner') return;
    const count = (await client.query<{ count: number }>("SELECT count(*)::int AS count FROM membership WHERE workspace_id=$1 AND role='owner'", [workspaceId])).rows[0]!.count;
    if (count <= 1) fail(409, 'LAST_OWNER', 'Assign another owner before removing or changing the last owner.');
  }
  async function newToken(client: TeamClient, sql: string, params: unknown[]) {
    const value = randomBytes(32).toString('base64url');
    const invitation = (await client.query<Invitation & Record<string, unknown>>(sql, [...params, digest(value)])).rows[0]!;
    return { invitation: { id: invitation.id, email: invitation.email, role: invitation.role, expiresAt: invitation.expiresAt }, token: value };
  }

  // Discover the workspace without an invitation lock, then lock workspace -> invitation -> email, as every acceptance does.
  async function lockInvitation(client: TeamClient, tokenDigest: string) {
    const found = (await client.query<{ workspace_id: string }>('SELECT workspace_id FROM workspace_invitation WHERE token_hash=$1', [tokenDigest])).rows[0] ?? unavailable();
    const workspace = (await client.query<{ id: string }>('SELECT id FROM workspace WHERE id=$1 FOR UPDATE', [found.workspace_id])).rows[0] ?? unavailable();
    const invitation = (await client.query<Invitation & { inviter_id: string }>(
      `SELECT id,email,role,expires_at AS "expiresAt",inviter_id FROM workspace_invitation
       WHERE token_hash=$1 AND workspace_id=$2 AND expires_at>clock_timestamp() FOR UPDATE`, [tokenDigest, workspace.id])).rows[0] ?? unavailable();
    const inviter = (await client.query<{ role: Role }>('SELECT role FROM membership WHERE workspace_id=$1 AND user_id=$2', [workspace.id, invitation.inviter_id])).rows[0];
    if (!mayGrant(inviter?.role, invitation.role)) unavailable();
    // One normalised email can hold invitations to several workspaces; serialise its account creation without locking them.
    await client.query('SELECT pg_advisory_xact_lock($1,hashtext($2))', [emailLockKey, invitation.email]);
    return { workspaceId: workspace.id, invitation };
  }
  async function consumeInvitation(client: TeamClient, invitation: Invitation, workspaceId: string, userId: string) {
    // A link adds a membership; it never replaces an existing member's role.
    await client.query('INSERT INTO membership(workspace_id,user_id,role) VALUES($1,$2,$3) ON CONFLICT(workspace_id,user_id) DO NOTHING', [workspaceId, userId, invitation.role]);
    const consumed = await client.query('DELETE FROM workspace_invitation WHERE id=$1 AND expires_at>clock_timestamp() RETURNING id', [invitation.id]);
    if (!consumed.rowCount) unavailable();
  }
  async function lockPendingInvitation(client: TeamClient, workspaceId: string, userId: string, invitationId: string): Promise<Invitation> {
    await lockWorkspace(client, workspaceId);
    const actor = await managerRole(client, workspaceId, userId);
    const invitation = (await client.query<Invitation & { pending: boolean }>(
      `SELECT i.id,i.email,i.role,i.expires_at AS "expiresAt",(i.expires_at>clock_timestamp() AND ${pendingRole}) AS pending
       FROM workspace_invitation i LEFT JOIN membership m ON m.workspace_id=i.workspace_id AND m.user_id=i.inviter_id
       WHERE i.workspace_id=$1 AND i.id=$2 FOR UPDATE OF i`, [workspaceId, invitationId])).rows[0];
    if (invitation) requireGrant(actor, invitation.role);
    // Accepted and revoked invitations are deleted, so a missing row is answered like an expired one.
    if (!invitation?.pending) fail(409, 'INVITATION_NOT_PENDING', 'This invitation is no longer pending. It was accepted, revoked or has expired. Refresh the team.');
    return { id: invitation!.id, email: invitation!.email, role: invitation!.role, expiresAt: invitation!.expiresAt };
  }

  return {
    async createWorkspace(client: TeamClient, userId: unknown, input: unknown) {
      const owner = id(userId), workspaceName = name(fields(input, ['name']).name);
      if (!(await client.query('SELECT id FROM "user" WHERE id=$1', [owner])).rowCount) fail(401, 'SIGN_IN_REQUIRED', 'Sign in to continue.');
      const workspace = { id: randomUUID(), name: workspaceName };
      await client.query('INSERT INTO workspace(id,name) VALUES($1,$2)', [workspace.id, workspace.name]);
      await client.query("INSERT INTO membership(workspace_id,user_id,role) VALUES($1,$2,'owner')", [workspace.id, owner]);
      return { workspace, role: 'owner' as const };
    },

    async renameWorkspace(client: TeamClient, workspaceId: unknown, userId: unknown, input: unknown) {
      const workspace = id(workspaceId), actor = id(userId), workspaceName = name(fields(input, ['name']).name);
      await lockWorkspace(client, workspace);
      const role = await managerRole(client, workspace, actor);
      await client.query('UPDATE workspace SET name=$1 WHERE id=$2', [workspaceName, workspace]);
      return { workspace: { id: workspace, name: workspaceName }, role };
    },

    /** Owners and administrators: members, and the invitations still pending (unexpired, inviter still able to grant). */
    async getTeam(client: TeamClient, workspaceId: unknown, userId: unknown) {
      const workspaceKey = id(workspaceId), actor = id(userId);
      const workspace = await lockWorkspace(client, workspaceKey);
      const role = await managerRole(client, workspaceKey, actor);
      const members = await client.query<{ userId: string; name: string; email: string; role: Role }>(
        'SELECT u.id AS "userId",u.name,u.email,m.role FROM membership m JOIN "user" u ON u.id=m.user_id WHERE m.workspace_id=$1 ORDER BY u.name,u.id', [workspaceKey]);
      const invitations = await client.query<Invitation & Record<string, unknown>>(
        `SELECT i.id,i.email,i.role,i.expires_at AS "expiresAt" FROM workspace_invitation i
         JOIN membership m ON m.workspace_id=i.workspace_id AND m.user_id=i.inviter_id
         WHERE i.workspace_id=$1 AND i.expires_at>clock_timestamp() AND ${pendingRole} ORDER BY i.created_at,i.id`, [workspaceKey]);
      const required = await client.query('SELECT 1 FROM workspace_two_factor_requirement WHERE workspace_id=$1', [workspaceKey]);
      return { workspace: { ...workspace, twoFactorRequired: required.rowCount === 1 }, role, members: members.rows, invitations: invitations.rows };
    },

    /** Owner only: require or stop requiring a verified second factor for every member. The owner must have one first. */
    async setTwoFactorRequirement(client: TeamClient, workspaceId: unknown, userId: unknown, input: unknown) {
      const workspace = id(workspaceId), actor = id(userId), { required } = fields(input, ['required']);
      if (typeof required !== 'boolean') invalid();
      await lockWorkspace(client, workspace);
      if (await managerRole(client, workspace, actor) !== 'owner') fail(403, 'FORBIDDEN', 'Only a workspace owner can change the two-factor requirement.');
      if (required) {
        // FOR SHARE: the owner's own concurrent factor disable either commits first or waits for this change.
        const owner = (await client.query<{ twoFactorEnabled: boolean }>('SELECT "twoFactorEnabled" FROM "user" WHERE id=$1 FOR SHARE', [actor])).rows[0];
        if (!owner?.twoFactorEnabled) fail(409, 'FACTOR_REQUIRED', 'Turn on two-factor authentication for your own account before requiring it for this workspace.');
        await client.query('INSERT INTO workspace_two_factor_requirement(workspace_id) VALUES($1) ON CONFLICT DO NOTHING', [workspace]);
      } else await client.query('DELETE FROM workspace_two_factor_requirement WHERE workspace_id=$1', [workspace]);
      return { twoFactorRequired: required as boolean };
    },

    /** True when the workspace requires two-factor and this member has none; the app refuses its workspace routes then. */
    async memberNeedsFactor(client: TeamClient, workspaceId: unknown, userId: unknown): Promise<boolean> {
      const locked = await client.query(
        `SELECT 1 FROM workspace_two_factor_requirement r JOIN membership m ON m.workspace_id=r.workspace_id AND m.user_id=$2
         JOIN "user" u ON u.id=m.user_id WHERE NOT u."twoFactorEnabled" AND r.workspace_id=$1`, [id(workspaceId), id(userId)]);
      return !!locked.rowCount;
    },

    /** Owners and administrators. Never grants owner. Replaces any earlier invitation to the same email. Returns the only copy of the token. */
    async inviteMember(client: TeamClient, workspaceId: unknown, userId: unknown, input: unknown) {
      const workspace = id(workspaceId), actor = id(userId), details = fields(input, ['email', 'role']);
      const invitee = email(details.email);
      const role = details.role;
      if (typeof role !== 'string' || role === 'owner' || !workspaceRoles.some(value => value === role)) invalid();
      await lockWorkspace(client, workspace);
      const actorRole = await managerRole(client, workspace, actor);
      requireGrant(actorRole, role as Role);
      const previous = (await client.query<{ role: Role }>('SELECT role FROM workspace_invitation WHERE workspace_id=$1 AND email=$2', [workspace, invitee])).rows[0];
      if (previous) requireGrant(actorRole, previous.role);
      await client.query('DELETE FROM workspace_invitation WHERE workspace_id=$1 AND email=$2', [workspace, invitee]);
      return newToken(client, `INSERT INTO workspace_invitation(id,workspace_id,inviter_id,email,role,token_hash,expires_at)
        VALUES($1,$2,$3,$4,$5,$6,clock_timestamp()+interval '7 days') RETURNING id,email,role,expires_at AS "expiresAt"`, [randomUUID(), workspace, actor, invitee, role]);
    },

    async revokeInvitation(client: TeamClient, workspaceId: unknown, userId: unknown, invitationId: unknown): Promise<void> {
      const workspace = id(workspaceId), actor = id(userId), invitationKey = id(invitationId);
      await lockWorkspace(client, workspace);
      const actorRole = await managerRole(client, workspace, actor);
      const invitation = (await client.query<{ role: Role }>('SELECT role FROM workspace_invitation WHERE workspace_id=$1 AND id=$2', [workspace, invitationKey])).rows[0];
      if (!invitation) fail(404, 'NOT_FOUND', 'Invitation not found or unavailable.');
      requireGrant(actorRole, invitation!.role);
      await client.query('DELETE FROM workspace_invitation WHERE workspace_id=$1 AND id=$2', [workspace, invitationKey]);
    },

    /**
     * Replaces a pending invitation's token and restarts its seven days, keeping its id, email, role and inviter; the
     * previous link stops working. `admit` runs after authorization and the pending check, inside the same transaction.
     */
    async rotateInvitation(client: TeamClient, workspaceId: unknown, userId: unknown, invitationId: unknown, admit?: (client: TeamClient, invitation: Invitation) => Promise<void>) {
      const workspace = id(workspaceId), actor = id(userId), invitationKey = id(invitationId);
      const pending = await lockPendingInvitation(client, workspace, actor, invitationKey);
      await admit?.(client, pending);
      return newToken(client, `UPDATE workspace_invitation SET token_hash=$3,expires_at=clock_timestamp()+interval '7 days'
        WHERE workspace_id=$1 AND id=$2 RETURNING id,email,role,expires_at AS "expiresAt"`, [workspace, invitationKey]);
    },

    /** Needs authority over the saved and the requested role; keeps an owner; removes invitations the member can no longer grant. */
    async changeRole(client: TeamClient, workspaceId: unknown, userId: unknown, targetUserId: unknown, input: unknown): Promise<void> {
      const workspace = id(workspaceId), actor = id(userId), target = id(targetUserId), { role } = fields(input, ['role']);
      if (typeof role !== 'string' || !workspaceRoles.some(value => value === role)) invalid();
      await lockWorkspace(client, workspace);
      const actorRole = await managerRole(client, workspace, actor);
      const saved = (await client.query<{ role: Role }>('SELECT role FROM membership WHERE workspace_id=$1 AND user_id=$2', [workspace, target])).rows[0];
      if (!saved) fail(404, 'NOT_FOUND', 'Member not found or unavailable.');
      if (!mayManageWorkspaceMember(actorRole, saved!.role, role)) fail(403, 'FORBIDDEN', 'Only an owner can manage owners and administrators.');
      await preserveOwner(client, workspace, saved!.role, role as Role);
      await client.query('UPDATE membership SET role=$1 WHERE workspace_id=$2 AND user_id=$3', [role, workspace, target]);
      await client.query(`DELETE FROM workspace_invitation WHERE workspace_id=$1 AND inviter_id=$2
        AND ($3::text NOT IN ('owner','admin') OR ($3='admin' AND role='admin'))`, [workspace, target, role]);
    },

    /** An owner promotes another member, confirmed by that member's email, and becomes an administrator, in one step. */
    async transferOwnership(client: TeamClient, workspaceId: unknown, userId: unknown, input: unknown) {
      const workspace = id(workspaceId), actor = id(userId), details = fields(input, ['targetUserId', 'confirmationEmail']);
      const target = id(details.targetUserId), confirmation = email(details.confirmationEmail);
      if (target === actor) fail(400, 'INVALID_INPUT', 'Choose another existing workspace member.');
      await lockWorkspace(client, workspace);
      if (await managerRole(client, workspace, actor) !== 'owner') fail(403, 'FORBIDDEN', 'Only a current owner can transfer ownership.');
      const member = (await client.query<{ email: string }>('SELECT u.email FROM membership m JOIN "user" u ON u.id=m.user_id WHERE m.workspace_id=$1 AND m.user_id=$2', [workspace, target])).rows[0];
      if (!member) fail(404, 'NOT_FOUND', 'Member not found or unavailable.');
      if (member!.email.toLowerCase() !== confirmation) fail(409, 'CONFIRMATION_MISMATCH', 'The confirmation email does not match this member. Refresh the team and check the email.');
      const changed = await client.query("UPDATE membership SET role=CASE WHEN user_id=$2 THEN 'owner' ELSE 'admin' END WHERE workspace_id=$1 AND user_id IN ($2,$3)", [workspace, target, actor]);
      if (changed.rowCount !== 2) fail(409, 'MEMBERSHIP_CHANGED', 'Team membership changed. Refresh the team before trying again.');
      await client.query("DELETE FROM workspace_invitation WHERE workspace_id=$1 AND inviter_id=$2 AND role='admin'", [workspace, actor]);
      return { ok: true as const, role: 'admin' as const, ownerUserId: target };
    },

    /** Also a member leaving (userId === targetUserId). Keeps an owner; removes invitations the member sent or received. */
    async removeMember(client: TeamClient, workspaceId: unknown, userId: unknown, targetUserId: unknown): Promise<void> {
      const workspace = id(workspaceId), actor = id(userId), target = id(targetUserId);
      await lockWorkspace(client, workspace);
      const saved = (await client.query<{ role: Role }>('SELECT role FROM membership WHERE workspace_id=$1 AND user_id=$2', [workspace, target])).rows[0];
      if (!saved) fail(404, 'NOT_FOUND', 'Member not found or unavailable.');
      if (actor !== target && !mayManageWorkspaceMember(await managerRole(client, workspace, actor), saved!.role)) fail(403, 'FORBIDDEN', 'Only an owner can manage owners and administrators.');
      await preserveOwner(client, workspace, saved!.role);
      await client.query('DELETE FROM membership WHERE workspace_id=$1 AND user_id=$2', [workspace, target]);
      await client.query('DELETE FROM workspace_invitation WHERE workspace_id=$1 AND (inviter_id=$2 OR email=(SELECT lower(email) FROM "user" WHERE id=$2))', [workspace, target]);
    },

    /** Public, for the token holder: what the invitation offers, and whether its email already has an account (so sign-in comes first). */
    async inspectInvitation(client: TeamClient, input: unknown) {
      const value = token(fields(input, ['token']).token);
      const invitation = (await client.query<{ workspaceId: string; workspaceName: string; email: string; role: InvitationRole; expiresAt: Date; accountExists: boolean }>(
        `SELECT w.id AS "workspaceId",w.name AS "workspaceName",i.email,i.role,i.expires_at AS "expiresAt",
           EXISTS(SELECT 1 FROM "user" u WHERE lower(u.email)=i.email) AS "accountExists"
         FROM workspace_invitation i JOIN workspace w ON w.id=i.workspace_id
         JOIN membership m ON m.workspace_id=i.workspace_id AND m.user_id=i.inviter_id
         WHERE i.token_hash=$1 AND i.expires_at>clock_timestamp() AND ${pendingRole}`, [digest(value)])).rows[0] ?? unavailable();
      return { workspace: { id: invitation.workspaceId, name: invitation.workspaceName }, email: invitation.email, role: invitation.role, expiresAt: invitation.expiresAt, accountExists: invitation.accountExists };
    },

    /**
     * Accepts with the invited account signed in, or creates that account with `name` and a 12-128 character `password`.
     * An existing account must be signed in (409 SIGN_IN_REQUIRED); another signed-in account is refused (403 WRONG_ACCOUNT).
     */
    async acceptInvitation(client: TeamClient, input: unknown, signedInUser?: { id: string; email: string }) {
      const details = fields(input, ['token', 'name', 'password']);
      const value = token(details.token);
      const newName = details.name === undefined ? undefined : name(details.name);
      if (details.password !== undefined && (typeof details.password !== 'string' || details.password.length < 12 || details.password.length > 128)) invalid();
      const signedIn = signedInUser === undefined ? undefined : { id: id(signedInUser.id), email: email(signedInUser.email) };
      const { workspaceId, invitation } = await lockInvitation(client, digest(value));
      let userId = (await client.query<{ id: string }>('SELECT id FROM "user" WHERE lower(email)=$1', [invitation.email])).rows[0]?.id;
      if (signedIn && (signedIn.id !== userId || signedIn.email !== invitation.email)) fail(403, 'WRONG_ACCOUNT', 'Sign in with the email this invitation was sent to.');
      const created = !userId;
      if (userId && !signedIn) fail(409, 'SIGN_IN_REQUIRED', 'Sign in with the invited email to accept this invitation.');
      if (!userId) {
        if (!newName || typeof details.password !== 'string') fail(400, 'INVALID_INPUT', 'Enter your name and a password between 12 and 128 characters.');
        const password = await hashPassword(details.password as string);
        userId = randomUUID();
        await client.query('INSERT INTO "user"(id,name,email) VALUES($1,$2,$3)', [userId, newName, invitation.email]);
        await client.query('INSERT INTO account(id,"accountId","providerId","userId",password) VALUES($1,$2,\'credential\',$2,$3)', [randomUUID(), userId, password]);
      }
      await consumeInvitation(client, invitation, workspaceId, userId!);
      return { workspaceId, created, email: invitation.email };
    },

    /** Server only: `identity` must be cryptographically verified OIDC claims. Creates the account; an existing one must link explicitly. */
    async acceptVerifiedOidcInvitation(client: TeamClient, tokenValue: unknown, identity: { email: string; name: string }, passwordHash?: string) {
      const verified = { email: email(identity?.email), name: name(identity?.name) };
      const { workspaceId, invitation } = await lockInvitation(client, digest(token(tokenValue)));
      if (invitation.email !== verified.email) fail(403, 'OIDC_INVITE_EMAIL_MISMATCH', 'The verified provider email does not match the invitation recipient.');
      if ((await client.query('SELECT id FROM "user" WHERE lower(email)=$1', [verified.email])).rowCount) {
        fail(409, 'OIDC_ACCOUNT_EXISTS', 'Sign in with the existing account before accepting this invitation. Link the provider explicitly in account settings.');
      }
      const userId = randomUUID();
      await client.query('INSERT INTO "user"(id,name,email,"emailVerified") VALUES($1,$2,$3,true)', [userId, verified.name, verified.email]);
      if (passwordHash) await client.query('INSERT INTO account(id,"accountId","providerId","userId",password) VALUES($1,$2,\'credential\',$2,$3)', [randomUUID(), userId, passwordHash]);
      await consumeInvitation(client, invitation, workspaceId, userId);
      return { userId, workspaceId };
    },

    async isInstanceOperator(client: TeamClient, userId: unknown): Promise<boolean> {
      return !!(await client.query('SELECT 1 FROM instance_operator WHERE user_id=$1', [id(userId)])).rowCount;
    },

    /** Holds the operator row (FOR SHARE) for the rest of the caller's transaction. */
    async requireInstanceOperator(client: TeamClient, userId: unknown): Promise<void> {
      if (!(await client.query('SELECT user_id FROM instance_operator WHERE user_id=$1 FOR SHARE', [id(userId)])).rowCount) fail(403, 'OPERATOR_REQUIRED', 'This action requires an instance operator.');
    },

    /** Host CLI only: no HTTP route grants operator authority. Grants or revokes and writes the audit row in the caller's transaction. */
    async setInstanceOperator(client: TeamClient, accountEmail: unknown, enabled: boolean): Promise<void> {
      const user = (await client.query<{ id: string }>('SELECT id FROM "user" WHERE lower(email)=$1 FOR UPDATE', [email(accountEmail)])).rows[0];
      if (!user) fail(404, 'NOT_FOUND', 'No existing account has that email.');
      if (enabled) await client.query("INSERT INTO instance_operator(user_id,source) VALUES($1,'host') ON CONFLICT(user_id) DO NOTHING", [user!.id]);
      else await client.query('DELETE FROM instance_operator WHERE user_id=$1', [user!.id]);
      await client.query('INSERT INTO instance_operator_audit(user_id,action) VALUES($1,$2)', [user!.id, enabled ? 'grant' : 'revoke']);
    },

    /** Host CLI only: the named open account, held as an operator; an unknown or closed account gets the non-operator refusal. */
    async requireNamedInstanceOperator(client: TeamClient, accountEmail: unknown): Promise<string> {
      const user = (await client.query<{ id: string }>('SELECT id FROM "user" WHERE lower(email)=$1 AND closed_at IS NULL', [email(accountEmail)])).rows[0];
      if (!user) fail(403, 'OPERATOR_REQUIRED', 'This action requires an instance operator.');
      if (!(await client.query('SELECT user_id FROM instance_operator WHERE user_id=$1 FOR SHARE', [user!.id])).rowCount) fail(403, 'OPERATOR_REQUIRED', 'This action requires an instance operator.');
      return user!.id;
    },
  };
}

export type WorkspaceTeam = ReturnType<typeof createWorkspaceTeam>;
