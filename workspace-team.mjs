// The shared workspace, team, invitation and instance-operator controller (#97), promoted from Discover
// src/server/teams.ts and src/server/instance-operators.ts (dev, 2026-10-25). It runs over the common schema shipped
// as workspace-team.sql (better-auth's "user" and account tables plus the team and operator tables).
//
// Every method takes the app's client inside the app's transaction; the app keeps its routes, rate limits and how a
// TeamError becomes its response, and must roll back on any thrown error. Decisions read their rows under locks
// (workspace FOR UPDATE, the caller's membership FOR SHARE, the target's and the owners' FOR UPDATE), so they hold at
// READ COMMITTED, REPEATABLE READ and SERIALIZABLE; at the two stricter levels a conflicting concurrent change fails
// with SQLSTATE 40001 and the caller retries. Lock order: workspace -> memberships -> invitation -> email.
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { mayGrantWorkspaceRole as mayGrant, mayManageWorkspaceMember, workspaceRoles } from './browser.mjs';
import { isEmailAddress } from './email-message.mjs';
/** Every refusal: `status` is the HTTP status that fits and `message` is safe to show. */
export class TeamError extends Error {
    status;
    code;
    constructor(status, code, message) {
        super(message);
        this.name = 'TeamError';
        this.status = status;
        this.code = code;
    }
}
export const isTeamError = (error) => error instanceof TeamError;
const fail = (status, code, message) => { throw new TeamError(status, code, message); };
const invalid = () => fail(400, 'INVALID_INPUT', 'Check the submitted fields and try again.');
const unavailable = () => fail(410, 'INVITATION_UNAVAILABLE', 'This invitation is unavailable or expired. Ask for a new invitation.');
const notFound = () => fail(404, 'NOT_FOUND', 'Workspace not found or unavailable.');
const forbidden = () => fail(403, 'FORBIDDEN', 'Only an owner can manage owners and administrators.');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const TOKEN = /^[A-Za-z0-9_-]{43}$/;
const hasControl = (value) => [...value].some(character => character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127);
const id = (value) => typeof value === 'string' && UUID.test(value) ? value : invalid();
/** 1-120 characters after trimming, with no control characters (NUL included), as Campaign requires. */
const name = (value) => typeof value === 'string' && !hasControl(value) && value.trim().length >= 1 && value.trim().length <= 120 ? value.trim() : invalid();
const normalise = (value) => typeof value === 'string' ? value.trim().toLowerCase() : '';
const email = (value) => {
    const normalised = normalise(value);
    return isEmailAddress(normalised) ? normalised : invalid();
};
const token = (value) => typeof value === 'string' && TOKEN.test(value) ? value : invalid();
/** Plain objects with only the allowed keys; anything else is refused. */
const fields = (input, allowed) => {
    if (input === null || typeof input !== 'object' || Array.isArray(input) || Object.keys(input).some(key => !allowed.includes(key)))
        invalid();
    return input;
};
const digest = (value) => createHash('sha256').update(value).digest('hex');
const pendingRole = "(m.role='owner' OR (m.role='admin' AND i.role IN ('editor','viewer')))";
const INT32 = 2 ** 31;
/**
 * `hashPassword` hashes the password of an account created by accepting an invitation (better-auth's, so the preset
 * verifies it). `emailLockKey` (a 32-bit integer) is the first key of `lockEmail`, which every account-creation path of
 * the app must take before it checks whether an email already has an account.
 */
export function createWorkspaceTeam({ hashPassword, emailLockKey = 109_859 }) {
    if (typeof hashPassword !== 'function' || !Number.isInteger(emailLockKey) || emailLockKey < -INT32 || emailLockKey >= INT32) {
        throw new TypeError('createWorkspaceTeam needs hashPassword and a 32-bit integer emailLockKey.');
    }
    /** Serialises account creation for one normalised email: pg_advisory_xact_lock(emailLockKey, hashtext(email)). */
    async function lockEmail(client, address) {
        await client.query('SELECT pg_advisory_xact_lock($1,hashtext($2))', [emailLockKey, normalise(address)]);
    }
    async function lockWorkspace(client, workspaceId) {
        return (await client.query('SELECT id,name FROM workspace WHERE id=$1 FOR UPDATE', [workspaceId])).rows[0] ?? notFound();
    }
    /** The caller's own role, held FOR SHARE so a concurrent change to it waits for this transaction. */
    async function roleOf(client, workspaceId, userId) {
        return (await client.query('SELECT role FROM membership WHERE workspace_id=$1 AND user_id=$2 FOR SHARE', [workspaceId, userId])).rows[0]?.role;
    }
    async function managerRole(client, workspaceId, userId) {
        const role = await roleOf(client, workspaceId, userId);
        return role === 'owner' || role === 'admin' ? role : notFound();
    }
    async function targetRole(client, workspaceId, userId) {
        const role = (await client.query('SELECT role FROM membership WHERE workspace_id=$1 AND user_id=$2 FOR UPDATE', [workspaceId, userId])).rows[0]?.role;
        return role ?? fail(404, 'NOT_FOUND', 'Member not found or unavailable.');
    }
    const requireGrant = (actor, role) => { if (!mayGrant(actor, role))
        forbidden(); };
    /** Locks every owner row, so two concurrent demotions or departures cannot both see another owner. */
    async function preserveOwner(client, workspaceId, previous, next) {
        if (previous !== 'owner' || next === 'owner')
            return;
        const owners = await client.query("SELECT user_id FROM membership WHERE workspace_id=$1 AND role='owner' FOR UPDATE", [workspaceId]);
        if ((owners.rowCount ?? 0) <= 1)
            fail(409, 'LAST_OWNER', 'Assign another owner before removing or changing the last owner.');
    }
    async function newToken(client, sql, params) {
        const value = randomBytes(32).toString('base64url');
        const invitation = (await client.query(sql, [...params, digest(value)])).rows[0];
        return { invitation: { id: invitation.id, email: invitation.email, role: invitation.role, expiresAt: invitation.expiresAt }, token: value };
    }
    // Find the workspace without an invitation lock, then lock workspace -> invitation -> email, as every acceptance does.
    async function lockInvitation(client, tokenDigest) {
        const found = (await client.query('SELECT workspace_id FROM workspace_invitation WHERE token_hash=$1', [tokenDigest])).rows[0] ?? unavailable();
        const workspace = (await client.query('SELECT id FROM workspace WHERE id=$1 FOR UPDATE', [found.workspace_id])).rows[0] ?? unavailable();
        const invitation = (await client.query(`SELECT id,email,role,expires_at AS "expiresAt",inviter_id FROM workspace_invitation
       WHERE token_hash=$1 AND workspace_id=$2 AND expires_at>clock_timestamp() FOR UPDATE`, [tokenDigest, workspace.id])).rows[0] ?? unavailable();
        if (!mayGrant(await roleOf(client, workspace.id, invitation.inviter_id), invitation.role))
            unavailable();
        await lockEmail(client, invitation.email);
        return { workspaceId: workspace.id, invitation };
    }
    /** Adds the membership (never replacing a role) and deletes the locked invitation. Reports the role the user now holds. */
    async function consumeInvitation(client, invitation, workspaceId, userId) {
        const added = await client.query('INSERT INTO membership(workspace_id,user_id,role) VALUES($1,$2,$3) ON CONFLICT(workspace_id,user_id) DO NOTHING', [workspaceId, userId, invitation.role]);
        await client.query('DELETE FROM workspace_invitation WHERE id=$1', [invitation.id]);
        const role = (await client.query('SELECT role FROM membership WHERE workspace_id=$1 AND user_id=$2', [workspaceId, userId])).rows[0].role;
        return { joined: added.rowCount === 1, role };
    }
    async function lockPendingInvitation(client, workspaceId, userId, invitationId) {
        await lockWorkspace(client, workspaceId);
        const actor = await managerRole(client, workspaceId, userId);
        const invitation = (await client.query(`SELECT i.id,i.email,i.role,i.expires_at AS "expiresAt",(i.expires_at>clock_timestamp() AND ${pendingRole}) AS pending
       FROM workspace_invitation i LEFT JOIN membership m ON m.workspace_id=i.workspace_id AND m.user_id=i.inviter_id
       WHERE i.workspace_id=$1 AND i.id=$2 FOR UPDATE OF i`, [workspaceId, invitationId])).rows[0];
        if (invitation)
            requireGrant(actor, invitation.role);
        // Accepted and revoked invitations are deleted, so a missing row is answered like an expired one.
        if (!invitation?.pending)
            fail(409, 'INVITATION_NOT_PENDING', 'This invitation is no longer pending. It was accepted, revoked or has expired. Refresh the team.');
        return { id: invitation.id, email: invitation.email, role: invitation.role, expiresAt: invitation.expiresAt };
    }
    const isOperator = (client, userId, lock = '') => client.query(`SELECT o.user_id FROM instance_operator o JOIN "user" u ON u.id=o.user_id WHERE o.user_id=$1 AND u.closed_at IS NULL ${lock}`, [userId]);
    return {
        lockEmail,
        async createWorkspace(client, userId, input) {
            const owner = id(userId), workspaceName = name(fields(input, ['name']).name);
            if (!(await client.query('SELECT id FROM "user" WHERE id=$1', [owner])).rowCount)
                fail(401, 'SIGN_IN_REQUIRED', 'Sign in to continue.');
            const workspace = { id: randomUUID(), name: workspaceName };
            await client.query('INSERT INTO workspace(id,name) VALUES($1,$2)', [workspace.id, workspace.name]);
            await client.query("INSERT INTO membership(workspace_id,user_id,role) VALUES($1,$2,'owner')", [workspace.id, owner]);
            return { workspace, role: 'owner' };
        },
        async renameWorkspace(client, workspaceId, userId, input) {
            const workspace = id(workspaceId), actor = id(userId), workspaceName = name(fields(input, ['name']).name);
            await lockWorkspace(client, workspace);
            const role = await managerRole(client, workspace, actor);
            await client.query('UPDATE workspace SET name=$1 WHERE id=$2', [workspaceName, workspace]);
            return { workspace: { id: workspace, name: workspaceName }, role };
        },
        /** Owners and administrators: members, and the invitations still pending (unexpired, inviter still able to grant). */
        async getTeam(client, workspaceId, userId) {
            const workspaceKey = id(workspaceId), actor = id(userId);
            const workspace = await lockWorkspace(client, workspaceKey);
            const role = await managerRole(client, workspaceKey, actor);
            const members = await client.query('SELECT u.id AS "userId",u.name,u.email,m.role FROM membership m JOIN "user" u ON u.id=m.user_id WHERE m.workspace_id=$1 ORDER BY u.name,u.id', [workspaceKey]);
            const invitations = await client.query(`SELECT i.id,i.email,i.role,i.expires_at AS "expiresAt" FROM workspace_invitation i
         JOIN membership m ON m.workspace_id=i.workspace_id AND m.user_id=i.inviter_id
         WHERE i.workspace_id=$1 AND i.expires_at>clock_timestamp() AND ${pendingRole} ORDER BY i.created_at,i.id`, [workspaceKey]);
            const required = await client.query('SELECT 1 FROM workspace_two_factor_requirement WHERE workspace_id=$1', [workspaceKey]);
            return { workspace: { ...workspace, twoFactorRequired: required.rowCount === 1 }, role, members: members.rows, invitations: invitations.rows };
        },
        /** Owner only: require or stop requiring a verified second factor for every member. The owner must have one first. */
        async setTwoFactorRequirement(client, workspaceId, userId, input) {
            const workspace = id(workspaceId), actor = id(userId), { required } = fields(input, ['required']);
            if (typeof required !== 'boolean')
                invalid();
            await lockWorkspace(client, workspace);
            if (await managerRole(client, workspace, actor) !== 'owner')
                fail(403, 'FORBIDDEN', 'Only a workspace owner can change the two-factor requirement.');
            if (required) {
                // FOR SHARE: the owner's own concurrent factor disable either commits first or waits for this change.
                const owner = (await client.query('SELECT "twoFactorEnabled" FROM "user" WHERE id=$1 FOR SHARE', [actor])).rows[0];
                if (!owner?.twoFactorEnabled)
                    fail(409, 'FACTOR_REQUIRED', 'Turn on two-factor authentication for your own account before requiring it for this workspace.');
                await client.query('INSERT INTO workspace_two_factor_requirement(workspace_id) VALUES($1) ON CONFLICT DO NOTHING', [workspace]);
            }
            else
                await client.query('DELETE FROM workspace_two_factor_requirement WHERE workspace_id=$1', [workspace]);
            return { twoFactorRequired: required };
        },
        /** True when the workspace requires two-factor and this member has none; the app refuses its workspace routes then. */
        async memberNeedsFactor(client, workspaceId, userId) {
            const locked = await client.query(`SELECT 1 FROM workspace_two_factor_requirement r JOIN membership m ON m.workspace_id=r.workspace_id AND m.user_id=$2
         JOIN "user" u ON u.id=m.user_id WHERE NOT u."twoFactorEnabled" AND r.workspace_id=$1`, [id(workspaceId), id(userId)]);
            return !!locked.rowCount;
        },
        /**
         * Owners and administrators. Never grants owner; refuses an email that already belongs to a member; replaces an
         * earlier invitation to the same email. Returns the only copy of the token. An address outside the current rule is
         * accepted only when an existing account already has it.
         */
        async inviteMember(client, workspaceId, userId, input) {
            const workspace = id(workspaceId), actor = id(userId), details = fields(input, ['email', 'role']);
            const invitee = normalise(details.email);
            const role = details.role;
            if (typeof role !== 'string' || role === 'owner' || !workspaceRoles.some(value => value === role))
                invalid();
            // The shape is checked before any query; the full address rule below applies only to emails with no account yet.
            if (invitee.length > 320 || hasControl(invitee) || !/^[^\s@]+@[^\s@]+$/.test(invitee))
                invalid();
            await lockWorkspace(client, workspace);
            const actorRole = await managerRole(client, workspace, actor);
            requireGrant(actorRole, role);
            const account = (await client.query('SELECT id FROM "user" WHERE lower(email)=$1', [invitee])).rows[0];
            if (!account && !isEmailAddress(invitee))
                invalid();
            if (account && (await client.query('SELECT 1 FROM membership WHERE workspace_id=$1 AND user_id=$2', [workspace, account.id])).rowCount) {
                fail(409, 'MEMBER_EXISTS', 'This person already belongs to the workspace.');
            }
            const previous = (await client.query('SELECT role FROM workspace_invitation WHERE workspace_id=$1 AND email=$2 FOR UPDATE', [workspace, invitee])).rows[0];
            if (previous)
                requireGrant(actorRole, previous.role);
            await client.query('DELETE FROM workspace_invitation WHERE workspace_id=$1 AND email=$2', [workspace, invitee]);
            return newToken(client, `INSERT INTO workspace_invitation(id,workspace_id,inviter_id,email,role,token_hash,expires_at)
        VALUES($1,$2,$3,$4,$5,$6,clock_timestamp()+interval '7 days') RETURNING id,email,role,expires_at AS "expiresAt"`, [randomUUID(), workspace, actor, invitee, role]);
        },
        async revokeInvitation(client, workspaceId, userId, invitationId) {
            const workspace = id(workspaceId), actor = id(userId), invitationKey = id(invitationId);
            await lockWorkspace(client, workspace);
            const actorRole = await managerRole(client, workspace, actor);
            const invitation = (await client.query('SELECT role FROM workspace_invitation WHERE workspace_id=$1 AND id=$2 FOR UPDATE', [workspace, invitationKey])).rows[0];
            if (!invitation)
                fail(404, 'NOT_FOUND', 'Invitation not found or unavailable.');
            requireGrant(actorRole, invitation.role);
            await client.query('DELETE FROM workspace_invitation WHERE workspace_id=$1 AND id=$2', [workspace, invitationKey]);
        },
        /**
         * Replaces a pending invitation's token and restarts its seven days, keeping its id, email, role and inviter; the
         * previous link stops working. `admit` runs after authorization and the pending check, inside the same transaction.
         */
        async rotateInvitation(client, workspaceId, userId, invitationId, admit) {
            const workspace = id(workspaceId), actor = id(userId), invitationKey = id(invitationId);
            if (admit !== undefined && typeof admit !== 'function')
                invalid();
            const pending = await lockPendingInvitation(client, workspace, actor, invitationKey);
            await admit?.(client, pending);
            return newToken(client, `UPDATE workspace_invitation SET token_hash=$3,expires_at=clock_timestamp()+interval '7 days'
        WHERE workspace_id=$1 AND id=$2 RETURNING id,email,role,expires_at AS "expiresAt"`, [workspace, invitationKey]);
        },
        /** Needs authority over the saved and the requested role; keeps an owner; removes invitations the member can no longer grant. */
        async changeRole(client, workspaceId, userId, targetUserId, input) {
            const workspace = id(workspaceId), actor = id(userId), target = id(targetUserId), { role } = fields(input, ['role']);
            if (typeof role !== 'string' || !workspaceRoles.some(value => value === role))
                invalid();
            await lockWorkspace(client, workspace);
            const actorRole = await managerRole(client, workspace, actor);
            const saved = await targetRole(client, workspace, target);
            if (!mayManageWorkspaceMember(actorRole, saved, role))
                forbidden();
            await preserveOwner(client, workspace, saved, role);
            await client.query('UPDATE membership SET role=$1 WHERE workspace_id=$2 AND user_id=$3', [role, workspace, target]);
            await client.query(`DELETE FROM workspace_invitation WHERE workspace_id=$1 AND inviter_id=$2
        AND ($3::text NOT IN ('owner','admin') OR ($3='admin' AND role='admin'))`, [workspace, target, role]);
        },
        /** An owner promotes another member, confirmed by that member's email, and becomes an administrator, in one step. */
        async transferOwnership(client, workspaceId, userId, input) {
            const workspace = id(workspaceId), actor = id(userId), details = fields(input, ['targetUserId', 'confirmationEmail']);
            const target = id(details.targetUserId), confirmation = normalise(details.confirmationEmail);
            if (!confirmation)
                invalid();
            if (target === actor)
                fail(400, 'INVALID_INPUT', 'Choose another existing workspace member.');
            await lockWorkspace(client, workspace);
            if (await managerRole(client, workspace, actor) !== 'owner')
                fail(403, 'FORBIDDEN', 'Only a current owner can transfer ownership.');
            await targetRole(client, workspace, target);
            const member = (await client.query('SELECT email FROM "user" WHERE id=$1', [target])).rows[0];
            if (member.email.toLowerCase() !== confirmation)
                fail(409, 'CONFIRMATION_MISMATCH', 'The confirmation email does not match this member. Refresh the team and check the email.');
            const changed = await client.query("UPDATE membership SET role=CASE WHEN user_id=$2 THEN 'owner' ELSE 'admin' END WHERE workspace_id=$1 AND user_id IN ($2,$3)", [workspace, target, actor]);
            if (changed.rowCount !== 2)
                fail(409, 'MEMBERSHIP_CHANGED', 'Team membership changed. Refresh the team before trying again.');
            await client.query("DELETE FROM workspace_invitation WHERE workspace_id=$1 AND inviter_id=$2 AND role='admin'", [workspace, actor]);
            return { ok: true, role: 'admin', ownerUserId: target };
        },
        /**
         * Removes a member, or lets a member leave (userId === targetUserId). The caller's authority is checked before the
         * target is read, so a non-manager gets the same answer whether or not the target exists. Keeps an owner; removes
         * invitations the member sent or received.
         */
        async removeMember(client, workspaceId, userId, targetUserId) {
            const workspace = id(workspaceId), actor = id(userId), target = id(targetUserId);
            await lockWorkspace(client, workspace);
            let saved;
            if (actor === target) {
                saved = (await client.query('SELECT role FROM membership WHERE workspace_id=$1 AND user_id=$2 FOR UPDATE', [workspace, actor])).rows[0]?.role ?? notFound();
            }
            else {
                const actorRole = await managerRole(client, workspace, actor);
                saved = await targetRole(client, workspace, target);
                if (!mayManageWorkspaceMember(actorRole, saved))
                    forbidden();
            }
            await preserveOwner(client, workspace, saved);
            await client.query('DELETE FROM membership WHERE workspace_id=$1 AND user_id=$2', [workspace, target]);
            await client.query('DELETE FROM workspace_invitation WHERE workspace_id=$1 AND (inviter_id=$2 OR email=(SELECT lower(email) FROM "user" WHERE id=$2))', [workspace, target]);
        },
        /** Public, for the token holder: what the invitation offers, and whether its email already has an account (so sign-in comes first). */
        async inspectInvitation(client, input) {
            const value = token(fields(input, ['token']).token);
            const invitation = (await client.query(`SELECT w.id AS "workspaceId",w.name AS "workspaceName",i.email,i.role,i.expires_at AS "expiresAt",
           EXISTS(SELECT 1 FROM "user" u WHERE lower(u.email)=i.email) AS "accountExists"
         FROM workspace_invitation i JOIN workspace w ON w.id=i.workspace_id
         JOIN membership m ON m.workspace_id=i.workspace_id AND m.user_id=i.inviter_id
         WHERE i.token_hash=$1 AND i.expires_at>clock_timestamp() AND ${pendingRole}`, [digest(value)])).rows[0] ?? unavailable();
            return { workspace: { id: invitation.workspaceId, name: invitation.workspaceName }, email: invitation.email, role: invitation.role, expiresAt: invitation.expiresAt, accountExists: invitation.accountExists };
        },
        /**
         * Accepts with the invited account signed in, or creates that account with `name` and a 12-128 character `password`
         * (hashed before any lock is taken). An existing account must be signed in (409 SIGN_IN_REQUIRED); another
         * signed-in account is refused (403 WRONG_ACCOUNT). `joined` is false when the account was already a member, whose
         * role is never replaced; `role` is the role it holds now.
         */
        async acceptInvitation(client, input, signedInUser) {
            const details = fields(input, ['token', 'name', 'password']);
            const value = token(details.token);
            const newName = details.name === undefined ? undefined : name(details.name);
            if (details.password !== undefined && (typeof details.password !== 'string' || details.password.length < 12 || details.password.length > 128))
                invalid();
            const signedInFields = signedInUser === undefined ? undefined : fields(signedInUser, ['id', 'email']);
            // A stored email predating the current address rule still matches: it is only trimmed and lowercased.
            const signedIn = signedInFields === undefined ? undefined : { id: id(signedInFields.id), email: normalise(signedInFields.email) };
            const passwordHash = typeof details.password === 'string' ? await hashPassword(details.password) : undefined;
            const { workspaceId, invitation } = await lockInvitation(client, digest(value));
            let userId = (await client.query('SELECT id FROM "user" WHERE lower(email)=$1', [invitation.email])).rows[0]?.id;
            if (signedIn && (signedIn.id !== userId || signedIn.email !== invitation.email))
                fail(403, 'WRONG_ACCOUNT', 'Sign in with the email this invitation was sent to.');
            const created = !userId;
            if (userId && !signedIn)
                fail(409, 'SIGN_IN_REQUIRED', 'Sign in with the invited email to accept this invitation.');
            if (!userId) {
                if (!newName || !passwordHash)
                    fail(400, 'INVALID_INPUT', 'Enter your name and a password between 12 and 128 characters.');
                userId = randomUUID();
                await client.query('INSERT INTO "user"(id,name,email) VALUES($1,$2,$3)', [userId, newName, invitation.email]);
                await client.query('INSERT INTO account(id,"accountId","providerId","userId",password) VALUES($1,$2,\'credential\',$2,$3)', [randomUUID(), userId, passwordHash]);
            }
            const { joined, role } = await consumeInvitation(client, invitation, workspaceId, userId);
            return { workspaceId, userId: userId, role, joined, created, email: invitation.email };
        },
        /** Server only: `identity` must be cryptographically verified OIDC claims. Creates the account; an existing one must link explicitly. */
        async acceptVerifiedOidcInvitation(client, tokenValue, identity, passwordHash) {
            const claims = fields(identity, ['email', 'name']);
            const verified = { email: email(claims.email), name: name(claims.name) };
            if (passwordHash !== undefined && typeof passwordHash !== 'string')
                invalid();
            const { workspaceId, invitation } = await lockInvitation(client, digest(token(tokenValue)));
            if (invitation.email !== verified.email)
                fail(403, 'OIDC_INVITE_EMAIL_MISMATCH', 'The verified provider email does not match the invitation recipient.');
            if ((await client.query('SELECT id FROM "user" WHERE lower(email)=$1', [verified.email])).rowCount) {
                fail(409, 'OIDC_ACCOUNT_EXISTS', 'Sign in with the existing account before accepting this invitation. Link the provider explicitly in account settings.');
            }
            const userId = randomUUID();
            await client.query('INSERT INTO "user"(id,name,email,"emailVerified") VALUES($1,$2,$3,true)', [userId, verified.name, verified.email]);
            if (passwordHash)
                await client.query('INSERT INTO account(id,"accountId","providerId","userId",password) VALUES($1,$2,\'credential\',$2,$3)', [randomUUID(), userId, passwordHash]);
            const { role } = await consumeInvitation(client, invitation, workspaceId, userId);
            return { userId, workspaceId, role };
        },
        /** An open account with an operator row; closed accounts never count. */
        async isInstanceOperator(client, userId) {
            return !!(await isOperator(client, id(userId))).rowCount;
        },
        /** Holds the operator row (FOR SHARE) for the rest of the caller's transaction; closed accounts are refused. */
        async requireInstanceOperator(client, userId) {
            if (!(await isOperator(client, id(userId), 'FOR SHARE OF o')).rowCount)
                fail(403, 'OPERATOR_REQUIRED', 'This action requires an instance operator.');
        },
        /**
         * Host CLI only: no HTTP route grants operator authority. Grants (open accounts only) or revokes, and writes the
         * audit row in the caller's transaction only when something changed.
         */
        async setInstanceOperator(client, accountEmail, enabled) {
            if (typeof enabled !== 'boolean')
                invalid();
            const user = (await client.query(`SELECT id FROM "user" WHERE lower(email)=$1 ${enabled ? 'AND closed_at IS NULL' : ''} FOR UPDATE`, [email(accountEmail)])).rows[0];
            if (!user)
                fail(404, 'NOT_FOUND', 'No existing account has that email.');
            const changed = enabled
                ? await client.query("INSERT INTO instance_operator(user_id,source) VALUES($1,'host') ON CONFLICT(user_id) DO NOTHING", [user.id])
                : await client.query('DELETE FROM instance_operator WHERE user_id=$1', [user.id]);
            if (changed.rowCount === 1)
                await client.query('INSERT INTO instance_operator_audit(user_id,action) VALUES($1,$2)', [user.id, enabled ? 'grant' : 'revoke']);
        },
        /** Host CLI only: the named open account, held as an operator; an unknown or closed account gets the non-operator refusal. */
        async requireNamedInstanceOperator(client, accountEmail) {
            const user = (await client.query('SELECT id FROM "user" WHERE lower(email)=$1 AND closed_at IS NULL', [email(accountEmail)])).rows[0];
            if (!user || !(await isOperator(client, user.id, 'FOR SHARE OF o')).rowCount)
                fail(403, 'OPERATOR_REQUIRED', 'This action requires an instance operator.');
            return user.id;
        },
    };
}
