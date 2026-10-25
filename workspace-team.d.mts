import { type WorkspaceRole as Role } from './browser.mjs';
/** The subset of a `pg` client (or pool, for the read-only calls) that the controller uses. */
export interface TeamClient {
    query<R extends Record<string, unknown> = Record<string, unknown>>(sql: string, params?: unknown[]): Promise<{
        rows: R[];
        rowCount: number | null;
    }>;
}
export type TeamErrorCode = 'INVALID_INPUT' | 'SIGN_IN_REQUIRED' | 'NOT_FOUND' | 'FORBIDDEN' | 'LAST_OWNER' | 'FACTOR_REQUIRED' | 'INVITATION_UNAVAILABLE' | 'INVITATION_NOT_PENDING' | 'WRONG_ACCOUNT' | 'CONFIRMATION_MISMATCH' | 'MEMBERSHIP_CHANGED' | 'OIDC_INVITE_EMAIL_MISMATCH' | 'OIDC_ACCOUNT_EXISTS' | 'OPERATOR_REQUIRED';
/** Thrown for every refusal: `status` is the HTTP status that fits and `message` is safe to show. */
export type TeamError = Error & {
    status: 400 | 401 | 403 | 404 | 409 | 410;
    code: TeamErrorCode;
};
export type InvitationRole = Exclude<Role, 'owner'>;
export type Invitation = {
    id: string;
    email: string;
    role: InvitationRole;
    expiresAt: Date;
};
/**
 * `hashPassword` hashes the password of an account created by accepting an invitation (better-auth's, so the preset can
 * verify it). `emailLockKey` is the first key of the advisory lock that serialises account creation per email.
 */
export declare function createWorkspaceTeam({ hashPassword, emailLockKey }: {
    hashPassword(password: string): Promise<string>;
    emailLockKey?: number;
}): {
    createWorkspace(client: TeamClient, userId: unknown, input: unknown): Promise<{
        workspace: {
            id: `${string}-${string}-${string}-${string}-${string}`;
            name: string;
        };
        role: 'owner';
    }>;
    renameWorkspace(client: TeamClient, workspaceId: unknown, userId: unknown, input: unknown): Promise<{
        workspace: {
            id: string;
            name: string;
        };
        role: "admin" | "owner";
    }>;
    /** Owners and administrators: members, and the invitations still pending (unexpired, inviter still able to grant). */
    getTeam(client: TeamClient, workspaceId: unknown, userId: unknown): Promise<{
        workspace: {
            id: string;
            name: string;
            twoFactorRequired: boolean;
        };
        role: "admin" | "owner";
        members: {
            userId: string;
            name: string;
            email: string;
            role: Role;
        }[];
        invitations: (Invitation & Record<string, unknown>)[];
    }>;
    /** Owner only: require or stop requiring a verified second factor for every member. The owner must have one first. */
    setTwoFactorRequirement(client: TeamClient, workspaceId: unknown, userId: unknown, input: unknown): Promise<{
        twoFactorRequired: boolean;
    }>;
    /** True when the workspace requires two-factor and this member has none; the app refuses its workspace routes then. */
    memberNeedsFactor(client: TeamClient, workspaceId: unknown, userId: unknown): Promise<boolean>;
    /** Owners and administrators. Never grants owner. Replaces any earlier invitation to the same email. Returns the only copy of the token. */
    inviteMember(client: TeamClient, workspaceId: unknown, userId: unknown, input: unknown): Promise<{
        invitation: {
            id: string;
            email: string;
            role: InvitationRole;
            expiresAt: Date;
        };
        token: string;
    }>;
    revokeInvitation(client: TeamClient, workspaceId: unknown, userId: unknown, invitationId: unknown): Promise<void>;
    /**
     * Replaces a pending invitation's token and restarts its seven days, keeping its id, email, role and inviter; the
     * previous link stops working. `admit` runs after authorization and the pending check, inside the same transaction.
     */
    rotateInvitation(client: TeamClient, workspaceId: unknown, userId: unknown, invitationId: unknown, admit?: (client: TeamClient, invitation: Invitation) => Promise<void>): Promise<{
        invitation: {
            id: string;
            email: string;
            role: InvitationRole;
            expiresAt: Date;
        };
        token: string;
    }>;
    /** Needs authority over the saved and the requested role; keeps an owner; removes invitations the member can no longer grant. */
    changeRole(client: TeamClient, workspaceId: unknown, userId: unknown, targetUserId: unknown, input: unknown): Promise<void>;
    /** An owner promotes another member, confirmed by that member's email, and becomes an administrator, in one step. */
    transferOwnership(client: TeamClient, workspaceId: unknown, userId: unknown, input: unknown): Promise<{
        ok: true;
        role: 'admin';
        ownerUserId: string;
    }>;
    /** Also a member leaving (userId === targetUserId). Keeps an owner; removes invitations the member sent or received. */
    removeMember(client: TeamClient, workspaceId: unknown, userId: unknown, targetUserId: unknown): Promise<void>;
    /** Public, for the token holder: what the invitation offers, and whether its email already has an account (so sign-in comes first). */
    inspectInvitation(client: TeamClient, input: unknown): Promise<{
        workspace: {
            id: string;
            name: string;
        };
        email: string;
        role: InvitationRole;
        expiresAt: Date;
        accountExists: boolean;
    }>;
    /**
     * Accepts with the invited account signed in, or creates that account with `name` and a 12-128 character `password`.
     * An existing account must be signed in (409 SIGN_IN_REQUIRED); another signed-in account is refused (403 WRONG_ACCOUNT).
     */
    acceptInvitation(client: TeamClient, input: unknown, signedInUser?: {
        id: string;
        email: string;
    }): Promise<{
        workspaceId: string;
        created: boolean;
        email: string;
    }>;
    /** Server only: `identity` must be cryptographically verified OIDC claims. Creates the account; an existing one must link explicitly. */
    acceptVerifiedOidcInvitation(client: TeamClient, tokenValue: unknown, identity: {
        email: string;
        name: string;
    }, passwordHash?: string): Promise<{
        userId: `${string}-${string}-${string}-${string}-${string}`;
        workspaceId: string;
    }>;
    isInstanceOperator(client: TeamClient, userId: unknown): Promise<boolean>;
    /** Holds the operator row (FOR SHARE) for the rest of the caller's transaction. */
    requireInstanceOperator(client: TeamClient, userId: unknown): Promise<void>;
    /** Host CLI only: no HTTP route grants operator authority. Grants or revokes and writes the audit row in the caller's transaction. */
    setInstanceOperator(client: TeamClient, accountEmail: unknown, enabled: boolean): Promise<void>;
    /** Host CLI only: the named open account, held as an operator; an unknown or closed account gets the non-operator refusal. */
    requireNamedInstanceOperator(client: TeamClient, accountEmail: unknown): Promise<string>;
};
export type WorkspaceTeam = ReturnType<typeof createWorkspaceTeam>;
