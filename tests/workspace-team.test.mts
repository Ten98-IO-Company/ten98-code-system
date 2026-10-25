import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import pg from 'pg';
import { createWorkspaceTeam } from '../index.mjs';
import type { TeamClient } from '../index.mjs';

// Integration tests on real PostgreSQL, opt-in: set TEN98_TEST_DATABASE_URL to a disposable server (a superuser URL; each
// run creates and drops its own database). Without it the suite is skipped, like the other opt-in checks.
const admin = process.env.TEN98_TEST_DATABASE_URL;
const skip = admin ? false : 'set TEN98_TEST_DATABASE_URL to a disposable PostgreSQL to run the workspace-team integration tests';
const team = createWorkspaceTeam({ hashPassword: async password => `hash:${password}` });
let pool: pg.Pool | undefined;
let database = '';

test.before(async () => {
  if (!admin) return;
  database = `ten98_team_${randomBytes(6).toString('hex')}`;
  const root = new pg.Client({ connectionString: admin });
  await root.connect();
  await root.query(`CREATE DATABASE ${database}`);
  await root.end();
  const url = new URL(admin);
  url.pathname = `/${database}`;
  pool = new pg.Pool({ connectionString: url.href, max: 4 });
  await pool.query(readFileSync(new URL('./fixtures/workspace-team.sql', import.meta.url), 'utf8'));
});
test.after(async () => {
  if (!admin || !pool) return;
  await pool.end();
  const root = new pg.Client({ connectionString: admin });
  await root.connect();
  await root.query(`DROP DATABASE IF EXISTS ${database} WITH (FORCE)`);
  await root.end();
});

async function tx<T>(run: (client: TeamClient) => Promise<T>): Promise<T> {
  const client = await pool!.connect();
  try {
    await client.query('BEGIN');
    const result = await run(client as unknown as TeamClient);
    await client.query('COMMIT');
    return result;
  } catch (error) { await client.query('ROLLBACK'); throw error; }
  finally { client.release(); }
}
const code = (expected: string, status?: number) => (error: unknown) => (error as { code?: string }).code === expected && (status === undefined || (error as { status?: number }).status === status);
async function user(email: string, { twoFactor = false, closed = false } = {}) {
  const userId = randomUUID();
  await pool!.query('INSERT INTO "user"(id,name,email,"twoFactorEnabled",closed_at) VALUES($1,$2,$3,$4,$5)', [userId, email.split('@')[0], email, twoFactor, closed ? new Date() : null]);
  return userId;
}
async function workspaceWith(members: Record<string, 'admin' | 'editor' | 'viewer'> = {}) {
  const owner = await user(`owner-${randomUUID()}@example.com`);
  const { workspace } = await tx(client => team.createWorkspace(client, owner, { name: '  Acme  ' }));
  const ids: Record<string, string> = {};
  for (const [label, role] of Object.entries(members)) {
    ids[label] = await user(`${label}-${randomUUID()}@example.com`);
    await pool!.query('INSERT INTO membership(workspace_id,user_id,role) VALUES($1,$2,$3)', [workspace.id, ids[label], role]);
  }
  return { owner, workspaceId: workspace.id, ids };
}
const emailOf = async (userId: string) => (await pool!.query<{ email: string }>('SELECT email FROM "user" WHERE id=$1', [userId])).rows[0]!.email;

test('an owner creates, renames and lists a workspace', { skip }, async () => {
  const { owner, workspaceId, ids } = await workspaceWith({ viewer: 'viewer' });
  assert.deepEqual(await tx(client => team.renameWorkspace(client, workspaceId, owner, { name: 'Beta' })), { workspace: { id: workspaceId, name: 'Beta' }, role: 'owner' });
  const listed = await tx(client => team.getTeam(client, workspaceId, owner));
  assert.deepEqual([listed.workspace.name, listed.workspace.twoFactorRequired, listed.members.length, listed.role], ['Beta', false, 2, 'owner']);
  await assert.rejects(tx(client => team.getTeam(client, workspaceId, ids.viewer)), code('NOT_FOUND', 404));
  await assert.rejects(tx(client => team.createWorkspace(client, randomUUID(), { name: 'x' })), code('SIGN_IN_REQUIRED', 401));
  for (const input of [{ name: '' }, { name: 'x'.repeat(121) }, { name: 'ok', extra: 1 }, null]) await assert.rejects(tx(client => team.createWorkspace(client, owner, input)), code('INVALID_INPUT', 400));
});

test('invitations never grant owner, follow grant authority, and are accepted once', { skip }, async () => {
  const { owner, workspaceId, ids } = await workspaceWith({ admin: 'admin' });
  await assert.rejects(tx(client => team.inviteMember(client, workspaceId, owner, { email: 'x@example.com', role: 'owner' })), code('INVALID_INPUT'));
  await assert.rejects(tx(client => team.inviteMember(client, workspaceId, ids.admin!, { email: 'x@example.com', role: 'admin' })), code('FORBIDDEN', 403));
  const { invitation, token } = await tx(client => team.inviteMember(client, workspaceId, ids.admin!, { email: ' New@Example.com ', role: 'editor' }));
  assert.deepEqual([invitation.email, invitation.role, token.length], ['new@example.com', 'editor', 43]);
  const stored = (await pool!.query<{ token_hash: string }>('SELECT token_hash FROM workspace_invitation WHERE id=$1', [invitation.id])).rows[0]!.token_hash;
  assert.notEqual(stored, token);
  assert.equal((await tx(client => team.inspectInvitation(client, { token }))).accountExists, false);
  await assert.rejects(tx(client => team.acceptInvitation(client, { token, name: 'New' })), code('INVALID_INPUT'));
  const accepted = await tx(client => team.acceptInvitation(client, { token, name: 'New', password: 'twelve chars!' }));
  assert.deepEqual([accepted.workspaceId, accepted.created, accepted.email], [workspaceId, true, 'new@example.com']);
  const account = (await pool!.query<{ password: string }>('SELECT a.password FROM account a JOIN "user" u ON u.id=a."userId" WHERE u.email=$1', ['new@example.com'])).rows[0]!;
  assert.equal(account.password, 'hash:twelve chars!');
  await assert.rejects(tx(client => team.acceptInvitation(client, { token, name: 'New', password: 'twelve chars!' })), code('INVITATION_UNAVAILABLE', 410));
  await assert.rejects(tx(client => team.inspectInvitation(client, { token })), code('INVITATION_UNAVAILABLE', 410));
});

test('an existing account must be signed in as itself to accept', { skip }, async () => {
  const { owner, workspaceId } = await workspaceWith();
  const invited = await user(`invited-${randomUUID()}@example.com`), other = await user(`other-${randomUUID()}@example.com`);
  const invitedEmail = await emailOf(invited);
  const { token } = await tx(client => team.inviteMember(client, workspaceId, owner, { email: invitedEmail, role: 'viewer' }));
  assert.equal((await tx(client => team.inspectInvitation(client, { token }))).accountExists, true);
  await assert.rejects(tx(client => team.acceptInvitation(client, { token })), code('SIGN_IN_REQUIRED', 409));
  await assert.rejects(tx(async client => team.acceptInvitation(client, { token }, { id: other, email: await emailOf(other) })), code('WRONG_ACCOUNT', 403));
  const accepted = await tx(async client => team.acceptInvitation(client, { token }, { id: invited, email: await emailOf(invited) }));
  assert.equal(accepted.created, false);
  assert.equal((await pool!.query('SELECT role FROM membership WHERE workspace_id=$1 AND user_id=$2', [workspaceId, invited])).rows[0]?.role, 'viewer');
});

test('rotation replaces the link, revocation and expiry end it, and losing authority withdraws it', { skip }, async () => {
  const { owner, workspaceId, ids } = await workspaceWith({ admin: 'admin' });
  const first = await tx(client => team.inviteMember(client, workspaceId, owner, { email: 'r@example.com', role: 'viewer' }));
  const rotated = await tx(client => team.rotateInvitation(client, workspaceId, owner, first.invitation.id));
  assert.equal(rotated.invitation.id, first.invitation.id);
  await assert.rejects(tx(client => team.inspectInvitation(client, { token: first.token })), code('INVITATION_UNAVAILABLE'));
  await tx(client => team.inspectInvitation(client, { token: rotated.token }));
  await tx(client => team.revokeInvitation(client, workspaceId, owner, first.invitation.id));
  await assert.rejects(tx(client => team.inspectInvitation(client, { token: rotated.token })), code('INVITATION_UNAVAILABLE'));
  await assert.rejects(tx(client => team.rotateInvitation(client, workspaceId, owner, first.invitation.id)), code('INVITATION_NOT_PENDING', 409));
  const expiring = await tx(client => team.inviteMember(client, workspaceId, owner, { email: 'e@example.com', role: 'viewer' }));
  await pool!.query("UPDATE workspace_invitation SET expires_at=now()-interval '1 second' WHERE id=$1", [expiring.invitation.id]);
  await assert.rejects(tx(client => team.inspectInvitation(client, { token: expiring.token })), code('INVITATION_UNAVAILABLE'));
  // An administrator's invitations go when they are demoted below the role they invited.
  const sent = await tx(client => team.inviteMember(client, workspaceId, ids.admin!, { email: 'a@example.com', role: 'editor' }));
  await tx(client => team.changeRole(client, workspaceId, owner, ids.admin!, { role: 'editor' }));
  await assert.rejects(tx(client => team.inspectInvitation(client, { token: sent.token })), code('INVITATION_UNAVAILABLE'));
  const pending = await tx(client => team.getTeam(client, workspaceId, owner));
  assert.equal(pending.invitations.some(row => row.email === 'a@example.com'), false);
  // Even if the inviter's role changes outside the controller, acceptance rechecks the inviter's authority.
  const second = await workspaceWith({ admin: 'admin' });
  const orphan = await tx(client => team.inviteMember(client, second.workspaceId, second.ids.admin!, { email: 'o@example.com', role: 'editor' }));
  await pool!.query("UPDATE membership SET role='viewer' WHERE workspace_id=$1 AND user_id=$2", [second.workspaceId, second.ids.admin]);
  await assert.rejects(tx(client => team.acceptInvitation(client, { token: orphan.token, name: 'O', password: 'twelve chars!' })), code('INVITATION_UNAVAILABLE'));
});

test('roles keep an owner, transfers are atomic, and members can leave', { skip }, async () => {
  const { owner, workspaceId, ids } = await workspaceWith({ admin: 'admin', viewer: 'viewer' });
  await assert.rejects(tx(client => team.changeRole(client, workspaceId, owner, owner, { role: 'admin' })), code('LAST_OWNER', 409));
  await assert.rejects(tx(client => team.removeMember(client, workspaceId, owner, owner)), code('LAST_OWNER', 409));
  await assert.rejects(tx(client => team.changeRole(client, workspaceId, ids.admin!, owner, { role: 'viewer' })), code('FORBIDDEN', 403));
  await assert.rejects(tx(client => team.transferOwnership(client, workspaceId, owner, { targetUserId: ids.admin, confirmationEmail: 'wrong@example.com' })), code('CONFIRMATION_MISMATCH', 409));
  const adminInvite = await tx(client => team.inviteMember(client, workspaceId, owner, { email: 'adm@example.com', role: 'admin' }));
  const transfer = await tx(async client => team.transferOwnership(client, workspaceId, owner, { targetUserId: ids.admin, confirmationEmail: (await emailOf(ids.admin!)).toUpperCase() }));
  assert.deepEqual(transfer, { ok: true, role: 'admin', ownerUserId: ids.admin });
  const roles = Object.fromEntries((await pool!.query<{ user_id: string; role: string }>('SELECT user_id,role FROM membership WHERE workspace_id=$1', [workspaceId])).rows.map(row => [row.user_id, row.role]));
  assert.deepEqual([roles[owner], roles[ids.admin!]], ['admin', 'owner']);
  await assert.rejects(tx(client => team.inspectInvitation(client, { token: adminInvite.token })), code('INVITATION_UNAVAILABLE'));
  // A viewer leaves on their own; their invitations go with them.
  await tx(client => team.removeMember(client, workspaceId, ids.viewer!, ids.viewer!));
  assert.equal((await pool!.query('SELECT 1 FROM membership WHERE workspace_id=$1 AND user_id=$2', [workspaceId, ids.viewer])).rowCount, 0);
  await assert.rejects(tx(client => team.removeMember(client, workspaceId, ids.viewer!, owner)), code('NOT_FOUND'));
});

test('removing a member removes invitations they sent and received', { skip }, async () => {
  const { owner, workspaceId, ids } = await workspaceWith({ admin: 'admin' });
  const sent = await tx(client => team.inviteMember(client, workspaceId, ids.admin!, { email: 's@example.com', role: 'viewer' }));
  const received = await tx(async client => team.inviteMember(client, workspaceId, owner, { email: await emailOf(ids.admin!), role: 'editor' }));
  await tx(client => team.removeMember(client, workspaceId, owner, ids.admin!));
  for (const { token } of [sent, received]) await assert.rejects(tx(client => team.inspectInvitation(client, { token })), code('INVITATION_UNAVAILABLE'));
});

test('two concurrent acceptances of one link create one account and one membership', { skip }, async () => {
  const { owner, workspaceId } = await workspaceWith();
  const { token } = await tx(client => team.inviteMember(client, workspaceId, owner, { email: 'race@example.com', role: 'viewer' }));
  const results = await Promise.allSettled([1, 2].map(() => tx(client => team.acceptInvitation(client, { token, name: 'Race', password: 'twelve chars!' }))));
  assert.deepEqual(results.map(result => result.status).sort(), ['fulfilled', 'rejected']);
  assert.ok(code('INVITATION_UNAVAILABLE')((results.find(result => result.status === 'rejected') as PromiseRejectedResult).reason));
  assert.equal((await pool!.query('SELECT 1 FROM "user" WHERE email=$1', ['race@example.com'])).rowCount, 1);
});

test('verified OIDC acceptance creates only a new, matching account', { skip }, async () => {
  const { owner, workspaceId } = await workspaceWith();
  const existing = await user(`taken-${randomUUID()}@example.com`);
  const mismatch = await tx(client => team.inviteMember(client, workspaceId, owner, { email: 'sso@example.com', role: 'viewer' }));
  await assert.rejects(tx(client => team.acceptVerifiedOidcInvitation(client, mismatch.token, { email: 'other@example.com', name: 'S' })), code('OIDC_INVITE_EMAIL_MISMATCH', 403));
  const taken = await tx(async client => team.inviteMember(client, workspaceId, owner, { email: await emailOf(existing), role: 'viewer' }));
  await assert.rejects(tx(async client => team.acceptVerifiedOidcInvitation(client, taken.token, { email: await emailOf(existing), name: 'T' })), code('OIDC_ACCOUNT_EXISTS', 409));
  const created = await tx(client => team.acceptVerifiedOidcInvitation(client, mismatch.token, { email: 'SSO@example.com', name: 'Sso' }));
  assert.equal(created.workspaceId, workspaceId);
  assert.equal((await pool!.query<{ emailVerified: boolean }>('SELECT "emailVerified" FROM "user" WHERE id=$1', [created.userId])).rows[0]!.emailVerified, true);
});

test('a two-factor requirement needs the owner\'s own factor and flags members without one', { skip }, async () => {
  const { owner, workspaceId, ids } = await workspaceWith({ editor: 'editor' });
  await assert.rejects(tx(client => team.setTwoFactorRequirement(client, workspaceId, owner, { required: true })), code('FACTOR_REQUIRED', 409));
  await assert.rejects(tx(client => team.setTwoFactorRequirement(client, workspaceId, ids.editor!, { required: true })), code('NOT_FOUND'));
  await pool!.query('UPDATE "user" SET "twoFactorEnabled"=true WHERE id=$1', [owner]);
  assert.deepEqual(await tx(client => team.setTwoFactorRequirement(client, workspaceId, owner, { required: true })), { twoFactorRequired: true });
  assert.equal(await team.memberNeedsFactor(pool! as unknown as TeamClient, workspaceId, ids.editor), true);
  assert.equal(await team.memberNeedsFactor(pool! as unknown as TeamClient, workspaceId, owner), false);
  await tx(client => team.setTwoFactorRequirement(client, workspaceId, owner, { required: false }));
  assert.equal(await team.memberNeedsFactor(pool! as unknown as TeamClient, workspaceId, ids.editor), false);
});

test('operator grants come from the host, are audited, and closed accounts never act as operators', { skip }, async () => {
  const operator = await user(`op-${randomUUID()}@example.com`), closed = await user(`closed-${randomUUID()}@example.com`, { closed: true });
  await assert.rejects(tx(client => team.requireInstanceOperator(client, operator)), code('OPERATOR_REQUIRED', 403));
  await tx(async client => team.setInstanceOperator(client, (await emailOf(operator)).toUpperCase(), true));
  assert.equal(await team.isInstanceOperator(pool! as unknown as TeamClient, operator), true);
  assert.equal(await tx(async client => team.requireNamedInstanceOperator(client, await emailOf(operator))), operator);
  await tx(async client => team.setInstanceOperator(client, await emailOf(closed), true));
  await assert.rejects(tx(async client => team.requireNamedInstanceOperator(client, await emailOf(closed))), code('OPERATOR_REQUIRED'));
  await tx(async client => team.setInstanceOperator(client, await emailOf(operator), false));
  assert.equal(await team.isInstanceOperator(pool! as unknown as TeamClient, operator), false);
  const audit = (await pool!.query<{ action: string }>('SELECT action FROM instance_operator_audit WHERE user_id=$1 ORDER BY id', [operator])).rows.map(row => row.action);
  assert.deepEqual(audit, ['grant', 'revoke']);
  await assert.rejects(tx(client => team.setInstanceOperator(client, 'nobody@example.com', true)), code('NOT_FOUND', 404));
});

test('ids, tokens and emails are validated before any query', async () => {
  const calls: string[] = [];
  const client: TeamClient = { async query(sql: string) { calls.push(sql); return { rows: [], rowCount: 0 }; } };
  await assert.rejects(team.renameWorkspace(client, 'not-a-uuid', randomUUID(), { name: 'x' }), code('INVALID_INPUT'));
  await assert.rejects(team.inspectInvitation(client, { token: 'short' }), code('INVALID_INPUT'));
  await assert.rejects(team.inviteMember(client, randomUUID(), randomUUID(), { email: 'not an email', role: 'viewer' }), code('INVALID_INPUT'));
  await assert.rejects(team.acceptInvitation(client, { token: 'A'.repeat(43), password: 'short' }), code('INVALID_INPUT'));
  assert.deepEqual(calls, []);
  assert.throws(() => createWorkspaceTeam({ hashPassword: undefined as unknown as (password: string) => Promise<string> }), TypeError);
});
