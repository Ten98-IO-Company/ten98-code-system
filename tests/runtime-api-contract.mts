import * as current from '../index.mjs';
import type * as previous from './fixtures/runtime-0.1.4.mjs';
type Equal<A, B> = (<T>() => T extends A ? 1 : 2) extends (<T>() => T extends B ? 1 : 2) ? true : false;
type Assert<T extends true> = T;
// Additions are allowed; every value exported by 0.1.4 must remain assignable.
export type PublicValuesCompatible = Assert<typeof current extends typeof previous ? true : false>;
export type PublicRoleUnchanged = Assert<Equal<current.WorkspaceRole, previous.WorkspaceRole>>;
