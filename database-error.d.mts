declare const NAMES: readonly ['constraint', 'table', 'column', 'schema'];
type Kept = Partial<Record<'code' | (typeof NAMES)[number], string>>;
/** A database error reduced to its class name, SQLSTATE code and the constraint, table, column and schema names. */
export declare class SafeDatabaseError extends Error {
    name: string;
    /** The class name of the error this was made from, such as `DrizzleQueryError` or `DatabaseError`. */
    readonly errorClass: string;
    readonly code?: string;
    readonly constraint?: string;
    readonly table?: string;
    readonly column?: string;
    readonly schema?: string;
    readonly cause?: SafeDatabaseError;
    constructor(errorClass: string, message: string, kept: Kept, cause?: SafeDatabaseError);
}
export declare function errorClassName(value: unknown): string;
/**
 * Whether the error carries a statement or a database server report: a statement wrapper (own `query` or `params`,
 * as DrizzleQueryError has), a pg server error (a SQLSTATE `code` with a `severity`), or one of those class names.
 */
export declare function isDatabaseError(value: unknown): boolean;
/**
 * The error, and each error in its `cause` chain, reduced to class name, SQLSTATE code and constraint, table, column and
 * schema names. The statement, its parameters, `detail`, `hint`, `where` and the server message are dropped; a
 * statement wrapper's message is cut before the statement ("Failed query"). The original is not attached.
 * Never throws; a value that is already a SafeDatabaseError is returned as it is.
 */
export declare function safeDatabaseError(error: unknown): SafeDatabaseError;
export {};
