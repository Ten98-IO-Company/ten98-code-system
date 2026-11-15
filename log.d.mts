export { safeDatabaseError, SafeDatabaseError } from './database-error.mjs';
export type LogLevel = 'debug' | 'info' | 'warn' | 'error';
export type LogFields = Readonly<Record<string, unknown>>;
export interface Logger {
    debug(message: string, fields?: LogFields | Error): void;
    info(message: string, fields?: LogFields | Error): void;
    warn(message: string, fields?: LogFields | Error): void;
    error(message: string, fields?: LogFields | Error): void;
    /** A logger that adds these fields to every line; fields given to a call override them. */
    child(fields: LogFields): Logger;
}
export interface LoggerOptions {
    service: string;
    /** The least severe level written; defaults to 'info'. */
    level?: LogLevel;
    /** Paths hidden in addition to DEFAULT_REDACT_PATHS, in pino's path syntax (`user.email`, `*.ssn`, `a["b-c"]`). */
    redact?: readonly string[];
    /** Receives each line, newline included; defaults to standard output. */
    write?: (line: string) => void;
}
/** The paths every logger hides with `[redacted]`; `createLogger({ redact })` adds to them and cannot remove any. */
export declare const DEFAULT_REDACT_PATHS: readonly string[];
/**
 * A logger writing one JSON line per call with `time` (ISO), `level`, `service`, the fields and `msg`. Values at
 * DEFAULT_REDACT_PATHS and `redact` are written as `[redacted]`. A field named `time`, `level`, `service` or `msg` is not
 * written. A log call never throws. Throws a TypeError for a missing service, an unknown level or an invalid path.
 */
export declare function createLogger({ service, level, redact, write }: LoggerOptions): Logger;
type HeaderSource = {
    headers: {
        get(name: string): string | null;
    };
} | {
    headers: Readonly<Record<string, string | string[] | undefined>>;
};
/**
 * The caller's `x-request-id` when it is a plain 8–128 character token (letters, digits, `.`, `_`, `-`), otherwise a
 * new UUID. Takes a web Request or a Node IncomingMessage. Bind it with `log.child({ requestId })`.
 */
export declare function requestId(request: HeaderSource): string;
