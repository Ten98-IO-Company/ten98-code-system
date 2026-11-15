export type LogLevel = 'debug' | 'info' | 'warn' | 'error';
export type LogFields = Readonly<Record<string, unknown>>;
export interface Logger {
    debug(message: string, fields?: LogFields): void;
    info(message: string, fields?: LogFields): void;
    warn(message: string, fields?: LogFields): void;
    error(message: string, fields?: LogFields): void;
    /** A logger that adds these fields to every line; fields given to a call override them. */
    child(fields: LogFields): Logger;
}
export interface LoggerOptions {
    service: string;
    /** The least severe level written; defaults to 'info'. */
    level?: LogLevel;
    /** Receives each line, newline included; defaults to standard output. */
    write?: (line: string) => void;
    /**
     * Field names this app knows to be harmless although they contain a secret fragment, such as `rankKeyword`. Compared
     * like every name (lowercased, separators removed). A name that is itself a secret, such as `password` or `apiKey`,
     * is refused with a TypeError: nothing an app passes can remove a secret fragment.
     */
    allow?: readonly string[];
}
/**
 * A logger never throws: a field getter that throws, an unserialisable value or a failing `write` costs at most that
 * line's fields (or the line), never the caller's request. A message whose `toString` throws writes no line.
 */
export declare function createLogger({ service, level, write, allow }: LoggerOptions): Logger;
/** The caller's x-request-id when it is a plain 8–128 character token, otherwise a new UUID. */
export declare function requestId(request: Request): string;
