import type { z } from 'zod';
type Environment = Readonly<Record<string, string | undefined>>;
export type ConfigError = Error & {
    code: 'CONFIG_INVALID';
    keys: string[];
};
/**
 * The value of `name`, or the trimmed contents of the file `${name}_FILE` names; undefined when neither is set.
 * Setting both, or naming a file that cannot be read, throws a ConfigError with `code: 'CONFIG_INVALID'`.
 */
export declare function readEnvironment(name: string, env?: Environment): string | undefined;
/** A required secret read through readEnvironment, refused when unset or shorter than `minimumLength` (default 32). */
export declare function readSecret(name: string, { minimumLength, env }?: {
    minimumLength?: number;
    env?: Environment;
}): string;
/**
 * Reads every key of `schema` through readEnvironment (unset keys are omitted, so `.default()` applies) and parses
 * the strings with zod; use `z.coerce` or `z.stringbool()` for non-string settings. Every problem is reported in one
 * ConfigError whose `keys` lists the failing keys. Any configured value of four or more characters is removed from
 * the message, including from an app's own refine messages; the ZodError is not attached.
 */
export declare function loadConfig<Schema extends z.ZodObject>(schema: Schema, env?: Environment): z.output<Schema>;
export {};
