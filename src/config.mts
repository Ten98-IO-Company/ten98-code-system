// Environment configuration: a value comes from NAME, or from the file NAME_FILE names (a Docker or Compose secret),
// never both. Extracted from discover's and books' `environmentValue` and `secret`; each app keeps its own getConfig.
// Only `import type` from zod, so readEnvironment and readSecret run without the optional zod peer installed.
import { readFileSync } from 'node:fs';
import type { z } from 'zod';

type Environment = Readonly<Record<string, string | undefined>>;
export type ConfigError = Error & { code: 'CONFIG_INVALID'; keys: string[] };

// Messages name keys and never carry a configured value or a file path, so they are safe to log at start-up.
const configError = (message: string, keys: string[]): ConfigError => Object.assign(new Error(message), { code: 'CONFIG_INVALID' as const, keys });
/**
 * The value of `name`, or the trimmed contents of the file `${name}_FILE` names; undefined when neither is set.
 * As in discover and books, the checks are truthy: an empty `${name}_FILE` is unset and an empty `name` never
 * conflicts with a file, but with no file `name` is returned unchanged, untrimmed and `''` included.
 * Setting both, or naming a file that cannot be read, throws a ConfigError with `code: 'CONFIG_INVALID'`.
 */
export function readEnvironment(name: string, env: Environment = process.env): string | undefined {
  const direct = env[name];
  const file = env[`${name}_FILE`];
  if (direct && file) throw configError(`Set only ${name} or ${name}_FILE`, [name]);
  if (!file) return direct;
  try {
    return readFileSync(file, 'utf8').trim();
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    throw configError(`${name}_FILE names a file that cannot be read${code ? ` (${code})` : ''}`, [name]);
  }
}

/** A required secret read through readEnvironment, refused when unset or shorter than `minimumLength` (default 32). */
export function readSecret(name: string, { minimumLength = 32, env = process.env }: { minimumLength?: number; env?: Environment } = {}): string {
  if (!Number.isSafeInteger(minimumLength) || minimumLength < 1) throw new RangeError('readSecret needs a positive integer minimumLength.');
  const value = readEnvironment(name, env);
  if (!value || value.length < minimumLength) throw configError(`${name} must contain at least ${minimumLength} characters`, [name]);
  return value;
}

/**
 * Reads every key of `schema` through readEnvironment and parses the strings with zod. Unset and empty keys are
 * omitted, so `.default()` applies to `X=''` (Compose's `X: ${X:-}` passes empty strings through); use `z.coerce` or `z.stringbool()` for non-string settings. Every problem is reported in one
 * ConfigError whose `keys` lists the failing keys. Any configured value of four or more characters is removed from
 * the message, including from an app's own refine messages; the ZodError is not attached.
 */
export function loadConfig<Schema extends z.ZodObject>(schema: Schema, env: Environment = process.env): z.output<Schema> {
  const input: Record<string, string> = {};
  const problems: { key: string; message: string }[] = [];
  for (const key of Object.keys(schema.shape)) {
    try {
      const value = readEnvironment(key, env);
      if (value) input[key] = value;
    } catch (error) {
      problems.push({ key, message: (error as Error).message });
    }
  }
  const values = Object.values(input).filter(value => value.length >= 4).sort((a, b) => b.length - a.length);
  const redact = (text: string) => values.reduce((result, value) => result.replaceAll(value, '[redacted]'), text);
  const fail = (): never => {
    const keys = [...new Set(problems.map(problem => problem.key))];
    throw configError(`Invalid configuration: ${problems.map(problem => `${problem.key}: ${redact(problem.message)}`).join('; ')}`, keys);
  };
  if (problems.length) fail();
  let result;
  try {
    result = schema.safeParse(input);
  } catch (error) {
    // A throwing transform (new URL, JSON.parse) can put the input in its message or properties; keep only the message.
    problems.push({ key: '(schema)', message: error instanceof Error ? error.message : 'the schema threw' });
    return fail();
  }
  if (result.success) return result.data;
  for (const issue of result.error.issues) problems.push({ key: issue.path.length ? String(issue.path[0]) : '(schema)', message: issue.message });
  return fail();
}
