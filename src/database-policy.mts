type RecordValue = Record<string, unknown>;

function object(value: unknown): value is RecordValue {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

// The canonical default engine; every other engine needs a reviewed exception or a transition to it.
const defaultEngine = 'postgresql';

function text(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}

/** Inspect canonical declarations only; this does not discover or migrate databases. */
export function inspectDatabasePolicy(policy: unknown, profiles: unknown): string[] {
  if (!object(policy) || !object(profiles)) return ['Missing canonical database policy or profiles.'];
  const errors: string[] = [];
  if (policy.default !== defaultEngine) errors.push(`databasePolicy.default must be ${defaultEngine}.`);
  if (policy.integration !== 'drizzle') errors.push('databasePolicy.integration must be drizzle.');
  if (policy.stateless !== 'none') errors.push('Stateless packages must declare no database.');
  const exceptions = object(policy.exceptions) ? policy.exceptions : {};
  const transitions = object(policy.transitions) ? policy.transitions : {};
  if (!object(policy.exceptions) || !object(policy.transitions)) errors.push('Database exceptions and transitions must be centrally recorded.');

  for (const [name, entry] of Object.entries(exceptions)) {
    if (!object(entry) || !text(entry.engine) || ['none', defaultEngine].includes(entry.engine)
      || !text(entry.purpose) || !['native-platform-binding', 'approved-requirement'].includes(entry.purpose)
      || !text(entry.requirement) || !text(entry.review) || !Array.isArray(entry.profiles)
      || entry.profiles.length === 0 || entry.profiles.some(profile => !text(profile) || !Object.hasOwn(profiles, profile))) {
      errors.push(`Database exception ${name} needs an explicit engine, approved purpose, requirement, review and known profiles.`);
    }
  }
  for (const [name, entry] of Object.entries(transitions)) {
    if (!object(entry) || !text(entry.engine) || ['none', defaultEngine].includes(entry.engine)
      || entry.target !== defaultEngine || !text(entry.profile) || !Object.hasOwn(profiles, entry.profile)
      || !text(entry.reason) || !text(entry.review)) {
      errors.push(`Database transition ${name} must preserve a named current implementation and target ${defaultEngine} with a reason and review.`);
    }
  }
  for (const [name, profile] of Object.entries(profiles)) {
    const database = object(profile) && object(profile.database) ? profile.database : undefined;
    if (!database || !text(database.engine)) {
      errors.push(`profiles.${name}.database must declare ${defaultEngine}, none or a recorded nondefault engine.`);
      continue;
    }
    if (database.engine === defaultEngine || database.engine === 'none') {
      if (database.exception !== undefined || database.transition !== undefined) errors.push(`profiles.${name}.database does not need a nondefault exception or transition.`);
      continue;
    }
    if (text(database.exception) && database.transition === undefined) {
      const entry = exceptions[database.exception];
      if (object(entry) && entry.engine === database.engine && Array.isArray(entry.profiles) && entry.profiles.includes(name)) continue;
    } else if (text(database.transition) && database.exception === undefined) {
      const entry = transitions[database.transition];
      if (object(entry) && entry.engine === database.engine && entry.profile === name && entry.target === defaultEngine) continue;
    }
    errors.push(`profiles.${name}.database: nondefault engine ${database.engine} needs a matching centrally reviewed purpose or ${defaultEngine} transition.`);
  }
  return errors;
}
