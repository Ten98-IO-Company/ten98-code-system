function object(value) {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
}
// The canonical default engine; every other engine needs a reviewed exception or a transition to it.
const defaultEngine = 'postgresql';
function text(value) {
    return typeof value === 'string' && value.trim().length > 0;
}
const list = (value) => Array.isArray(value) && value.length > 0 && value.every(text) ? value : undefined;
/**
 * Inspect canonical declarations only; this does not discover or migrate databases. `exceptions` and `transitions` are
 * the declaration's general lists; entries for rule `database.engine` name the engine in `items`.
 */
export function inspectDatabasePolicy(policy, profiles, exceptions = {}, transitions = {}) {
    if (!object(policy) || !object(profiles) || !object(exceptions) || !object(transitions))
        return ['Missing canonical database policy, profiles, exceptions or transitions.'];
    const errors = [];
    if (policy.default !== defaultEngine)
        errors.push(`databasePolicy.default must be ${defaultEngine}.`);
    if (policy.integration !== 'drizzle')
        errors.push('databasePolicy.integration must be drizzle.');
    if (policy.stateless !== 'none')
        errors.push('Stateless packages must declare no database.');
    if (policy.driver !== 'pg')
        errors.push('databasePolicy.driver must be pg.');
    if (!text(policy.postgresql) || !/^\d+$/u.test(policy.postgresql))
        errors.push('databasePolicy.postgresql must name the PostgreSQL major version.');
    if (!list(policy.otherDrivers) || list(policy.otherDrivers)?.includes('pg'))
        errors.push('databasePolicy.otherDrivers must list the database drivers apps may not add beside pg.');
    const engineOf = (entry) => object(entry) && entry.rule === 'database.engine' && list(entry.items)?.length === 1 ? entry.items[0] : undefined;
    for (const [name, entry] of Object.entries(exceptions)) {
        if (!object(entry) || entry.rule !== 'database.engine')
            continue;
        const engine = engineOf(entry);
        if (!engine || ['none', defaultEngine].includes(engine) || typeof entry.purpose !== 'string' || !['native-platform-binding', 'approved-requirement'].includes(entry.purpose)) {
            errors.push(`Database exception ${name} needs exactly one nondefault engine in items and an approved purpose.`);
        }
    }
    for (const [name, entry] of Object.entries(transitions)) {
        if (!object(entry) || entry.rule !== 'database.engine')
            continue;
        const engine = engineOf(entry);
        if (!engine || ['none', defaultEngine].includes(engine))
            errors.push(`Database transition ${name} must name the one current nondefault engine it moves to ${defaultEngine}.`);
    }
    for (const [name, profile] of Object.entries(profiles)) {
        const database = object(profile) && object(profile.database) ? profile.database : undefined;
        if (!database || !text(database.engine)) {
            errors.push(`profiles.${name}.database must declare ${defaultEngine}, none or a recorded nondefault engine.`);
            continue;
        }
        if (database.engine === defaultEngine || database.engine === 'none') {
            if (database.exception !== undefined || database.transition !== undefined)
                errors.push(`profiles.${name}.database does not need a nondefault exception or transition.`);
            continue;
        }
        if (text(database.exception) && database.transition === undefined) {
            const entry = exceptions[database.exception];
            if (object(entry) && engineOf(entry) === database.engine && list(entry.profiles)?.includes(name))
                continue;
        }
        else if (text(database.transition) && database.exception === undefined) {
            const entry = transitions[database.transition];
            if (object(entry) && engineOf(entry) === database.engine && entry.profile === name)
                continue;
        }
        errors.push(`profiles.${name}.database: nondefault engine ${database.engine} needs a matching centrally reviewed purpose or ${defaultEngine} transition.`);
    }
    return errors;
}
