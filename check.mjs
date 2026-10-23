import { inspectDatabasePolicy } from './database-policy.mjs';
import { readFileSync, writeFileSync, realpathSync, existsSync, readdirSync, lstatSync } from 'node:fs';
import { resolve, relative, basename } from 'node:path';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
const contract = JSON.parse(readFileSync(new URL('./architecture.json', import.meta.url), 'utf8'));
// Caught values are unknown; Error instances carry the message the CLI reports.
function messageOf(error) {
    return error instanceof Error ? error.message : String(error);
}
export function checkRuntimeVersion(version = process.versions.node) {
    // Support the canonical bounded Node-major contract without adding a semver dependency.
    const range = /^>=(\d+)\.(\d+)\.(\d+) <(\d+)$/u.exec(contract.node);
    const actual = typeof version === 'string' ? /^(\d+)\.(\d+)\.(\d+)$/u.exec(version) : null;
    if (!range || !actual)
        return [`Cannot validate running Node ${version} against canonical range ${contract.node}.`];
    const [major, minor, patch] = actual.slice(1).map(Number);
    const [minimumMajor, minimumMinor, minimumPatch, maximumMajor] = range.slice(1).map(Number);
    const atLeastMinimum = major > minimumMajor || major === minimumMajor
        && (minor > minimumMinor || minor === minimumMinor && patch >= minimumPatch);
    return atLeastMinimum && major < maximumMajor ? [] : [`Running Node ${version} is outside canonical range ${contract.node}. Use the approved Node runtime.`];
}
// Gate commands use a small, fail-closed shell form, not a search for command text.
// Requiring an inline && chain avoids package-manager differences in pre-script hooks.
function hasRequiredGate(script) {
    if (typeof script !== 'string' || /[|;#\r\n]/u.test(script) || script.replaceAll('&&', '').includes('&'))
        return false;
    const commands = script.split('&&').map(command => command.trim());
    return commands.length > 1 && commands.every(Boolean)
        && /^(?:npm\s+run|pnpm(?:\s+run)?)\s+check:architecture$/u.test(commands[0]);
}
// A floored package's pinned archive must exist, and only one release of it may be vendored.
// Lockfile integrity is left to the package manager's frozen install, which rejects a mismatched archive.
export function checkVendoredFloors(directory, manifest) {
    const errors = [];
    for (const name of Object.keys(contract.sharedPackageFloors ?? {})) {
        const spec = manifest.dependencies?.[name] ?? manifest.devDependencies?.[name];
        if (typeof spec !== 'string' || !spec.startsWith('file:vendor/'))
            continue;
        const prefix = `${name.replace(/^@/u, '').replace('/', '-')}-`;
        if (!existsSync(resolve(directory, spec.slice('file:'.length))))
            errors.push(`${name}: pinned archive ${spec.slice('file:'.length)} is missing.`);
        const vendored = existsSync(resolve(directory, 'vendor')) ? readdirSync(resolve(directory, 'vendor')).filter(file => file.startsWith(prefix) && file.endsWith('.tgz')) : [];
        if (vendored.length > 1)
            errors.push(`${name}: vendor holds ${vendored.length} archives (${vendored.join(', ')}); keep only the pinned release.`);
    }
    return errors;
}
// This checks declared dependencies and build gates, not application security or behavior.
export function checkManifest(manifest) {
    const profileName = String(manifest.name);
    const errors = inspectDatabasePolicy(contract.databasePolicy, contract.profiles), profile = Object.hasOwn(contract.profiles, profileName) ? contract.profiles[profileName] : undefined;
    if (!profile)
        return [`Unknown architecture profile: ${manifest.name ?? '(missing name)'}. Update architecture.json after review.`];
    const shared = { ...contract.sharedVersions, ...contract.sharedPackages };
    const floors = contract.sharedPackageFloors ?? {};
    const same = (actual, expected, label) => { if (actual !== expected)
        errors.push(`${label}: expected ${expected}, found ${actual ?? '(missing)'}.`); };
    // A floored package is pinned by the app to one vendored release archive at or above the canonical floor.
    const atLeastFloor = (name, actual, label) => {
        const archive = name.replace(/^@/u, '').replace('/', '-');
        const version = typeof actual === 'string' ? new RegExp(`^file:vendor/${archive}-(\\d+)\\.(\\d+)\\.(\\d+)\\.tgz$`, 'u').exec(actual) : null;
        const floor = /^(\d+)\.(\d+)\.(\d+)$/u.exec(floors[name] ?? '');
        if (!version || !floor) {
            errors.push(`${label}: expected file:vendor/${archive}-<version>.tgz at or above ${floors[name]}, found ${actual ?? '(missing)'}.`);
            return;
        }
        const [major, minor, patch] = version.slice(1).map(Number), [floorMajor, floorMinor, floorPatch] = floor.slice(1).map(Number);
        const below = major - floorMajor || minor - floorMinor || patch - floorPatch;
        if (below < 0)
            errors.push(`${label}: ${version.slice(1).join('.')} is below the supported floor ${floors[name]}.`);
    };
    const pinned = (name, actual, expected, label) => {
        if (Object.hasOwn(floors, name))
            atLeastFloor(name, actual, label);
        else
            same(actual, expected, label);
    };
    same(manifest.engines?.node, contract.node, 'engines.node');
    same(manifest.type, 'module', 'type');
    const expected = { ...profile.dependencies, ...Object.fromEntries(profile.sharedDependencies.map(name => [name, shared[name]])) };
    for (const [name, version] of Object.entries(expected))
        pinned(name, manifest.dependencies?.[name], version, `dependencies.${name}`);
    for (const name of Object.keys(manifest.dependencies ?? {}))
        if (!Object.hasOwn(expected, name))
            errors.push(`Unapproved runtime dependency ${name}. Update architecture.json after review.`);
    for (const name of Object.keys(manifest.optionalDependencies ?? {}))
        errors.push(`Unapproved optional runtime dependency ${name}. Update architecture.json after review.`);
    const expectedDev = { ...profile.devDependencies, ...Object.fromEntries(profile.sharedDevDependencies.map(name => [name, shared[name]])) };
    for (const [name, version] of Object.entries(expectedDev))
        pinned(name, manifest.devDependencies?.[name], version, `devDependencies.${name}`);
    for (const name of Object.keys(manifest.devDependencies ?? {}))
        if (!Object.hasOwn(expectedDev, name))
            errors.push(`Unapproved development dependency ${name}. Update architecture.json after review.`);
    for (const [name, version] of Object.entries(profile.peerDependencies))
        same(manifest.peerDependencies?.[name], version, `peerDependencies.${name}`);
    for (const name of Object.keys(manifest.peerDependencies ?? {}))
        if (!Object.hasOwn(profile.peerDependencies, name))
            errors.push(`Unapproved peer dependency ${name}. Update architecture.json after review.`);
    // These manifests consume accepted lockfiles/archives without graph substitutions.
    for (const [name, value] of [
        ['overrides', manifest.overrides], ['resolutions', manifest.resolutions],
        ['pnpm.overrides', manifest.pnpm?.overrides], ['pnpm.patchedDependencies', manifest.pnpm?.patchedDependencies],
        ['pnpm.packageExtensions', manifest.pnpm?.packageExtensions],
        ['bundledDependencies', manifest.bundledDependencies], ['bundleDependencies', manifest.bundleDependencies],
    ]) {
        if (value != null && value !== false && (typeof value !== 'object' || Object.keys(value).length)) {
            errors.push(`Unapproved ${name}. Resolve dependency changes in architecture.json and the accepted package release instead.`);
        }
    }
    const command = manifest.name === '@ten98/runtime' ? 'node check.mjs .' : 'node node_modules/@ten98/runtime/check.mjs .';
    if (manifest.scripts?.['check:architecture'] !== command)
        errors.push(`scripts.check:architecture must run the shared check.mjs: ${command}`);
    for (const name of profile.checkScripts) {
        if (!manifest.scripts?.[name])
            errors.push(`Missing scripts.${name}.`);
        else if (!hasRequiredGate(manifest.scripts[name]))
            errors.push(`scripts.${name} must run check:architecture first in an inline && chain, without optional hooks, backgrounding or failure-masking shell operators.`);
    }
    return errors;
}
// Pure inspection is testable independently; CLI evidence always comes from the installed compiler below.
export function inspectSourcePolicy(directory, policy, compilation) {
    const errors = [];
    if (policy.default !== 'typescript')
        return ['Unknown source language policy.'];
    const nameOf = (file) => relative(directory, resolve(directory, file)).replaceAll('\\', '/');
    for (const project of compilation.projects ?? [compilation]) {
        const options = project.compilerOptions ?? {};
        if (options.strict !== true)
            errors.push('The source compiler must enable strict.');
        if (options.noCheck === true)
            errors.push('The source compiler must not disable checking with noCheck.');
        for (const name of ['noImplicitAny', 'noImplicitThis', 'strictNullChecks', 'strictFunctionTypes', 'strictBindCallApply', 'strictPropertyInitialization', 'strictBuiltinIteratorReturn', 'alwaysStrict', 'useUnknownInCatchVariables']) {
            if (options[name] === false)
                errors.push(`The source compiler must not disable ${name}.`);
        }
        // Node 24 strips types from tests and scripts without checking them; erasable syntax keeps the run and checked programs identical.
        const stripped = (project.files ?? []).map(nameOf).find(name => /^(?:tests|scripts)\//u.test(name) && /\.[cm]?ts$/u.test(name) && !/\.d\.[cm]?ts$/u.test(name));
        if (stripped && options.erasableSyntaxOnly !== true)
            errors.push(`${stripped}: a compiler project covering tests or scripts must enable erasableSyntaxOnly.`);
    }
    const checked = new Set(compilation.files.map(file => resolve(directory, file)));
    const legacy = new Set(policy.legacyJavaScript), files = [];
    const artifacts = new Set(policy.artifactDirectories ?? []), tests = new Set(policy.testDirectories ?? []);
    const native = policy.nativeFiles ?? {};
    // Inventory the whole app, excluding explicit non-source artifacts and native test boundaries.
    // Otherwise a new api/lib directory could silently bypass the production-root policy.
    const classify = (folder) => {
        for (const entry of readdirSync(folder, { withFileTypes: true })) {
            const file = resolve(folder, entry.name), name = relative(directory, file).replaceAll('\\', '/');
            if (artifacts.has(name) || tests.has(name) || policy.roots.includes(name))
                continue;
            if (entry.isSymbolicLink())
                errors.push(`Source links need explicit review: ${name}`);
            else if (entry.isDirectory())
                classify(file);
            else if (/\.(?:[cm]?[jt]sx?|ps1|cmd|bat)$/iu.test(name) && !Object.hasOwn(native, name)) {
                errors.push(`${name}: code outside declared production roots needs a canonical source classification.`);
            }
        }
    };
    classify(resolve(directory));
    const walk = (folder) => {
        if (!existsSync(folder)) {
            errors.push(`Required source root missing: ${relative(directory, folder)}`);
            return;
        }
        if (lstatSync(folder).isSymbolicLink()) {
            errors.push(`Source links need explicit review: ${relative(directory, folder)}`);
            return;
        }
        for (const entry of readdirSync(folder, { withFileTypes: true })) {
            const file = resolve(folder, entry.name);
            // Nested artifact directories such as tests/fixtures hold checker inputs and recorded payloads, not authored source.
            if (entry.isDirectory() && artifacts.has(nameOf(file)))
                continue;
            if (entry.isDirectory())
                walk(file);
            else if (entry.isSymbolicLink())
                errors.push(`Source links need explicit review: ${relative(directory, file)}`);
            else if (entry.isFile())
                files.push(file);
        }
    };
    for (const root of policy.roots)
        walk(resolve(directory, root));
    // The legacy list only shrinks: entries for removed, converted or relocated files must be deleted.
    const found = new Set(files.map(nameOf).filter(name => /\.(?:[cm]?js|jsx)$/iu.test(name)));
    for (const name of legacy)
        if (!found.has(name))
            errors.push(`${name}: stale legacyJavaScript entry; no such authored JavaScript under a source root.`);
    for (const file of files) {
        const name = nameOf(file);
        if (found.has(name) && !legacy.has(name))
            errors.push(`${name}: new authored JavaScript is not approved; use checked TypeScript.`);
        // Roots skip the whole-app inventory above, so native scripts inside them need the same explicit classification.
        if (/\.(?:ps1|cmd|bat)$/iu.test(name) && !Object.hasOwn(native, name))
            errors.push(`${name}: code outside declared production roots needs a canonical source classification.`);
        if (!/\.(?:[cm]?ts|tsx)$/iu.test(name))
            continue;
        if (!checked.has(file))
            errors.push(`${name}: TypeScript is absent from the configured compiler program.`);
        const source = readFileSync(file, 'utf8'), generated = policy.generated[name];
        if (generated && !source.includes(generated))
            errors.push(`${name}: reviewed generated-file provenance marker is missing.`);
        // The split spelling keeps this checker's own source from matching the directive it searches for.
        if (/@ts-no[c]heck\b/iu.test(source) && !generated)
            errors.push(`${name}: authored TypeScript must not disable checking with @ts-no${'check'}.`);
    }
    return errors;
}
export function checkSourceLanguage(directory, name) {
    const policy = contract.profiles[name]?.sourceLanguage;
    if (!policy)
        return [];
    directory = resolve(directory);
    const compiler = resolve(directory, 'node_modules/typescript/bin/tsc');
    const installed = JSON.parse(readFileSync(resolve(directory, 'node_modules/typescript/package.json'), 'utf8'));
    if (installed.version !== contract.sharedVersions.typescript)
        return ['Installed TypeScript does not match the canonical version.'];
    const deadline = Date.now() + 90_000;
    const run = (project, args) => {
        if (Date.now() >= deadline)
            throw Error('TypeScript source checking exceeded its 90-second budget.');
        const result = spawnSync(process.execPath, [compiler, '--project', project, ...args], {
            cwd: directory, encoding: 'utf8', timeout: Math.min(30_000, deadline - Date.now()), maxBuffer: 8 * 1024 * 1024, windowsHide: true,
        });
        if (result.error || result.status !== 0)
            throw Error(`TypeScript ${project} ${args.join(' ')} failed: ${result.error?.message ?? result.stdout + result.stderr}`);
        return result.stdout;
    };
    const projects = [], files = [];
    // Resolve the actual import closure as well as configured roots; callers cannot submit a synthetic program.
    for (const project of policy.compilerProjects) {
        const program = run(project, ['--listFilesOnly', '--pretty', 'false']).trim().split(/\r?\n/u).filter(Boolean);
        projects.push({ ...JSON.parse(run(project, ['--showConfig'])), files: program });
        files.push(...program);
    }
    const errors = inspectSourcePolicy(directory, policy, { projects, files });
    if (!errors.length)
        for (const project of policy.compilerProjects)
            run(project, ['--noEmit', '--pretty', 'false']);
    return errors;
}
const CREATE_ELEMENT = new Set(['createElement', 'jsx', 'jsxs', '_jsx']);
const UI_SOURCE = /^@ten98\/ui(?:\/app)?$/u;
// Counts presentation violations per file and rule. Dynamic JSX spreads are a known limit: only
// object-literal spreads are inspected, so a spread variable can still carry className/style.
function presentationCounts(directory, policy, parseAst) {
    const counts = {}, errors = [], files = [];
    const add = (name, rule) => { counts[name] ??= {}; counts[name][rule] = (counts[name][rule] ?? 0) + 1; };
    const rootOf = (node) => node.type === 'JSXMemberExpression' ? rootOf(node.object) : node.name;
    const walk = (folder) => {
        if (!existsSync(folder)) {
            errors.push(`Required presentation root missing: ${relative(directory, folder)}`);
            return;
        }
        for (const entry of readdirSync(folder, { withFileTypes: true })) {
            const file = resolve(folder, entry.name);
            if (entry.isDirectory())
                walk(file);
            else if (entry.isFile() && /\.[jt]sx$/u.test(entry.name))
                files.push(file);
        }
    };
    for (const root of policy.roots)
        walk(resolve(directory, root));
    for (const file of files) {
        const name = relative(directory, file).replaceAll('\\', '/');
        let program;
        try {
            program = parseAst(readFileSync(file, 'utf8'), { lang: name.endsWith('tsx') ? 'tsx' : 'jsx' });
        }
        catch (error) {
            errors.push(`${name}: cannot parse for the presentation check: ${messageOf(error)}`);
            continue;
        }
        const uiNamespaces = new Set();
        for (const node of program.body) {
            if (node.type !== 'ImportDeclaration')
                continue;
            const source = node.source.value;
            if (/\.(?:css|scss|sass|less)$/u.test(source) && !source.startsWith('@ten98/ui'))
                add(name, 'stylesheet');
            if (UI_SOURCE.test(source))
                for (const specifier of node.specifiers)
                    if (specifier.type !== 'ImportSpecifier')
                        uiNamespaces.add(specifier.local.name);
        }
        const visit = (node) => {
            if (Array.isArray(node))
                return node.forEach(visit);
            if (!node || typeof node.type !== 'string')
                return;
            if (node.type === 'JSXOpeningElement') {
                const tag = node.name;
                if (tag.type === 'JSXIdentifier' ? /^[a-z]/u.test(tag.name) : tag.type === 'JSXNamespacedName' || !uiNamespaces.has(rootOf(tag)))
                    add(name, 'element');
            }
            else if (node.type === 'JSXAttribute') {
                if (node.name.name === 'className' || node.name.name === 'style')
                    add(name, 'styling');
                if (node.name.name === 'dangerouslySetInnerHTML')
                    add(name, 'inner-html');
            }
            else if (node.type === 'JSXSpreadAttribute') {
                if (node.argument.type === 'ObjectExpression' && node.argument.properties.some((property) => ['className', 'style'].includes(property.key?.name ?? property.key?.value)))
                    add(name, 'styling');
            }
            else if (node.type === 'CallExpression' && typeof node.arguments[0]?.value === 'string' && node.arguments[0].type === 'Literal') {
                const callee = node.callee;
                if (callee.type === 'Identifier' ? CREATE_ELEMENT.has(callee.name) : callee.type === 'MemberExpression' && callee.object.name === 'React' && callee.property.name === 'createElement')
                    add(name, 'create-element');
            }
            for (const value of Object.values(node))
                if (value && typeof value === 'object')
                    visit(value);
        };
        visit(program.body);
    }
    return { counts, errors };
}
// rolldown arrives through the pinned vite; strict layouts (pnpm) expose it only from vite's own scope.
function resolveParseAst(directory) {
    const consumer = createRequire(resolve(directory, 'package.json'));
    // The resolved module is untrusted runtime data; only its parseAst export is used.
    const loaders = [
        () => consumer('rolldown/parseAst'),
        () => createRequire(consumer.resolve('vite/package.json'))('rolldown/parseAst'),
    ];
    for (const load of loaders) {
        try {
            return load().parseAst;
        }
        catch { /* try the next scope */ }
    }
    return undefined;
}
// Ratchet: a file may not exceed its baseline count for any rule; unlisted files and rules allow 0.
// parseAst is injectable for tests; the CLI always resolves it from the consumer and fails closed.
export function checkPresentation(directory, name, { parseAst = resolveParseAst(directory) } = {}) {
    const policy = contract.profiles[name]?.presentation;
    if (!policy)
        return [];
    if (typeof parseAst !== 'function')
        return ['Cannot resolve rolldown/parseAst from the consumer; install the pinned build tooling to check presentation ownership.'];
    directory = resolve(directory);
    const { counts, errors } = presentationCounts(directory, policy, parseAst);
    const file = policy.baseline && resolve(directory, policy.baseline);
    const baseline = file && existsSync(file) ? JSON.parse(readFileSync(file, 'utf8')) : {};
    for (const [path, rules] of Object.entries(counts)) {
        for (const [rule, found] of Object.entries(rules)) {
            const allowed = baseline[path]?.[rule] ?? 0;
            if (found > allowed)
                errors.push(`${path}: ${rule} ${found} exceeds baseline ${allowed} (presentation is owned by ${policy.owner}).`);
        }
    }
    return errors;
}
// Only lowers or removes entries: any rise or new violation refuses and reports the errors instead.
// A missing baseline is recorded once from current counts; that first file is reviewed in the app's diff.
export function updatePresentationBaseline(directory, name, options = {}) {
    const policy = contract.profiles[name]?.presentation;
    if (!policy?.baseline)
        return [];
    const parseAst = options.parseAst ?? resolveParseAst(directory);
    if (existsSync(resolve(directory, policy.baseline)) || typeof parseAst !== 'function') {
        const errors = checkPresentation(directory, name, { parseAst });
        if (errors.length)
            return errors;
    }
    // A missing parser always makes checkPresentation return an error above, so a function is present here.
    const { counts, errors } = presentationCounts(resolve(directory), policy, parseAst);
    if (errors.length)
        return errors;
    writeFileSync(resolve(directory, policy.baseline), `${JSON.stringify(Object.fromEntries(Object.entries(counts).sort(([a], [b]) => a < b ? -1 : 1)), null, 2)}\n`);
    return [];
}
// Release mode is separate from ordinary architecture checks and reads committed evidence.
export function collectReleaseIdentity(directory, { tag = '', commit = '', tagObject, archive, archiveSha256, event } = {}) {
    directory = resolve(directory);
    const sha = /^[0-9a-f]{40}$/u;
    if (!/^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/u.test(tag))
        throw Error('Release tag must use normal vX.Y.Z SemVer.');
    if (!sha.test(commit) || tagObject !== undefined && !sha.test(tagObject))
        throw Error('Expected commit and optional tag object must be full Git SHA-1 IDs from independent evidence.');
    const run = (command, args, input) => {
        const result = spawnSync(command, args, { cwd: directory, input, encoding: 'utf8', timeout: 30_000, maxBuffer: 8 * 1024 * 1024, windowsHide: true });
        if (result.error || result.status !== 0)
            throw Error(`${command} evidence collection failed: ${result.error?.message ?? result.stderr}`);
        return result.stdout.trim();
    };
    const git = (...args) => run('git', ['--no-replace-objects', ...args]);
    const ref = `refs/tags/${tag}`;
    if (git('cat-file', '-t', ref) !== 'tag')
        throw Error('Release requires an annotated Git tag.');
    const actualObject = git('rev-parse', '--verify', ref);
    const actualCommit = git('rev-parse', '--verify', `${ref}^{commit}`);
    if (actualCommit !== commit || git('rev-parse', '--verify', 'HEAD') !== commit)
        throw Error('Release tag or checkout differs from the independently qualified commit.');
    if (tagObject !== undefined && actualObject !== tagObject)
        throw Error('Release tag moved or its annotation was replaced.');
    const annotation = git('cat-file', 'tag', actualObject).split('\n\n')[0];
    if (!annotation.split('\n').includes(`tag ${tag}`))
        throw Error('Annotated tag name differs from its release ref.');
    if (event !== undefined) {
        const pushed = JSON.parse(readFileSync(resolve(event), 'utf8'));
        if (pushed.ref !== ref || pushed.created !== true || pushed.deleted !== false || pushed.forced !== false || !/^0{40}$/u.test(pushed.before ?? '') || ![actualCommit, actualObject].includes(pushed.after ?? '')) {
            throw Error('Release push must create a new tag; moved, deleted or mismatched tag events are rejected.');
        }
    }
    const manifest = JSON.parse(git('show', `${commit}:package.json`));
    const version = tag.slice(1), name = manifest.name;
    if (typeof name !== 'string' || !/^(?:@[a-z0-9._-]+\/)?[a-z0-9._-]+$/u.test(name) || manifest.version !== version)
        throw Error('Committed package name/version does not match the release tag.');
    const tracked = git('ls-tree', '--name-only', commit, '--', 'package-lock.json', 'pnpm-lock.yaml').split('\n').filter(Boolean);
    if (tracked.length !== 1)
        throw Error('Release commit must track exactly one lockfile: package-lock.json or pnpm-lock.yaml.');
    // npm records the root name and version in its lock; pnpm's lock records neither, so package.json alone carries them.
    if (tracked[0] === 'package-lock.json') {
        const lock = JSON.parse(git('show', `${commit}:package-lock.json`));
        if (lock.name !== name || lock.version !== version || lock.packages?.['']?.name !== name || lock.packages[''].version !== version)
            throw Error('Committed root lock name/version differs from the package.');
    }
    else if (!/^importers:\r?\n(?:\r?\n)? {2}\.:\r?$/mu.test(git('show', `${commit}:pnpm-lock.yaml`))) {
        throw Error('Committed pnpm lock has no root importer.');
    }
    const evidence = { name, version, tag, commit: actualCommit, tagObject: actualObject, tagHistory: event ? 'new-tag push event' : tagObject ? 'independent tag-object receipt' : 'unverified; no prior tag-object receipt or push event' };
    if (archiveSha256 !== undefined && (!archive || !/^[0-9a-f]{64}$/u.test(archiveSha256)))
        throw Error('Archive digest comparison needs an archive and a full SHA256.');
    if (archive !== undefined) {
        archive = resolve(archive);
        const filename = `${name.replace(/^@/u, '').replaceAll('/', '-')}-${version}.tgz`;
        if (basename(archive) !== filename)
            throw Error('Archive filename differs from the package release identity.');
        const bytes = readFileSync(archive);
        const entries = run('tar', ['-tzf', '-'], bytes).split(/\r?\n/u);
        if (entries.filter(entry => entry === 'package/package.json').length !== 1)
            throw Error('Archive must contain exactly one package/package.json.');
        const packed = JSON.parse(run('tar', ['-xOzf', '-', 'package/package.json'], bytes));
        if (packed.name !== name || packed.version !== version)
            throw Error('Actual packed package identity differs from the tagged package.');
        const digest = createHash('sha256').update(bytes).digest('hex');
        if (archiveSha256 !== undefined && digest !== archiveSha256)
            throw Error('Archive bytes differ from the independently recorded SHA256.');
        evidence.archive = { filename, bytes: bytes.length, sha256: digest, priorBytesVerified: archiveSha256 !== undefined };
    }
    return evidence;
}
function releaseArguments(args) {
    const directory = args.shift();
    if (!directory || directory.startsWith('--') || args.length % 2)
        throw Error('Usage: --release DIRECTORY --tag vX.Y.Z --commit SHA [--tag-object SHA] [--event FILE] [--archive FILE] [--archive-sha256 SHA]');
    const keys = { '--tag': 'tag', '--commit': 'commit', '--tag-object': 'tagObject', '--event': 'event', '--archive': 'archive', '--archive-sha256': 'archiveSha256' }, options = {};
    for (let index = 0; index < args.length; index += 2) {
        const key = keys[args[index]];
        if (!key || Object.hasOwn(options, key))
            throw Error(`Unknown or duplicate release option: ${args[index]}`);
        options[key] = args[index + 1];
    }
    return collectReleaseIdentity(directory, options);
}
if (process.argv[1] && existsSync(process.argv[1]) && realpathSync(resolve(process.argv[1])) === realpathSync(fileURLToPath(import.meta.url))) {
    const runtimeErrors = checkRuntimeVersion();
    for (const error of runtimeErrors)
        console.error(error);
    let failures = runtimeErrors.length;
    const flag = '--update-presentation-baseline', args = process.argv.slice(2), release = args[0] === '--release', update = !release && args.includes(flag);
    const directories = args.filter(arg => arg !== flag);
    if (!failures && release) {
        try {
            console.log(JSON.stringify(releaseArguments(args.slice(1)), null, 2));
        }
        catch (error) {
            failures++;
            console.error(messageOf(error));
        }
    }
    for (const directory of runtimeErrors.length || release ? [] : directories.length ? directories : ['.']) {
        try {
            const manifest = JSON.parse(readFileSync(resolve(directory, 'package.json'), 'utf8'));
            const errors = checkManifest(manifest);
            if (!errors.length)
                errors.push(...checkVendoredFloors(directory, manifest));
            if (!errors.length)
                errors.push(...checkSourceLanguage(directory, String(manifest.name)));
            if (!errors.length)
                errors.push(...(update ? updatePresentationBaseline : checkPresentation)(directory, String(manifest.name)));
            for (const error of errors)
                console.error(`${directory}: ${error}`);
            failures += errors.length;
            if (!errors.length)
                console.log(`${directory}: architecture declarations match ${manifest.name}.`);
        }
        catch (error) {
            failures++;
            console.error(`${directory}: ${messageOf(error)}`);
        }
    }
    if (failures)
        process.exitCode = 1;
}
