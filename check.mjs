import { readFileSync, realpathSync, existsSync, readdirSync, lstatSync } from 'node:fs';
import { resolve, relative, basename } from 'node:path';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const contract = JSON.parse(readFileSync(new URL('./architecture.json', import.meta.url), 'utf8'));

export function checkRuntimeVersion(version = process.versions.node) {
  // Support the canonical bounded Node-major contract without adding a semver dependency.
  const range = /^>=(\d+)\.(\d+)\.(\d+) <(\d+)$/u.exec(contract.node);
  const actual = typeof version === 'string' ? /^(\d+)\.(\d+)\.(\d+)$/u.exec(version) : null;
  if (!range || !actual) return [`Cannot validate running Node ${version} against canonical range ${contract.node}.`];
  const [major, minor, patch] = actual.slice(1).map(Number);
  const [minimumMajor, minimumMinor, minimumPatch, maximumMajor] = range.slice(1).map(Number);
  const atLeastMinimum = major > minimumMajor || major === minimumMajor
    && (minor > minimumMinor || minor === minimumMinor && patch >= minimumPatch);
  return atLeastMinimum && major < maximumMajor ? [] : [`Running Node ${version} is outside canonical range ${contract.node}. Use the approved Node runtime.`];
}

// Gate commands use a small, fail-closed shell form, not a search for command text.
// Requiring an inline && chain avoids package-manager differences in pre-script hooks.
function hasRequiredGate(script) {
  if (typeof script !== 'string' || /[|;#\r\n]/u.test(script) || script.replaceAll('&&', '').includes('&')) return false;
  const commands = script.split('&&').map(command => command.trim());
  return commands.length > 1 && commands.every(Boolean)
    && /^(?:npm\s+run|pnpm(?:\s+run)?)\s+check:architecture$/u.test(commands[0]);
}

// This checks declared dependencies and build gates, not application security or behavior.
export function checkManifest(manifest) {
  const errors = [], profile = Object.hasOwn(contract.profiles, manifest.name) ? contract.profiles[manifest.name] : undefined;
  if (!profile) return [`Unknown architecture profile: ${manifest.name ?? '(missing name)'}. Update architecture.json after review.`];
  const shared = { ...contract.sharedVersions, ...contract.sharedPackages };
  const same = (actual, expected, label) => { if (actual !== expected) errors.push(`${label}: expected ${expected}, found ${actual ?? '(missing)'}.`); };
  same(manifest.engines?.node, contract.node, 'engines.node');
  same(manifest.type, 'module', 'type');
  const expected = { ...profile.dependencies, ...Object.fromEntries(profile.sharedDependencies.map(name => [name, shared[name]])) };
  for (const [name, version] of Object.entries(expected)) same(manifest.dependencies?.[name], version, `dependencies.${name}`);
  for (const name of Object.keys(manifest.dependencies ?? {})) if (!Object.hasOwn(expected, name)) errors.push(`Unapproved runtime dependency ${name}. Update architecture.json after review.`);
  for (const name of Object.keys(manifest.optionalDependencies ?? {})) errors.push(`Unapproved optional runtime dependency ${name}. Update architecture.json after review.`);
  const expectedDev = { ...profile.devDependencies, ...Object.fromEntries(profile.sharedDevDependencies.map(name => [name, shared[name]])) };
  for (const [name, version] of Object.entries(expectedDev)) same(manifest.devDependencies?.[name], version, `devDependencies.${name}`);
  for (const name of Object.keys(manifest.devDependencies ?? {})) if (!Object.hasOwn(expectedDev, name)) errors.push(`Unapproved development dependency ${name}. Update architecture.json after review.`);
  for (const [name, version] of Object.entries(profile.peerDependencies)) same(manifest.peerDependencies?.[name], version, `peerDependencies.${name}`);
  for (const name of Object.keys(manifest.peerDependencies ?? {})) if (!Object.hasOwn(profile.peerDependencies, name)) errors.push(`Unapproved peer dependency ${name}. Update architecture.json after review.`);
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
  if (manifest.scripts?.['check:architecture'] !== command) errors.push(`scripts.check:architecture must run the shared check.mjs: ${command}`);
  for (const name of profile.checkScripts) {
    if (!manifest.scripts?.[name]) errors.push(`Missing scripts.${name}.`);
    else if (!hasRequiredGate(manifest.scripts[name])) errors.push(`scripts.${name} must run check:architecture first in an inline && chain, without optional hooks, backgrounding or failure-masking shell operators.`);
  }
  return errors;
}

// Pure inspection is testable independently; CLI evidence always comes from the installed compiler below.
export function inspectSourcePolicy(directory, policy, compilation) {
  const errors = [];
  if (policy.default !== 'typescript') return ['Unknown source language policy.'];
  for (const project of compilation.projects ?? [compilation]) {
    const options = project.compilerOptions ?? {};
    if (options.strict !== true) errors.push('The source compiler must enable strict.');
    if (options.noCheck === true) errors.push('The source compiler must not disable checking with noCheck.');
    for (const name of ['noImplicitAny', 'noImplicitThis', 'strictNullChecks', 'strictFunctionTypes', 'strictBindCallApply', 'strictPropertyInitialization', 'strictBuiltinIteratorReturn', 'alwaysStrict', 'useUnknownInCatchVariables']) {
      if (options[name] === false) errors.push(`The source compiler must not disable ${name}.`);
    }
  }
  const checked = new Set(compilation.files.map(file => resolve(directory, file)));
  const legacy = new Set(policy.legacyJavaScript), files = [];
  const artifacts = new Set(policy.artifactDirectories ?? []), tests = new Set(policy.testDirectories ?? []);
  const native = policy.nativeFiles ?? {};
  // Inventory the whole app, excluding explicit non-source artifacts and native test boundaries.
  // Otherwise a new api/lib directory could silently bypass the production-root policy.
  const classify = folder => {
    for (const entry of readdirSync(folder, { withFileTypes: true })) {
      const file = resolve(folder, entry.name), name = relative(directory, file).replaceAll('\\', '/');
      if (artifacts.has(name) || tests.has(name) || policy.roots.includes(name)) continue;
      if (entry.isSymbolicLink()) errors.push(`Source links need explicit review: ${name}`);
      else if (entry.isDirectory()) classify(file);
      else if (/\.(?:[cm]?[jt]sx?|ps1|cmd|bat)$/iu.test(name) && !Object.hasOwn(native, name)) {
        errors.push(`${name}: code outside declared production roots needs a canonical source classification.`);
      }
    }
  };
  classify(resolve(directory));
  const walk = folder => {
    if (!existsSync(folder)) { errors.push(`Required source root missing: ${relative(directory, folder)}`); return; }
    if (lstatSync(folder).isSymbolicLink()) { errors.push(`Source links need explicit review: ${relative(directory, folder)}`); return; }
    for (const entry of readdirSync(folder, { withFileTypes: true })) {
      const file = resolve(folder, entry.name);
      if (entry.isDirectory()) walk(file);
      else if (entry.isSymbolicLink()) errors.push(`Source links need explicit review: ${relative(directory, file)}`);
      else if (entry.isFile()) files.push(file);
    }
  };
  for (const root of policy.roots) walk(resolve(directory, root));
  for (const file of files) {
    const name = relative(directory, file).replaceAll('\\', '/');
    if (/\.(?:[cm]?js|jsx)$/u.test(name) && !legacy.has(name)) errors.push(`${name}: new authored JavaScript is not approved; use checked TypeScript.`);
    if (!/\.(?:[cm]?ts|tsx)$/u.test(name)) continue;
    if (!checked.has(file)) errors.push(`${name}: TypeScript is absent from the configured compiler program.`);
    const source = readFileSync(file, 'utf8'), generated = policy.generated[name];
    if (generated && !source.includes(generated)) errors.push(`${name}: reviewed generated-file provenance marker is missing.`);
    if (/@ts-nocheck\b/iu.test(source) && !generated) errors.push(`${name}: authored TypeScript must not disable checking with @ts-nocheck.`);
  }
  return errors;
}

export function checkSourceLanguage(directory, name) {
  const policy = contract.profiles[name]?.sourceLanguage;
  if (!policy) return [];
  directory = resolve(directory);
  const compiler = resolve(directory, 'node_modules/typescript/bin/tsc');
  const installed = JSON.parse(readFileSync(resolve(directory, 'node_modules/typescript/package.json'), 'utf8'));
  if (installed.version !== contract.sharedVersions.typescript) return ['Installed TypeScript does not match the canonical version.'];
  const deadline = Date.now() + 90_000;
  const run = (project, args) => {
    if (Date.now() >= deadline) throw Error('TypeScript source checking exceeded its 90-second budget.');
    const result = spawnSync(process.execPath, [compiler, '--project', project, ...args], {
      cwd: directory, encoding: 'utf8', timeout: Math.min(30_000, deadline - Date.now()), maxBuffer: 8 * 1024 * 1024, windowsHide: true,
    });
    if (result.error || result.status !== 0) throw Error(`TypeScript ${project} ${args.join(' ')} failed: ${result.error?.message ?? result.stdout + result.stderr}`);
    return result.stdout;
  };
  const projects = [], files = [];
  // Resolve the actual import closure as well as configured roots; callers cannot submit a synthetic program.
  for (const project of policy.compilerProjects) {
    projects.push(JSON.parse(run(project, ['--showConfig'])));
    files.push(...run(project, ['--listFilesOnly', '--pretty', 'false']).trim().split(/\r?\n/u).filter(Boolean));
  }
  const errors = inspectSourcePolicy(directory, policy, { projects, files });
  if (!errors.length) for (const project of policy.compilerProjects) run(project, ['--noEmit', '--pretty', 'false']);
  return errors;
}

// Release mode is separate from ordinary architecture checks and reads committed evidence.
export function collectReleaseIdentity(directory, { tag, commit, tagObject, archive, archiveSha256, event } = {}) {
  directory = resolve(directory);
  const sha = /^[0-9a-f]{40}$/u;
  if (!/^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/u.test(tag ?? '')) throw Error('Release tag must use normal vX.Y.Z SemVer.');
  if (!sha.test(commit ?? '') || tagObject !== undefined && !sha.test(tagObject)) throw Error('Expected commit and optional tag object must be full Git SHA-1 IDs from independent evidence.');
  const run = (command, args, input) => {
    const result = spawnSync(command, args, { cwd: directory, input, encoding: 'utf8', timeout: 30_000, maxBuffer: 8 * 1024 * 1024, windowsHide: true });
    if (result.error || result.status !== 0) throw Error(`${command} evidence collection failed: ${result.error?.message ?? result.stderr}`);
    return result.stdout.trim();
  };
  const git = (...args) => run('git', ['--no-replace-objects', ...args]);
  const ref = `refs/tags/${tag}`;
  if (git('cat-file', '-t', ref) !== 'tag') throw Error('Release requires an annotated Git tag.');
  const actualObject = git('rev-parse', '--verify', ref);
  const actualCommit = git('rev-parse', '--verify', `${ref}^{commit}`);
  if (actualCommit !== commit || git('rev-parse', '--verify', 'HEAD') !== commit) throw Error('Release tag or checkout differs from the independently qualified commit.');
  if (tagObject !== undefined && actualObject !== tagObject) throw Error('Release tag moved or its annotation was replaced.');
  const annotation = git('cat-file', 'tag', actualObject).split('\n\n')[0];
  if (!annotation.split('\n').includes(`tag ${tag}`)) throw Error('Annotated tag name differs from its release ref.');
  if (event !== undefined) {
    const pushed = JSON.parse(readFileSync(resolve(event), 'utf8'));
    if (pushed.ref !== ref || pushed.created !== true || pushed.deleted !== false || pushed.forced !== false || !/^0{40}$/u.test(pushed.before ?? '') || ![actualCommit, actualObject].includes(pushed.after)) {
      throw Error('Release push must create a new tag; moved, deleted or mismatched tag events are rejected.');
    }
  }
  const manifest = JSON.parse(git('show', `${commit}:package.json`));
  const lock = JSON.parse(git('show', `${commit}:package-lock.json`));
  const version = tag.slice(1), name = manifest.name;
  if (typeof name !== 'string' || !/^(?:@[a-z0-9._-]+\/)?[a-z0-9._-]+$/u.test(name) || manifest.version !== version) throw Error('Committed package name/version does not match the release tag.');
  if (lock.name !== name || lock.version !== version || lock.packages?.['']?.name !== name || lock.packages[''].version !== version) throw Error('Committed root lock name/version differs from the package.');
  const evidence = { name, version, tag, commit: actualCommit, tagObject: actualObject, tagHistory: event ? 'new-tag push event' : tagObject ? 'independent tag-object receipt' : 'unverified; no prior tag-object receipt or push event' };
  if (archiveSha256 !== undefined && (!archive || !/^[0-9a-f]{64}$/u.test(archiveSha256))) throw Error('Archive digest comparison needs an archive and a full SHA256.');
  if (archive !== undefined) {
    archive = resolve(archive);
    const filename = `${name.replace(/^@/u, '').replaceAll('/', '-')}-${version}.tgz`;
    if (basename(archive) !== filename) throw Error('Archive filename differs from the package release identity.');
    const bytes = readFileSync(archive);
    const entries = run('tar', ['-tzf', '-'], bytes).split(/\r?\n/u);
    if (entries.filter(entry => entry === 'package/package.json').length !== 1) throw Error('Archive must contain exactly one package/package.json.');
    const packed = JSON.parse(run('tar', ['-xOzf', '-', 'package/package.json'], bytes));
    if (packed.name !== name || packed.version !== version) throw Error('Actual packed package identity differs from the tagged package.');
    const digest = createHash('sha256').update(bytes).digest('hex');
    if (archiveSha256 !== undefined && digest !== archiveSha256) throw Error('Archive bytes differ from the independently recorded SHA256.');
    evidence.archive = { filename, bytes: bytes.length, sha256: digest, priorBytesVerified: archiveSha256 !== undefined };
  }
  return evidence;
}

function releaseArguments(args) {
  const directory = args.shift();
  if (!directory || directory.startsWith('--') || args.length % 2) throw Error('Usage: --release DIRECTORY --tag vX.Y.Z --commit SHA [--tag-object SHA] [--event FILE] [--archive FILE] [--archive-sha256 SHA]');
  const keys = { '--tag': 'tag', '--commit': 'commit', '--tag-object': 'tagObject', '--event': 'event', '--archive': 'archive', '--archive-sha256': 'archiveSha256' }, options = {};
  for (let index = 0; index < args.length; index += 2) {
    const key = keys[args[index]];
    if (!key || Object.hasOwn(options, key)) throw Error(`Unknown or duplicate release option: ${args[index]}`);
    options[key] = args[index + 1];
  }
  return collectReleaseIdentity(directory, options);
}

if (process.argv[1] && existsSync(process.argv[1]) && realpathSync(resolve(process.argv[1])) === realpathSync(fileURLToPath(import.meta.url))) {
  const runtimeErrors = checkRuntimeVersion();
  for (const error of runtimeErrors) console.error(error);
  let failures = runtimeErrors.length;
  const args = process.argv.slice(2), release = args[0] === '--release';
  if (!failures && release) {
    try { console.log(JSON.stringify(releaseArguments(args.slice(1)), null, 2)); }
    catch (error) { failures++; console.error(error.message); }
  }
  for (const directory of runtimeErrors.length || release ? [] : args.length ? args : ['.']) {
    try {
      const manifest = JSON.parse(readFileSync(resolve(directory, 'package.json'), 'utf8'));
      const errors = checkManifest(manifest);
      if (!errors.length) errors.push(...checkSourceLanguage(directory, manifest.name));
      for (const error of errors) console.error(`${directory}: ${error}`);
      failures += errors.length;
      if (!errors.length) console.log(`${directory}: architecture declarations match ${manifest.name}.`);
    } catch (error) { failures++; console.error(`${directory}: ${error.message}`); }
  }
  if (failures) process.exitCode = 1;
}
