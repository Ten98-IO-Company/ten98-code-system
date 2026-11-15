import { inspectDatabasePolicy } from './database-policy.mjs';
import { readFileSync, writeFileSync, realpathSync, existsSync, readdirSync, lstatSync, statSync } from 'node:fs';
import { resolve, relative, basename } from 'node:path';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

type StringMap = Record<string, string>;

interface SourceLanguagePolicy {
  default: string;
  roots: string[];
  legacyJavaScript: string[];
  generated: StringMap;
  artifactDirectories?: string[];
  testDirectories?: string[];
  nativeFiles?: StringMap;
  compilerProjects: string[];
}

interface PresentationPolicy {
  roots: string[];
  baseline?: string;
  owner: string;
}

// Raw statements in app source are counted per file against an allowlist the app commits; a count may only fall.
interface DataPolicy {
  roots: string[];
  baseline: string;
}

interface Profile {
  dependencies: StringMap;
  devDependencies: StringMap;
  sharedDependencies: string[];
  sharedDevDependencies: string[];
  peerDependencies: StringMap;
  checkScripts: string[];
  sourceLanguage?: SourceLanguagePolicy;
  presentation?: PresentationPolicy;
  data?: DataPolicy;
}

// An app profile declares only what it adds to the shared app stack; its other fields come from appStack.
type DeclaredProfile = Partial<Profile> & { stack?: 'app' };

// Exceptions are standing, reviewed deviations; transitions are temporary and end when doneWhen holds.
interface Exception { rule: string; profiles: string[]; items?: string[]; reason: string; owner: string; reviewTrigger: string; review: string }
interface Transition { rule: string; profile: string; items?: string[]; reason: string; owner: string; doneWhen: string }

interface Contract {
  node: string;
  packageManager: string;
  baseImage: string;
  sharedVersions: StringMap;
  sharedPackages: StringMap;
  // Minimum versions for shared packages that each app pins itself (decision record #28).
  sharedPackageFloors?: StringMap;
  appStack: Profile;
  databasePolicy: { postgresql: string; otherDrivers: string[] } & Record<string, unknown>;
  profiles: Record<string, DeclaredProfile>;
  exceptions: Record<string, Exception>;
  transitions: Record<string, Transition>;
}

export interface PackageManifest {
  name?: string;
  packageManager?: string;
  type?: string;
  engines?: { node?: string };
  dependencies?: StringMap;
  optionalDependencies?: StringMap;
  devDependencies?: StringMap;
  peerDependencies?: StringMap;
  scripts?: Record<string, string | undefined>;
  overrides?: unknown;
  resolutions?: unknown;
  pnpm?: { overrides?: unknown; patchedDependencies?: unknown; packageExtensions?: unknown };
  bundledDependencies?: unknown;
  bundleDependencies?: unknown;
}

interface CompilerProject {
  compilerOptions?: Record<string, unknown>;
  // Resolved program files; a single-project Compilation's own files list serves this role.
  files?: string[];
}

export interface Compilation extends CompilerProject {
  projects?: CompilerProject[];
  files: string[];
}

// The one `any`: rolldown's parseAst result is untyped third-party data, so nodes are inspected structurally by `type`.
interface AstNode { type: string; [key: string]: any }
type ParseAst = (source: string, options: { lang: string }) => { body: AstNode[] };
type PresentationCounts = Record<string, Record<string, number>>;

export interface ReleaseOptions {
  tag?: string;
  commit?: string;
  tagObject?: string;
  archive?: string;
  archiveSha256?: string;
  event?: string;
}

export interface ReleaseEvidence {
  name: string;
  version: string;
  tag: string;
  commit: string;
  tagObject: string;
  tagHistory: string;
  archive?: { filename: string; bytes: number; sha256: string; priorBytesVerified: boolean };
}

const contract: Contract = JSON.parse(readFileSync(new URL('./architecture.json', import.meta.url), 'utf8'));

// The rules an exception or transition may relax; anything else is a typo that would silently waive nothing.
const waivableRules = ['database.engine', 'packageManager', 'baseImage', 'appStack', 'profile.name'];

export function inspectWaivers(): string[] {
  const errors: string[] = [], text = (value: unknown): boolean => typeof value === 'string' && value.trim().length > 0;
  const items = (value: unknown): boolean => value === undefined || Array.isArray(value) && value.length > 0 && value.every(text);
  for (const [name, entry] of Object.entries(contract.exceptions ?? {})) {
    if (!waivableRules.includes(entry?.rule) || !Array.isArray(entry.profiles) || !entry.profiles.length || entry.profiles.some(profile => !Object.hasOwn(contract.profiles, profile))
      || !items(entry.items) || !text(entry.reason) || !text(entry.owner) || !text(entry.reviewTrigger) || !text(entry.review)) {
      errors.push(`exceptions.${name} needs a known rule, known profiles, a reason, an owner, a review trigger and a review record.`);
    }
  }
  const stack = new Set([...Object.keys(contract.appStack?.dependencies ?? {}), ...Object.keys(contract.appStack?.devDependencies ?? {})]);
  for (const [name, entry] of Object.entries(contract.transitions ?? {})) {
    // A transition names what it still allows, so it relaxes a rule to the app's recorded current state, not entirely.
    if (!waivableRules.includes(entry?.rule) || !Object.hasOwn(contract.profiles, entry.profile) || !items(entry.items)
      || entry.rule !== 'database.engine' && entry.items === undefined
      || entry.rule === 'appStack' && entry.items?.some(item => !stack.has(item))
      || !text(entry.reason) || !text(entry.owner) || !text(entry.doneWhen)) {
      errors.push(`transitions.${name} needs a known rule, a known profile, the items it still allows, a reason, an owner and a done-when condition.`);
    }
  }
  // One shared stack: an app profile adds libraries and its own source and data roots, and cannot restate the stack.
  const own = new Set(['stack', 'boundary', 'dependencies', 'devDependencies', 'sourceLanguage', 'data']);
  for (const [name, profile] of Object.entries(contract.profiles)) {
    if (profile.stack !== 'app') continue;
    const restated = [...Object.keys(profile).filter(key => !own.has(key)), ...Object.keys({ ...profile.dependencies, ...profile.devDependencies }).filter(item => stack.has(item))];
    if (restated.length) errors.push(`profiles.${name} restates the shared app stack (${restated.join(', ')}); change appStack or record a transition.`);
  }
  return errors;
}

// Whether a transition for this profile and rule allows `value`; `unset` stands for an absent field.
function transitionAllows(profile: string, rule: string, value: string | undefined): boolean {
  return transitionsFor(profile, rule).some(entry => entry.items?.includes(value ?? 'unset'));
}

// Open transitions for a profile and rule; their items name what each transition still waives.
function transitionsFor(profile: string, rule: string): Transition[] {
  return Object.values(contract.transitions ?? {}).filter(entry => entry.profile === profile && entry.rule === rule);
}

/** The profile a package name resolves to, with an app profile merged over the shared app stack. */
export function resolveProfile(packageName: string): { name: string; profile: Profile } | undefined {
  const name = Object.hasOwn(contract.profiles, packageName) ? packageName
    : Object.values(contract.transitions ?? {}).find(entry => entry.rule === 'profile.name' && entry.items?.includes(packageName))?.profile;
  const declared = name === undefined ? undefined : contract.profiles[name];
  if (name === undefined || !declared) return undefined;
  if (declared.stack !== 'app') return { name, profile: declared as Profile };
  const { stack: _stack, ...own } = declared, base = contract.appStack;
  return { name, profile: { ...base, ...own, dependencies: { ...base.dependencies, ...own.dependencies }, devDependencies: { ...base.devDependencies, ...own.devDependencies } } };
}

// Caught values are unknown; Error instances carry the message the CLI reports.
function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export function checkRuntimeVersion(version: unknown = process.versions.node): string[] {
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
function hasRequiredGate(script: unknown): boolean {
  if (typeof script !== 'string' || /[|;#\r\n]/u.test(script) || script.replaceAll('&&', '').includes('&')) return false;
  const commands = script.split('&&').map(command => command.trim());
  return commands.length > 1 && commands.every(Boolean)
    && /^(?:npm\s+run|pnpm(?:\s+run)?)\s+check:architecture$/u.test(commands[0]);
}

// A floored package's pinned archive must exist, and only one release of it may be vendored.
// Lockfile integrity is left to the package manager's frozen install, which rejects a mismatched archive.
export function checkVendoredFloors(directory: string, manifest: PackageManifest): string[] {
  const errors: string[] = [];
  for (const name of Object.keys(contract.sharedPackageFloors ?? {})) {
    const spec = manifest.dependencies?.[name] ?? manifest.devDependencies?.[name];
    if (typeof spec !== 'string' || !spec.startsWith('file:vendor/')) continue;
    const prefix = `${name.replace(/^@/u, '').replace('/', '-')}-`;
    if (!existsSync(resolve(directory, spec.slice('file:'.length)))) errors.push(`${name}: pinned archive ${spec.slice('file:'.length)} is missing.`);
    const vendored = existsSync(resolve(directory, 'vendor')) ? readdirSync(resolve(directory, 'vendor')).filter(file => file.startsWith(prefix) && file.endsWith('.tgz')) : [];
    if (vendored.length > 1) errors.push(`${name}: vendor holds ${vendored.length} archives (${vendored.join(', ')}); keep only the pinned release.`);
  }
  return errors;
}

// This checks declared dependencies and build gates, not application security or behavior.
export function checkManifest(manifest: PackageManifest): string[] {
  const errors = [...inspectDatabasePolicy(contract.databasePolicy, Object.fromEntries(Object.keys(contract.profiles).map(name => [name, resolveProfile(name)?.profile])), contract.exceptions, contract.transitions), ...inspectWaivers()];
  const resolved = resolveProfile(String(manifest.name));
  if (!resolved) return [`Unknown architecture profile: ${manifest.name ?? '(missing name)'}. Update architecture.json after review.`];
  const { name: profileName, profile } = resolved;
  // Shared app-stack libraries an open transition still lets this app go without; present ones must still match.
  const pending = new Set(transitionsFor(profileName, 'appStack').flatMap(entry => entry.items ?? []));
  const shared = { ...contract.sharedVersions, ...contract.sharedPackages };
  const floors = contract.sharedPackageFloors ?? {};
  const same = (actual: unknown, expected: unknown, label: string): void => { if (actual !== expected) errors.push(`${label}: expected ${expected}, found ${actual ?? '(missing)'}.`); };
  // A floored package is pinned by the app to one vendored release archive at or above the canonical floor.
  const atLeastFloor = (name: string, actual: unknown, label: string): void => {
    const archive = name.replace(/^@/u, '').replace('/', '-');
    const version = typeof actual === 'string' ? new RegExp(`^file:vendor/${archive}-(\\d+)\\.(\\d+)\\.(\\d+)\\.tgz$`, 'u').exec(actual) : null;
    const floor = /^(\d+)\.(\d+)\.(\d+)$/u.exec(floors[name] ?? '');
    if (!version || !floor) { errors.push(`${label}: expected file:vendor/${archive}-<version>.tgz at or above ${floors[name]}, found ${actual ?? '(missing)'}.`); return; }
    const [major, minor, patch] = version.slice(1).map(Number), [floorMajor, floorMinor, floorPatch] = floor.slice(1).map(Number);
    const below = major! - floorMajor! || minor! - floorMinor! || patch! - floorPatch!;
    if (below < 0) errors.push(`${label}: ${version.slice(1).join('.')} is below the supported floor ${floors[name]}.`);
  };
  const pinned = (name: string, actual: unknown, expected: unknown, label: string): void => {
    if (Object.hasOwn(floors, name)) atLeastFloor(name, actual, label); else same(actual, expected, label);
  };
  same(manifest.engines?.node, contract.node, 'engines.node');
  same(manifest.type, 'module', 'type');
  if (!transitionAllows(profileName, 'packageManager', manifest.packageManager)) same(manifest.packageManager, contract.packageManager, 'packageManager');
  const drivers = new Set(contract.databasePolicy.otherDrivers);
  for (const section of [manifest.dependencies, manifest.optionalDependencies, manifest.devDependencies, manifest.peerDependencies]) {
    for (const name of Object.keys(section ?? {})) if (drivers.has(name)) errors.push(`Second database driver ${name}: applications reach PostgreSQL only through pg and Drizzle.`);
  }
  const expected = { ...profile.dependencies, ...Object.fromEntries(profile.sharedDependencies.map(name => [name, shared[name]])) };
  for (const [name, version] of Object.entries(expected)) if (!pending.has(name) || manifest.dependencies?.[name] !== undefined) pinned(name, manifest.dependencies?.[name], version, `dependencies.${name}`);
  for (const name of Object.keys(manifest.dependencies ?? {})) if (!Object.hasOwn(expected, name)) errors.push(`Unapproved runtime dependency ${name}. Update architecture.json after review.`);
  for (const name of Object.keys(manifest.optionalDependencies ?? {})) errors.push(`Unapproved optional runtime dependency ${name}. Update architecture.json after review.`);
  const expectedDev = { ...profile.devDependencies, ...Object.fromEntries(profile.sharedDevDependencies.map(name => [name, shared[name]])) };
  for (const [name, version] of Object.entries(expectedDev)) if (!pending.has(name) || manifest.devDependencies?.[name] !== undefined) pinned(name, manifest.devDependencies?.[name], version, `devDependencies.${name}`);
  for (const name of Object.keys(manifest.devDependencies ?? {})) if (!Object.hasOwn(expectedDev, name)) errors.push(`Unapproved development dependency ${name}. Update architecture.json after review.`);
  for (const [name, version] of Object.entries(profile.peerDependencies)) same(manifest.peerDependencies?.[name], version, `peerDependencies.${name}`);
  for (const name of Object.keys(manifest.peerDependencies ?? {})) if (!Object.hasOwn(profile.peerDependencies, name)) errors.push(`Unapproved peer dependency ${name}. Update architecture.json after review.`);
  // These manifests consume accepted lockfiles/archives without graph substitutions.
  for (const [name, value] of [
    ['overrides', manifest.overrides], ['resolutions', manifest.resolutions],
    ['pnpm.overrides', manifest.pnpm?.overrides], ['pnpm.patchedDependencies', manifest.pnpm?.patchedDependencies],
    ['pnpm.packageExtensions', manifest.pnpm?.packageExtensions],
    ['bundledDependencies', manifest.bundledDependencies], ['bundleDependencies', manifest.bundleDependencies],
  ] satisfies [string, unknown][]) {
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
export function inspectSourcePolicy(directory: string, policy: SourceLanguagePolicy, compilation: Compilation): string[] {
  const errors: string[] = [];
  if (policy.default !== 'typescript') return ['Unknown source language policy.'];
  const nameOf = (file: string): string => relative(directory, resolve(directory, file)).replaceAll('\\', '/');
  for (const project of compilation.projects ?? [compilation]) {
    const options = project.compilerOptions ?? {};
    if (options.strict !== true) errors.push('The source compiler must enable strict.');
    if (options.noCheck === true) errors.push('The source compiler must not disable checking with noCheck.');
    for (const name of ['noImplicitAny', 'noImplicitThis', 'strictNullChecks', 'strictFunctionTypes', 'strictBindCallApply', 'strictPropertyInitialization', 'strictBuiltinIteratorReturn', 'alwaysStrict', 'useUnknownInCatchVariables']) {
      if (options[name] === false) errors.push(`The source compiler must not disable ${name}.`);
    }
    // Node 24 strips types from tests and scripts without checking them; erasable syntax keeps the run and checked programs identical.
    const stripped = (project.files ?? []).map(nameOf).find(name => /^(?:tests|scripts)\//u.test(name) && /\.[cm]?ts$/u.test(name) && !/\.d\.[cm]?ts$/u.test(name));
    if (stripped && options.erasableSyntaxOnly !== true) errors.push(`${stripped}: a compiler project covering tests or scripts must enable erasableSyntaxOnly.`);
  }
  const checked = new Set(compilation.files.map(file => resolve(directory, file)));
  const legacy = new Set(policy.legacyJavaScript), files: string[] = [];
  const artifacts = new Set(policy.artifactDirectories ?? []), tests = new Set(policy.testDirectories ?? []);
  const native = policy.nativeFiles ?? {};
  // Inventory the whole app, excluding explicit non-source artifacts and native test boundaries.
  // Otherwise a new api/lib directory could silently bypass the production-root policy.
  const classify = (folder: string): void => {
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
  const walk = (folder: string): void => {
    if (!existsSync(folder)) { errors.push(`Required source root missing: ${relative(directory, folder)}`); return; }
    if (lstatSync(folder).isSymbolicLink()) { errors.push(`Source links need explicit review: ${relative(directory, folder)}`); return; }
    for (const entry of readdirSync(folder, { withFileTypes: true })) {
      const file = resolve(folder, entry.name);
      // Nested artifact directories such as tests/fixtures hold checker inputs and recorded payloads, not authored source.
      if (entry.isDirectory() && artifacts.has(nameOf(file))) continue;
      if (entry.isDirectory()) walk(file);
      else if (entry.isSymbolicLink()) errors.push(`Source links need explicit review: ${relative(directory, file)}`);
      else if (entry.isFile()) files.push(file);
    }
  };
  for (const root of policy.roots) walk(resolve(directory, root));
  // The legacy list only shrinks: entries for removed, converted or relocated files must be deleted.
  const found = new Set(files.map(nameOf).filter(name => /\.(?:[cm]?js|jsx)$/iu.test(name)));
  for (const name of legacy) if (!found.has(name)) errors.push(`${name}: stale legacyJavaScript entry; no such authored JavaScript under a source root.`);
  for (const file of files) {
    const name = nameOf(file);
    if (found.has(name) && !legacy.has(name)) errors.push(`${name}: new authored JavaScript is not approved; use checked TypeScript.`);
    // Roots skip the whole-app inventory above, so native scripts inside them need the same explicit classification.
    if (/\.(?:ps1|cmd|bat)$/iu.test(name) && !Object.hasOwn(native, name)) errors.push(`${name}: code outside declared production roots needs a canonical source classification.`);
    if (!/\.(?:[cm]?ts|tsx)$/iu.test(name)) continue;
    if (!checked.has(file)) errors.push(`${name}: TypeScript is absent from the configured compiler program.`);
    const source = readFileSync(file, 'utf8'), generated = policy.generated[name];
    if (generated && !source.includes(generated)) errors.push(`${name}: reviewed generated-file provenance marker is missing.`);
    // The split spelling keeps this checker's own source from matching the directive it searches for.
    if (/@ts-no[c]heck\b/iu.test(source) && !generated) errors.push(`${name}: authored TypeScript must not disable checking with @ts-no${'check'}.`);
  }
  return errors;
}

export function checkSourceLanguage(directory: string, name: string): string[] {
  const policy = resolveProfile(name)?.profile.sourceLanguage;
  if (!policy) return [];
  directory = resolve(directory);
  const compiler = resolve(directory, 'node_modules/typescript/bin/tsc');
  const installed: { version?: string } = JSON.parse(readFileSync(resolve(directory, 'node_modules/typescript/package.json'), 'utf8'));
  if (installed.version !== contract.sharedVersions.typescript) return ['Installed TypeScript does not match the canonical version.'];
  const deadline = Date.now() + 90_000;
  const run = (project: string, args: string[]): string => {
    if (Date.now() >= deadline) throw Error('TypeScript source checking exceeded its 90-second budget.');
    const result = spawnSync(process.execPath, [compiler, '--project', project, ...args], {
      cwd: directory, encoding: 'utf8', timeout: Math.min(30_000, deadline - Date.now()), maxBuffer: 8 * 1024 * 1024, windowsHide: true,
    });
    if (result.error || result.status !== 0) throw Error(`TypeScript ${project} ${args.join(' ')} failed: ${result.error?.message ?? result.stdout + result.stderr}`);
    return result.stdout;
  };
  const projects: CompilerProject[] = [], files: string[] = [];
  // Resolve the actual import closure as well as configured roots; callers cannot submit a synthetic program.
  for (const project of policy.compilerProjects) {
    const program = run(project, ['--listFilesOnly', '--pretty', 'false']).trim().split(/\r?\n/u).filter(Boolean);
    projects.push({ ...JSON.parse(run(project, ['--showConfig'])), files: program });
    files.push(...program);
  }
  const errors = inspectSourcePolicy(directory, policy, { projects, files });
  if (!errors.length) for (const project of policy.compilerProjects) run(project, ['--noEmit', '--pretty', 'false']);
  return errors;
}

const CREATE_ELEMENT = new Set(['createElement', 'jsx', 'jsxs', '_jsx']);
const UI_SOURCE = /^@ten98\/ui(?:\/app)?$/u;

// Counts presentation violations per file and rule. Dynamic JSX spreads are a known limit: only
// object-literal spreads are inspected, so a spread variable can still carry className/style.
function presentationCounts(directory: string, policy: PresentationPolicy, parseAst: ParseAst): { counts: PresentationCounts; errors: string[] } {
  const counts: PresentationCounts = {}, errors: string[] = [], files: string[] = [];
  const add = (name: string, rule: string): void => { counts[name] ??= {}; counts[name][rule] = (counts[name][rule] ?? 0) + 1; };
  const rootOf = (node: AstNode): string => node.type === 'JSXMemberExpression' ? rootOf(node.object) : node.name;
  const walk = (folder: string): void => {
    if (!existsSync(folder)) { errors.push(`Required presentation root missing: ${relative(directory, folder)}`); return; }
    for (const entry of readdirSync(folder, { withFileTypes: true })) {
      const file = resolve(folder, entry.name);
      if (entry.isDirectory()) walk(file);
      else if (entry.isFile() && /\.[jt]sx$/u.test(entry.name)) files.push(file);
    }
  };
  for (const root of policy.roots) walk(resolve(directory, root));
  for (const file of files) {
    const name = relative(directory, file).replaceAll('\\', '/');
    let program;
    try { program = parseAst(readFileSync(file, 'utf8'), { lang: name.endsWith('tsx') ? 'tsx' : 'jsx' }); }
    catch (error) { errors.push(`${name}: cannot parse for the presentation check: ${messageOf(error)}`); continue; }
    const uiNamespaces = new Set<string>();
    for (const node of program.body) {
      if (node.type !== 'ImportDeclaration') continue;
      const source = node.source.value;
      if (/\.(?:css|scss|sass|less)$/u.test(source) && !source.startsWith('@ten98/ui')) add(name, 'stylesheet');
      if (UI_SOURCE.test(source)) for (const specifier of node.specifiers) if (specifier.type !== 'ImportSpecifier') uiNamespaces.add(specifier.local.name);
    }
    const visit = (node: AstNode | AstNode[] | null | undefined): void => {
      if (Array.isArray(node)) return node.forEach(visit);
      if (!node || typeof node.type !== 'string') return;
      if (node.type === 'JSXOpeningElement') {
        const tag = node.name;
        if (tag.type === 'JSXIdentifier' ? /^[a-z]/u.test(tag.name) : tag.type === 'JSXNamespacedName' || !uiNamespaces.has(rootOf(tag))) add(name, 'element');
      } else if (node.type === 'JSXAttribute') {
        if (node.name.name === 'className' || node.name.name === 'style') add(name, 'styling');
        if (node.name.name === 'dangerouslySetInnerHTML') add(name, 'inner-html');
      } else if (node.type === 'JSXSpreadAttribute') {
        if (node.argument.type === 'ObjectExpression' && node.argument.properties.some((property: AstNode) => ['className', 'style'].includes(property.key?.name ?? property.key?.value))) add(name, 'styling');
      } else if (node.type === 'CallExpression' && typeof node.arguments[0]?.value === 'string' && node.arguments[0].type === 'Literal') {
        const callee = node.callee;
        if (callee.type === 'Identifier' ? CREATE_ELEMENT.has(callee.name) : callee.type === 'MemberExpression' && callee.object.name === 'React' && callee.property.name === 'createElement') add(name, 'create-element');
      }
      for (const value of Object.values(node)) if (value && typeof value === 'object') visit(value);
    };
    visit(program.body);
  }
  return { counts, errors };
}

// rolldown arrives through the pinned vite; strict layouts (pnpm) expose it only from vite's own scope.
function resolveParseAst(directory: string): ParseAst | undefined {
  const consumer = createRequire(resolve(directory, 'package.json'));
  // The resolved module is untrusted runtime data; only its parseAst export is used.
  const loaders: (() => { parseAst: ParseAst })[] = [
    () => consumer('rolldown/parseAst') as { parseAst: ParseAst },
    () => createRequire(consumer.resolve('vite/package.json'))('rolldown/parseAst') as { parseAst: ParseAst },
  ];
  for (const load of loaders) {
    try { return load().parseAst; } catch { /* try the next scope */ }
  }
  return undefined;
}

// Ratchet: a file may not exceed its baseline count for any rule; unlisted files and rules allow 0.
// parseAst is injectable for tests; the CLI always resolves it from the consumer and fails closed.
export function checkPresentation(directory: string, name: string, { parseAst = resolveParseAst(directory) }: { parseAst?: ParseAst } = {}): string[] {
  const policy = resolveProfile(name)?.profile.presentation;
  if (!policy) return [];
  if (typeof parseAst !== 'function') return ['Cannot resolve rolldown/parseAst from the consumer; install the pinned build tooling to check presentation ownership.'];
  directory = resolve(directory);
  const { counts, errors } = presentationCounts(directory, policy, parseAst);
  const file = policy.baseline && resolve(directory, policy.baseline);
  const baseline: Record<string, Record<string, number> | undefined> = file && existsSync(file) ? JSON.parse(readFileSync(file, 'utf8')) : {};
  for (const [path, rules] of Object.entries(counts)) {
    for (const [rule, found] of Object.entries(rules)) {
      const allowed = baseline[path]?.[rule] ?? 0;
      if (found > allowed) errors.push(`${path}: ${rule} ${found} exceeds baseline ${allowed} (presentation is owned by ${policy.owner}).`);
    }
  }
  return errors;
}

// Only lowers or removes entries: any rise or new violation refuses and reports the errors instead.
// A missing baseline is recorded once from current counts; that first file is reviewed in the app's diff.
export function updatePresentationBaseline(directory: string, name: string, options: { parseAst?: ParseAst } = {}): string[] {
  const policy = resolveProfile(name)?.profile.presentation;
  if (!policy?.baseline) return [];
  const parseAst = options.parseAst ?? resolveParseAst(directory);
  if (existsSync(resolve(directory, policy.baseline)) || typeof parseAst !== 'function') {
    const errors = checkPresentation(directory, name, { parseAst });
    if (errors.length) return errors;
  }
  // A missing parser always makes checkPresentation return an error above, so a function is present here.
  const { counts, errors } = presentationCounts(resolve(directory), policy, parseAst as ParseAst);
  if (errors.length) return errors;
  writeFileSync(resolve(directory, policy.baseline), `${JSON.stringify(Object.fromEntries(Object.entries(counts).sort(([a], [b]) => a < b ? -1 : 1)), null, 2)}\n`);
  return [];
}

const START = '@tanstack/react-start', START_ENTRY = '@ten98/runtime/start';
const START_FILE = 'src/start.ts', CLIENT_FILE = 'src/client.tsx';
// Start resolves its start and client entries as `./start` and `./client` from src (start-plugin-core 1.171.50
// planning.js resolveStartEntryPlan, through resolve-entries.js resolveEntry): exsolve takes the first file among the
// bare name, then .ts, .js, .mts, .mjs, .tsx and .jsx; a folder never resolves. So the checked file is the one Start runs
// only when no other file carries the entry's name. .cts and .cjs are refused as well, and names are compared without
// case, as a case-insensitive file system resolves them.
const ENTRY_NAME = /^(start|client)(?:\.(?:[cm]?[jt]s|[jt]sx))?$/iu;

// Local names bound by value imports of `name` from `source`; type-only imports bind nothing at run time.
function importedAs(body: AstNode[], source: string, name: string): Set<string> {
  const locals = new Set<string>();
  for (const node of body) {
    if (node.type !== 'ImportDeclaration' || node.source.value !== source || node.importKind === 'type') continue;
    for (const specifier of node.specifiers) {
      if (specifier.type === 'ImportSpecifier' && specifier.importKind !== 'type' && (specifier.imported.name ?? specifier.imported.value) === name) locals.add(specifier.local.name);
    }
  }
  return locals;
}

// The createStart references in one file: value imports and re-exports of that name, and calls to a function or
// method of that name or of one of `aliases`.
function createStartUses(program: AstNode[], aliases: Set<string> = new Set()): { specifiers: number; calls: number } {
  const uses = { specifiers: 0, calls: 0 };
  const visit = (node: AstNode | AstNode[] | null | undefined): void => {
    if (Array.isArray(node)) return node.forEach(visit);
    if (!node || typeof node.type !== 'string' || node.importKind === 'type' || node.exportKind === 'type') return;
    if (node.type === 'ImportSpecifier' || node.type === 'ExportSpecifier') {
      const name = node.type === 'ImportSpecifier' ? node.imported : node.local;
      if ((name?.name ?? name?.value) === 'createStart') uses.specifiers++;
    } else if (node.type === 'CallExpression') {
      const callee = node.callee;
      if (callee.type === 'Identifier' ? callee.name === 'createStart' || aliases.has(callee.name) : callee.type === 'MemberExpression' && (callee.property?.name ?? callee.property?.value) === 'createStart') uses.calls++;
    }
    for (const value of Object.values(node)) if (value && typeof value === 'object') visit(value);
  };
  visit(program);
  return uses;
}

const ERROR_COMPONENT_KEYS = new Set(['errorComponent', 'defaultErrorComponent']);
const ERROR_TEXT = new Set(['message', 'stack', 'cause', 'name', 'toString']);
const keyName = (node: AstNode | undefined): string | undefined => node?.type === 'Identifier' ? node.name : typeof node?.value === 'string' ? node.value : undefined;
// An expression without its parentheses, TypeScript assertions and optional chain.
const bare = (node: AstNode | undefined): AstNode | undefined =>
  node && ['ParenthesizedExpression', 'TSAsExpression', 'TSSatisfiesExpression', 'TSNonNullExpression', 'TSTypeAssertion', 'ChainExpression'].includes(node.type) ? bare(node.expression) : node;
const isFunction = (node: AstNode | undefined): boolean => node?.type === 'ArrowFunctionExpression' || node?.type === 'FunctionExpression' || node?.type === 'FunctionDeclaration';

// Where a function passed as errorComponent or defaultErrorComponent, in any object literal, reads its error's text:
// .message, .stack, .cause, .name or .toString, destructured or not, a spread of it, or a String() or template literal of
// it. The error is the `error` prop, taken in the parameter or from the props object in the body. The function is
// written inline or named from a top-level declaration in the same file. Each finding is `<line>: <what>`.
function errorComponentReads(program: AstNode[], text: string): string[] {
  const declared = new Map<string, AstNode>();
  for (const statement of program) {
    const node = statement.type === 'ExportNamedDeclaration' || statement.type === 'ExportDefaultDeclaration' ? statement.declaration : statement;
    if (node?.type === 'FunctionDeclaration' && node.id) declared.set(node.id.name, node);
    if (node?.type === 'VariableDeclaration') for (const declarator of node.declarations) if (declarator.id.type === 'Identifier' && isFunction(bare(declarator.init))) declared.set(declarator.id.name, bare(declarator.init)!);
  }
  const findings: string[] = [];
  const at = (node: AstNode, what: string): void => { findings.push(`line ${text.slice(0, node.start).split('\n').length}: ${what}`); };
  const walk = (node: unknown, visit: (node: AstNode) => void): void => {
    if (Array.isArray(node)) return node.forEach(child => walk(child, visit));
    if (!node || typeof node !== 'object' || typeof (node as AstNode).type !== 'string') return;
    visit(node as AstNode);
    for (const value of Object.values(node)) if (value && typeof value === 'object') walk(value, visit);
  };
  const inspect = (component: AstNode): void => {
    const errors = new Set<string>(), props = new Set<string>();
    // `{ error }`, `{ error: e }` or `{ error: { message } }` from the props; the rest of the props under another name.
    const fromProps = (pattern: AstNode): void => {
      for (const property of pattern.properties) {
        if (property.type === 'RestElement') { if (property.argument.type === 'Identifier') props.add(property.argument.name); continue; }
        if (keyName(property.key) !== 'error') continue;
        const value = property.value.type === 'AssignmentPattern' ? property.value.left : property.value;
        if (value.type === 'Identifier') errors.add(value.name);
        else if (value.type === 'ObjectPattern') destructured(value);
      }
    };
    const destructured = (pattern: AstNode): void => {
      for (const property of pattern.properties) {
        if (property.type === 'RestElement') at(property, 'copies the rest of the error');
        else if (ERROR_TEXT.has(keyName(property.key) ?? '')) at(property, `reads error.${keyName(property.key)}`);
      }
    };
    const parameter = component.params[0]?.type === 'AssignmentPattern' ? component.params[0].left : component.params[0];
    if (parameter?.type === 'ObjectPattern') fromProps(parameter);
    else if (parameter?.type === 'Identifier') props.add(parameter.name);
    const isError = (node: AstNode | undefined): boolean => {
      const expression = bare(node);
      return expression?.type === 'Identifier' ? errors.has(expression.name)
        : expression?.type === 'MemberExpression' && !expression.computed && bare(expression.object)?.type === 'Identifier' && props.has(bare(expression.object)!.name) && keyName(expression.property) === 'error';
    };
    // `const { error } = props` names the error before it is used.
    walk(component.body, node => {
      if (node.type === 'VariableDeclarator' && node.id.type === 'ObjectPattern' && bare(node.init)?.type === 'Identifier' && props.has(bare(node.init)!.name)) fromProps(node.id);
    });
    walk(component.body, node => {
      const member = node.type === 'MemberExpression' ? (node.computed ? node.property.type === 'Literal' : node.property.type === 'Identifier') && keyName(node.property) : undefined;
      if (member && ERROR_TEXT.has(member) && isError(node.object)) at(node, `reads error.${member}`);
      else if (node.type === 'VariableDeclarator' && node.id.type === 'ObjectPattern' && isError(node.init)) destructured(node.id);
      else if ((node.type === 'SpreadElement' || node.type === 'JSXSpreadAttribute') && isError(node.argument)) at(node, 'spreads the error');
      else if (node.type === 'TemplateLiteral' && node.expressions.some(isError)) at(node, 'puts the error in a template literal');
      else if (node.type === 'CallExpression' && bare(node.callee)?.type === 'Identifier' && bare(node.callee)!.name === 'String' && isError(node.arguments[0])) at(node, 'converts the error with String()');
    });
  };
  walk(program, node => {
    if (node.type !== 'Property' || !ERROR_COMPONENT_KEYS.has(keyName(node.key) ?? '') || node.computed) return;
    const value = bare(node.value);
    const component = isFunction(value) ? value : value?.type === 'Identifier' ? declared.get(value.name) : undefined;
    if (component) inspect(component);
  });
  return [...new Set(findings)];
}

// The app's source files outside artifact folders, as forward-slash paths from the app.
function appSources(directory: string, roots: string[], skip: Set<string>): string[] {
  const files: string[] = [];
  const walk = (folder: string): void => {
    if (!existsSync(folder)) return;
    for (const entry of readdirSync(folder, { withFileTypes: true })) {
      const file = resolve(folder, entry.name), name = relative(directory, file).replaceAll('\\', '/');
      if (skip.has(name) || entry.name === 'node_modules') continue;
      if (entry.isDirectory()) walk(file);
      else if (entry.isFile() && /\.(?:[cm]?[jt]s|[jt]sx)$/u.test(entry.name) && !/\.d\.[cm]?ts$/u.test(entry.name)) files.push(name);
    }
  };
  for (const root of roots) walk(resolve(directory, root));
  return files;
}

/**
 * A TanStack Start app takes its error and CSRF defaults from @ten98/runtime/start: src/start.ts exports
 * `startInstance = createStart(() => ten98StartOptions(...))`, src/client.tsx calls `hydrateTen98Start(...)` at its
 * top level, no other source file uses createStart, and no errorComponent reads its error's text. It applies when the
 * manifest's dependencies list Start, or the profile requires it and no open transition waives it. Parser-backed; the
 * adoption guide lists what it does not see.
 */
export function checkStartEntry(directory: string, manifest: PackageManifest, { parseAst = resolveParseAst(directory) }: { parseAst?: ParseAst } = {}): string[] {
  const resolved = resolveProfile(String(manifest.name));
  const waived = resolved !== undefined && transitionsFor(resolved.name, 'appStack').some(entry => entry.items?.includes(START));
  if (manifest.dependencies?.[START] === undefined && (resolved?.profile.dependencies[START] === undefined || waived)) return [];
  if (typeof parseAst !== 'function') return ['Cannot resolve rolldown/parseAst from the consumer; install the pinned build tooling to check the Start entry.'];
  directory = resolve(directory);
  const errors: string[] = [];
  const parse = (name: string): AstNode[] | undefined => {
    try { return parseAst(readFileSync(resolve(directory, name), 'utf8'), { lang: /\.[jt]sx$/u.test(name) ? name.slice(-3) : /\.[cm]?js$/u.test(name) ? 'js' : 'ts' }).body; }
    catch (error) { errors.push(`${name}: cannot parse for the Start entry check: ${messageOf(error)}`); return undefined; }
  };
  const start = existsSync(resolve(directory, START_FILE)) ? parse(START_FILE) : undefined;
  if (!existsSync(resolve(directory, START_FILE))) errors.push(`${START_FILE} is missing: a Start app exports startInstance = createStart(() => ten98StartOptions(...)) there, with ten98StartOptions from ${START_ENTRY}.`);
  else if (start) {
    const createStart = importedAs(start, START, 'createStart'), options = importedAs(start, START_ENTRY, 'ten98StartOptions');
    // Each callee must be bound by exactly one import, and the callback takes no parameters, so neither name can be
    // shadowed: the file holds no other declarations.
    const imported = start.flatMap(node => node.type === 'ImportDeclaration' ? node.specifiers.map((specifier: AstNode) => specifier.local.name as string) : []);
    const importedOnce = (locals: Set<string>, name: string): boolean => locals.has(name) && imported.filter(local => local === name).length === 1;
    const exported = start.find(node => node.type === 'ExportNamedDeclaration' && node.declaration?.type === 'VariableDeclaration' && node.declaration.kind === 'const'
      && node.declaration.declarations.every((declarator: AstNode) => {
        const init = declarator.init, getOptions = init?.arguments?.[0], body = getOptions?.body;
        return declarator.id.type === 'Identifier' && declarator.id.name === 'startInstance' && init?.type === 'CallExpression' && init.callee.type === 'Identifier' && importedOnce(createStart, init.callee.name)
          && init.arguments.length === 1 && getOptions.type === 'ArrowFunctionExpression' && getOptions.expression === true && getOptions.params.length === 0
          && body.type === 'CallExpression' && body.callee.type === 'Identifier' && importedOnce(options, body.callee.name);
      }));
    let instanceNames = 0;
    const countInstanceNames = (node: unknown): void => {
      if (Array.isArray(node)) return node.forEach(countInstanceNames);
      if (!node || typeof node !== 'object') return;
      if ((node as AstNode).type === 'Identifier' && (node as AstNode).name === 'startInstance') instanceNames++;
      for (const value of Object.values(node)) if (value && typeof value === 'object') countInstanceNames(value);
    };
    countInstanceNames(start);
    if (!exported) errors.push(`${START_FILE} must export const startInstance = createStart(() => ten98StartOptions(...)), returning ten98StartOptions from ${START_ENTRY} directly, so the shared error serialisation and CSRF middleware cannot be dropped.`);
    else if (start.some(node => node !== exported && node.type !== 'ImportDeclaration') || instanceNames !== 1) {
      errors.push(`${START_FILE} must hold only its imports and the startInstance export, and name startInstance nowhere else, so nothing else can change the start instance.`);
    } else if (createStartUses(start, createStart).calls !== 1) errors.push(`${START_FILE} must call createStart only once, for startInstance.`);
  }
  const client = existsSync(resolve(directory, CLIENT_FILE)) ? parse(CLIENT_FILE) : undefined;
  if (!existsSync(resolve(directory, CLIENT_FILE))) errors.push(`${CLIENT_FILE} is missing: a Start app calls hydrateTen98Start() from ${START_ENTRY} there.`);
  else if (client) {
    const hydrate = importedAs(client, START_ENTRY, 'hydrateTen98Start');
    if (!client.some(node => node.type === 'ExpressionStatement' && node.expression.type === 'CallExpression' && node.expression.callee.type === 'Identifier' && hydrate.has(node.expression.callee.name))) {
      errors.push(`${CLIENT_FILE} must call hydrateTen98Start(...) from ${START_ENTRY} at its top level.`);
    }
  }
  const src = resolve(directory, 'src');
  for (const entry of existsSync(src) ? readdirSync(src) : []) {
    const name = `src/${entry}`, kind = ENTRY_NAME.exec(entry)?.[1]?.toLowerCase();
    if (!kind || name === START_FILE || name === CLIENT_FILE || !statSync(resolve(src, entry), { throwIfNoEntry: false })?.isFile()) continue;
    const checked = kind === 'start' ? START_FILE : CLIENT_FILE;
    errors.push(`${name}: Start can take its ${kind} entry from this file instead of ${checked}; keep ${checked} as the only src/${kind} file.`);
  }
  const policy = resolved?.profile.sourceLanguage;
  for (const name of appSources(directory, policy?.roots ?? ['src'], new Set([START_FILE, ...policy?.artifactDirectories ?? []]))) {
    // Every form either rule counts contains its name, so files without one need no parse.
    const text = readFileSync(resolve(directory, name), 'utf8');
    const program = /createStart|rrorComponent/u.test(text) ? parse(name) : undefined;
    if (!program) continue;
    const uses = createStartUses(program);
    if (uses.specifiers + uses.calls) errors.push(`${name}: createStart belongs in ${START_FILE} only, as createStart(() => ten98StartOptions(...)).`);
    for (const finding of errorComponentReads(program, text)) {
      errors.push(`${name} ${finding}: an errorComponent also renders on the server with the original error, so it shows publicErrorMessage(error) and reads nothing else of the error.`);
    }
  }
  return errors;
}

const escapeRegExp = (value: string): string => value.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');

// Container files at the app root and one folder below it (deploy/, docker/), skipping installed and built output.
function containerFiles(directory: string, pattern: RegExp): string[] {
  const skip = new Set(['node_modules', '.git', 'vendor', 'dist', '.output', 'build', 'coverage']), files: string[] = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    if (entry.isFile() && pattern.test(entry.name)) files.push(entry.name);
    else if (entry.isDirectory() && !skip.has(entry.name)) {
      for (const inner of readdirSync(resolve(directory, entry.name), { withFileTypes: true })) if (inner.isFile() && pattern.test(inner.name)) files.push(`${entry.name}/${inner.name}`);
    }
  }
  return files.sort();
}

// Text matching of the app's Dockerfiles and compose files, not a parser: an image named through a build argument or
// an environment default without a literal `postgres` reference, or a differently named PostgreSQL image (pgvector,
// a registry mirror), is outside this check.
export function checkDeployment(directory: string, packageName: string): string[] {
  const resolved = resolveProfile(packageName);
  if (!resolved) return [];
  directory = resolve(directory);
  const errors: string[] = [];
  const digest = '(?:@sha256:[0-9a-f]{64})?';
  const allowed = [contract.baseImage, ...transitionsFor(resolved.name, 'baseImage').flatMap(entry => entry.items ?? [])];
  const base = new RegExp(`^(?:${allowed.map(escapeRegExp).join('|')})${digest}$`, 'u');
  for (const name of containerFiles(directory, /^(?:Dockerfile|Containerfile)(?:\..+)?$|\.(?:dockerfile|containerfile)$/iu)) {
    const stages = new Set<string>();
    for (const line of readFileSync(resolve(directory, name), 'utf8').split(/\r?\n/u)) {
      const from = /^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?/iu.exec(line);
      // COPY --from= may name another image instead of a stage, which brings that image's files (and Node) along.
      const copied = /^\s*COPY\s+(?:--\S+\s+)*?--from=(\S+)/iu.exec(line);
      const image = from?.[1] ?? copied?.[1];
      if (image && !stages.has(image.toLowerCase()) && !/^\d+$/u.test(image) && !base.test(image)) errors.push(`${name}: base image ${image} must be ${contract.baseImage}, optionally pinned by digest.`);
      if (from?.[2]) stages.add(from[2].toLowerCase());
    }
  }
  const major = contract.databasePolicy.postgresql;
  const postgres = new RegExp(`^postgres:${major}(?:[.-][\\w.-]*)?${digest}$`, 'u');
  for (const name of containerFiles(directory, /^(?:docker-)?compose(?:\.[\w-]+)*\.ya?ml$/iu)) {
    for (const line of readFileSync(resolve(directory, name), 'utf8').split(/\r?\n/u)) {
      const value = line.replace(/\s#.*$/u, '');
      if (!/\bimage\b/u.test(value)) continue;
      // Block and inline maps, quoted values and `${VAR:-postgres:16}` defaults; docker.io/library/ is the same image.
      for (const match of value.matchAll(/(?:^|[\s"'{,=]|:-)((?:docker\.io\/)?(?:library\/)?postgres(?:[:@][^\s"',}]*)?)(?=$|[\s"',}])/gu)) {
        const image = match[1].replace(/^(?:docker\.io\/)?(?:library\/)?/u, '');
        if (!postgres.test(image)) errors.push(`${name}: PostgreSQL image ${match[1]} must be major ${major} (postgres:${major}).`);
      }
    }
  }
  return errors;
}

// The index after an optional type argument starting at `index` (whitespace first), or `index` when there is none.
// Brackets are balanced so object types with `;`, nested generics and `=>` arrows are skipped whole.
function afterTypeArgument(text: string, index: number): number {
  // Whitespace and comments may stand before the type argument, as in `pool.query/* note */<Row>(`.
  let at = index + (/^(?:\s|\/\*[\s\S]*?\*\/|\/\/[^\n]*\n)*/u.exec(text.slice(index, index + 4000))?.[0].length ?? 0);
  if (text[at] !== '<') return index;
  for (let depth = 0, end = Math.min(text.length, at + 4000); at < end; at++) {
    if (text[at] === '<') depth++;
    else if (text[at] === '>' && text[at - 1] !== '=' && --depth === 0) return at + 1;
  }
  return index;
}

// Counts raw statements in one file: a pg `.query(` call (also `?.(`, `!(`, `?.<T>(`, `['query'](` and `.query.call(`,
// `.apply(`, `.bind(`, with comments allowed before the parenthesis), Drizzle `sql.raw(`, and `.execute(` given SQL text,
// a `sql` template or `sql.join(` (also inside extra parentheses or after a comment), each with or without a type
// argument, and with `sql` under any name it is imported as from drizzle-orm, namespace imports included. Text
// matching, not parsing: the adoption guide lists the forms it misses, while a comment or an unrelated query method is
// counted; the per-file allowlist absorbs the second kind.
function countRawStatements(text: string): number {
  const names = ['sql'], escape = (name: string) => name.replaceAll('$', '\\$');
  for (const [, list] of text.matchAll(/import\s+(?:type\s+)?\{([^}]*)\}\s*from\s*['"]drizzle-orm(?:\/[^'"]*)?['"]/gu)) {
    for (const [, alias] of list.matchAll(/\bsql\s+as\s+([A-Za-z_$][\w$]*)/gu)) names.push(escape(alias));
  }
  // `import * as d` and `import d, * as ns`.
  for (const [, namespace] of text.matchAll(/import\s+(?:[A-Za-z_$][\w$]*\s*,\s*)?\*\s+as\s+([A-Za-z_$][\w$]*)\s+from\s*['"]drizzle-orm(?:\/[^'"]*)?['"]/gu)) {
    names.push(String.raw`${escape(namespace)}\s*\.\s*sql`);
  }
  const sqlName = `(?:${names.join('|')})`, tag = new RegExp(String.raw`^${sqlName}\b`, 'u');
  // Whitespace and comments.
  const gap = String.raw`(?:\s|\/\*[\s\S]*?\*\/|\/\/[^\n]*\n)*`;
  const call = new RegExp(String.raw`^${gap}(?:\?\.|!)?${gap}\(`, 'u'), method = new RegExp(String.raw`^${gap}!?${gap}\??\.${gap}(?:call|apply|bind)${gap}\(`, 'u');
  const quote = /^\s*[`'"]/u, join = /^\s*\.\s*join\s*\(/u, optional = /^\s*(?:\?\.|!)(?=\s*<)/u;
  // `.execute`'s opening parenthesis, with any further parentheses and comments before its argument.
  const opening = new RegExp(String.raw`^\s*\((?:\s|\(|\/\*[\s\S]*?\*\/|\/\/[^\n]*\n)*`, 'u');
  let count = 0;
  for (const match of text.matchAll(new RegExp(String.raw`\.query\b|\[\s*['"]query['"]\s*\]|\b${sqlName}\.raw\b|\.execute\b`, 'gu'))) {
    let at = match.index + match[0].length;
    // `?.` or `!` before a type argument, as in `pool.query?.<Row>(`.
    at += optional.exec(text.slice(at, at + 16))?.[0].length ?? 0;
    const rest = text.slice(afterTypeArgument(text, at));
    if (match[0].endsWith('.raw')) count += Number(call.test(rest));
    else if (match[0] !== '.execute') count += Number(call.test(rest) || method.test(rest));
    else {
      // `.execute(` counts when its argument is SQL text, a `sql` template (with an optional type argument) or `sql.join(`.
      const opened = opening.exec(rest);
      if (!opened) continue;
      let argument = rest.slice(opened[0].length);
      const named = tag.exec(argument);
      if (named) argument = argument.slice(afterTypeArgument(argument, named[0].length));
      count += Number(quote.test(argument) || (named !== null && join.test(argument)));
    }
  }
  return count;
}

// Each source file under the data roots, as its forward-slash path from the app and its text.
function dataSources(directory: string, policy: DataPolicy): [string, string][] {
  const sources: [string, string][] = [];
  const walk = (folder: string): void => {
    if (!existsSync(folder)) return;
    for (const entry of readdirSync(folder, { withFileTypes: true })) {
      const file = resolve(folder, entry.name);
      if (entry.isDirectory()) walk(file);
      else if (entry.isFile() && /\.(?:[cm]?[jt]s|[jt]sx)$/u.test(entry.name) && !/\.d\.[cm]?ts$/u.test(entry.name)) {
        sources.push([relative(directory, file).replaceAll('\\', '/'), readFileSync(file, 'utf8')]);
      }
    }
  };
  for (const root of policy.roots) walk(resolve(directory, root));
  return sources;
}

function rawStatementCounts(sources: readonly [string, string][]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const [path, text] of sources) {
    const found = countRawStatements(text);
    if (found) counts[path] = found;
  }
  return counts;
}

// The test-only tenancy entry sets a scope without the membership check, so production code (the data roots) never
// imports it: as `from`, a bare or dynamic `import`, or `require`. Tests live outside the data roots.
const testingTenancy = /(?:\bfrom\s*|\bimport\s*\(\s*|\bimport\s+|\brequire\s*\(\s*)['"`]@ten98\/runtime\/tenancy\/testing['"`]/u;
function testingTenancyImports(sources: readonly [string, string][]): string[] {
  return sources.filter(([, text]) => testingTenancy.test(text))
    .map(([path]) => `${path}: imports the test-only @ten98/runtime/tenancy/testing, which sets a scope without the membership check; only tests outside the data roots may.`);
}

// One allowlist entry: how many raw statements the file may hold and why they cannot be typed Drizzle queries.
type Allowance = { count: number; reason: string };

function readAllowlist(directory: string, policy: DataPolicy): { allowed: Record<string, Allowance>; exists: boolean; errors: string[] } {
  const file = resolve(directory, policy.baseline);
  if (!existsSync(file)) return { allowed: {}, exists: false, errors: [] };
  const parsed: unknown = JSON.parse(readFileSync(file, 'utf8'));
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return { allowed: {}, exists: true, errors: [`${policy.baseline} must map each file to { "count", "reason" }.`] };
  const allowed: Record<string, Allowance> = {}, errors: string[] = [];
  for (const [path, entry] of Object.entries(parsed as Record<string, unknown>)) {
    const { count, reason } = (entry ?? {}) as Partial<Allowance>;
    if (!Number.isSafeInteger(count) || count! < 1) errors.push(`${policy.baseline}: ${path} needs a positive whole "count".`);
    if (typeof reason !== 'string' || !reason.trim()) errors.push(`${policy.baseline}: ${path} needs a "reason" saying why its raw statements cannot be typed Drizzle queries.`);
    allowed[path] = { count: Number.isSafeInteger(count) ? count! : 0, reason: typeof reason === 'string' ? reason : '' };
  }
  return { allowed, exists: true, errors };
}

function rawStatementRises(counts: Record<string, number>, allowed: Record<string, Allowance>, baseline: string): string[] {
  return Object.entries(counts).filter(([path, found]) => found > (allowed[path]?.count ?? 0))
    .map(([path, found]) => `${path}: raw statement count ${found} exceeds the allowlist (${allowed[path]?.count ?? 0} in ${baseline}); use a typed Drizzle query.`);
}

// Application queries are typed Drizzle queries. Raw statements stay only where the app's committed allowlist names
// the file with a reason, and never more of them than it records.
export function checkDataAccess(directory: string, packageName: string): string[] {
  const policy = resolveProfile(packageName)?.profile.data;
  if (!policy) return [];
  directory = resolve(directory);
  const { allowed, errors } = readAllowlist(directory, policy);
  const sources = dataSources(directory, policy);
  return [...errors, ...testingTenancyImports(sources), ...rawStatementRises(rawStatementCounts(sources), allowed, policy.baseline)];
}

// Lowers or removes allowlist entries and keeps their reasons; a rise is refused. A missing allowlist is recorded once
// from current counts. New entries are written with an empty reason, which the check refuses until someone writes it,
// so the first allowlist is justified file by file in the app's diff.
export function updateRawStatementBaseline(directory: string, packageName: string): string[] {
  const policy = resolveProfile(packageName)?.profile.data;
  if (!policy) return [];
  directory = resolve(directory);
  const { allowed, exists } = readAllowlist(directory, policy), counts = rawStatementCounts(dataSources(directory, policy));
  if (exists) {
    const rises = rawStatementRises(counts, allowed, policy.baseline);
    if (rises.length) return rises;
  }
  const entries = Object.entries(counts).sort(([a], [b]) => a < b ? -1 : 1).map(([path, count]) => [path, { count, reason: allowed[path]?.reason ?? '' }] as const);
  writeFileSync(resolve(directory, policy.baseline), `${JSON.stringify(Object.fromEntries(entries), null, 2)}\n`);
  return readAllowlist(directory, policy).errors;
}

/**
 * Read-only: each consumer manifest against the current declaration. Nothing is installed, built or written. `status`
 * is manifest drift; `adoption` lists what the folder's container files and raw statements would still fail once
 * the consumer installs this release. Source-language and presentation checks need an install and are not run.
 */
export function driftReport(directories: string[]): { directory: string; name: string; status: 'current' | 'behind'; runtime: string; problems: string[]; adoption: string[] }[] {
  return directories.map(directory => {
    const manifest: PackageManifest = JSON.parse(readFileSync(resolve(directory, 'package.json'), 'utf8'));
    const runtime = manifest.dependencies?.['@ten98/runtime'] ?? manifest.devDependencies?.['@ten98/runtime'] ?? '(none)';
    const problems = checkManifest(manifest), name = String(manifest.name);
    const adoption = [...checkDeployment(directory, name), ...checkDataAccess(directory, name)];
    return { directory, name, status: problems.length ? 'behind' : 'current', runtime, problems, adoption };
  });
}

// Release mode is separate from ordinary architecture checks and reads committed evidence.
export function collectReleaseIdentity(directory: string, { tag = '', commit = '', tagObject, archive, archiveSha256, event }: ReleaseOptions = {}): ReleaseEvidence {
  directory = resolve(directory);
  const sha = /^[0-9a-f]{40}$/u;
  if (!/^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/u.test(tag)) throw Error('Release tag must use normal vX.Y.Z SemVer.');
  if (!sha.test(commit) || tagObject !== undefined && !sha.test(tagObject)) throw Error('Expected commit and optional tag object must be full Git SHA-1 IDs from independent evidence.');
  const run = (command: string, args: string[], input?: string | Uint8Array): string => {
    const result = spawnSync(command, args, { cwd: directory, input, encoding: 'utf8', timeout: 30_000, maxBuffer: 8 * 1024 * 1024, windowsHide: true });
    if (result.error || result.status !== 0) throw Error(`${command} evidence collection failed: ${result.error?.message ?? result.stderr}`);
    return result.stdout.trim();
  };
  const git = (...args: string[]): string => run('git', ['--no-replace-objects', ...args]);
  const ref = `refs/tags/${tag}`;
  if (git('cat-file', '-t', ref) !== 'tag') throw Error('Release requires an annotated Git tag.');
  const actualObject = git('rev-parse', '--verify', ref);
  const actualCommit = git('rev-parse', '--verify', `${ref}^{commit}`);
  if (actualCommit !== commit || git('rev-parse', '--verify', 'HEAD') !== commit) throw Error('Release tag or checkout differs from the independently qualified commit.');
  if (tagObject !== undefined && actualObject !== tagObject) throw Error('Release tag moved or its annotation was replaced.');
  const annotation = git('cat-file', 'tag', actualObject).split('\n\n')[0];
  if (!annotation.split('\n').includes(`tag ${tag}`)) throw Error('Annotated tag name differs from its release ref.');
  if (event !== undefined) {
    const pushed: { ref?: string; created?: boolean; deleted?: boolean; forced?: boolean; before?: string; after?: string } = JSON.parse(readFileSync(resolve(event), 'utf8'));
    if (pushed.ref !== ref || pushed.created !== true || pushed.deleted !== false || pushed.forced !== false || !/^0{40}$/u.test(pushed.before ?? '') || ![actualCommit, actualObject].includes(pushed.after ?? '')) {
      throw Error('Release push must create a new tag; moved, deleted or mismatched tag events are rejected.');
    }
  }
  const manifest: { name?: unknown; version?: unknown } = JSON.parse(git('show', `${commit}:package.json`));
  const version = tag.slice(1), name = manifest.name;
  if (typeof name !== 'string' || !/^(?:@[a-z0-9._-]+\/)?[a-z0-9._-]+$/u.test(name) || manifest.version !== version) throw Error('Committed package name/version does not match the release tag.');
  const tracked = git('ls-tree', '--name-only', commit, '--', 'package-lock.json', 'pnpm-lock.yaml').split('\n').filter(Boolean);
  if (tracked.length !== 1) throw Error('Release commit must track exactly one lockfile: package-lock.json or pnpm-lock.yaml.');
  // npm records the root name and version in its lock; pnpm's lock records neither, so package.json alone carries them.
  if (tracked[0] === 'package-lock.json') {
    const lock: { name?: unknown; version?: unknown; packages?: Record<string, { name?: unknown; version?: unknown }> } = JSON.parse(git('show', `${commit}:package-lock.json`));
    if (lock.name !== name || lock.version !== version || lock.packages?.['']?.name !== name || lock.packages[''].version !== version) throw Error('Committed root lock name/version differs from the package.');
  } else if (!/^importers:\r?\n(?:\r?\n)? {2}\.:\r?$/mu.test(git('show', `${commit}:pnpm-lock.yaml`))) {
    throw Error('Committed pnpm lock has no root importer.');
  }
  const evidence: ReleaseEvidence = { name, version, tag, commit: actualCommit, tagObject: actualObject, tagHistory: event ? 'new-tag push event' : tagObject ? 'independent tag-object receipt' : 'unverified; no prior tag-object receipt or push event' };
  if (archiveSha256 !== undefined && (!archive || !/^[0-9a-f]{64}$/u.test(archiveSha256))) throw Error('Archive digest comparison needs an archive and a full SHA256.');
  if (archive !== undefined) {
    archive = resolve(archive);
    const filename = `${name.replace(/^@/u, '').replaceAll('/', '-')}-${version}.tgz`;
    if (basename(archive) !== filename) throw Error('Archive filename differs from the package release identity.');
    const bytes = readFileSync(archive);
    const entries = run('tar', ['-tzf', '-'], bytes).split(/\r?\n/u);
    if (entries.filter(entry => entry === 'package/package.json').length !== 1) throw Error('Archive must contain exactly one package/package.json.');
    const packed: { name?: unknown; version?: unknown } = JSON.parse(run('tar', ['-xOzf', '-', 'package/package.json'], bytes));
    if (packed.name !== name || packed.version !== version) throw Error('Actual packed package identity differs from the tagged package.');
    const digest = createHash('sha256').update(bytes).digest('hex');
    if (archiveSha256 !== undefined && digest !== archiveSha256) throw Error('Archive bytes differ from the independently recorded SHA256.');
    evidence.archive = { filename, bytes: bytes.length, sha256: digest, priorBytesVerified: archiveSha256 !== undefined };
  }
  return evidence;
}

function releaseArguments(args: string[]): ReleaseEvidence {
  const directory = args.shift();
  if (!directory || directory.startsWith('--') || args.length % 2) throw Error('Usage: --release DIRECTORY --tag vX.Y.Z --commit SHA [--tag-object SHA] [--event FILE] [--archive FILE] [--archive-sha256 SHA]');
  const keys: Record<string, keyof ReleaseOptions> = { '--tag': 'tag', '--commit': 'commit', '--tag-object': 'tagObject', '--event': 'event', '--archive': 'archive', '--archive-sha256': 'archiveSha256' }, options: ReleaseOptions = {};
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
  const flag = '--update-presentation-baseline', rawFlag = '--update-raw-statement-baseline', args = process.argv.slice(2);
  const release = args[0] === '--release', drift = args[0] === '--drift', update = !release && args.includes(flag), updateRaw = !release && args.includes(rawFlag);
  const directories = args.filter(arg => arg !== flag && arg !== rawFlag);
  if (!failures && release) {
    try { console.log(JSON.stringify(releaseArguments(args.slice(1)), null, 2)); }
    catch (error) { failures++; console.error(messageOf(error)); }
  }
  if (!failures && drift) {
    // A report, not a gate: a consumer being behind is its status, so only an unreadable manifest fails the command.
    try {
      for (const row of driftReport(directories.slice(1))) {
        console.log(`${row.name} (${row.directory}): ${row.status}, runtime ${row.runtime}`);
        for (const problem of row.problems) console.log(`  - ${problem}`);
        if (row.adoption.length) console.log(`  on adoption, ${row.adoption.length} container or raw-statement findings, first: ${row.adoption[0]}`);
      }
    } catch (error) { failures++; console.error(messageOf(error)); }
  }
  for (const directory of runtimeErrors.length || release || drift ? [] : directories.length ? directories : ['.']) {
    try {
      const manifest: PackageManifest = JSON.parse(readFileSync(resolve(directory, 'package.json'), 'utf8'));
      const errors = checkManifest(manifest);
      if (!errors.length) errors.push(...checkVendoredFloors(directory, manifest));
      if (!errors.length) errors.push(...checkDeployment(directory, String(manifest.name)));
      if (!errors.length) errors.push(...(updateRaw ? updateRawStatementBaseline : checkDataAccess)(directory, String(manifest.name)));
      if (!errors.length) errors.push(...checkSourceLanguage(directory, String(manifest.name)));
      if (!errors.length) errors.push(...(update ? updatePresentationBaseline : checkPresentation)(directory, String(manifest.name)));
      if (!errors.length) errors.push(...checkStartEntry(directory, manifest));
      for (const error of errors) console.error(`${directory}: ${error}`);
      failures += errors.length;
      if (!errors.length) console.log(`${directory}: architecture declarations match ${manifest.name}.`);
    } catch (error) { failures++; console.error(`${directory}: ${messageOf(error)}`); }
  }
  if (failures) process.exitCode = 1;
}
