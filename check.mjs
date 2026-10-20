import { readFileSync, realpathSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const contract = JSON.parse(readFileSync(new URL('./architecture.json', import.meta.url), 'utf8'));

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

if (process.argv[1] && existsSync(process.argv[1]) && realpathSync(resolve(process.argv[1])) === realpathSync(fileURLToPath(import.meta.url))) {
  let failures = 0;
  for (const directory of process.argv.slice(2).length ? process.argv.slice(2) : ['.']) {
    try {
      const manifest = JSON.parse(readFileSync(resolve(directory, 'package.json'), 'utf8'));
      const errors = checkManifest(manifest);
      for (const error of errors) console.error(`${directory}: ${error}`);
      failures += errors.length;
      if (!errors.length) console.log(`${directory}: architecture declarations match ${manifest.name}.`);
    } catch (error) { failures++; console.error(`${directory}: ${error.message}`); }
  }
  if (failures) process.exitCode = 1;
}
