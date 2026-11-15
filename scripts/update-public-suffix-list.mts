// Replaces data/public_suffix_list.dat with the file at one publicsuffix/list commit, byte for byte, and records that
// commit and the file's SHA-256 in data/public_suffix_list.json and THIRD_PARTY_NOTICES.md. Run it in every runtime minor:
//   node scripts/update-public-suffix-list.mts <full 40-character publicsuffix/list commit SHA>
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';

const commit = process.argv[2] ?? '';
if (!/^[0-9a-f]{40}$/u.test(commit)) {
  console.error('Usage: node scripts/update-public-suffix-list.mts <full 40-character publicsuffix/list commit SHA>');
  process.exit(2);
}
const record = new URL('../data/public_suffix_list.json', import.meta.url);
const notices = new URL('../THIRD_PARTY_NOTICES.md', import.meta.url);
const source = `https://raw.githubusercontent.com/publicsuffix/list/${commit}/public_suffix_list.dat`;
const response = await fetch(source, { redirect: 'error', signal: AbortSignal.timeout(60_000) });
if (!response.ok) throw new Error(`${source}: HTTP ${response.status}`);
const bytes = Buffer.from(await response.arrayBuffer());
const text = bytes.toString('utf8');
for (const marker of ['subject to the terms of the Mozilla Public', 'https://mozilla.org/MPL/2.0/','// ===BEGIN ICANN DOMAINS===', '// ===END ICANN DOMAINS===']) {
  if (!text.includes(marker)) throw new Error(`${source} lacks "${marker}"; nothing was written.`);
}
const sha256 = createHash('sha256').update(bytes).digest('hex');
const previous: { commit: string } = JSON.parse(readFileSync(record, 'utf8'));
writeFileSync(new URL('../data/public_suffix_list.dat', import.meta.url), bytes);
writeFileSync(record, `${JSON.stringify({ repository: 'https://github.com/publicsuffix/list', commit, path: 'public_suffix_list.dat', sha256, license: 'MPL-2.0' }, null, 2)}\n`);
writeFileSync(notices, readFileSync(notices, 'utf8').replaceAll(previous.commit, commit));
console.log(`public_suffix_list.dat ${commit} sha256 ${sha256}`);
