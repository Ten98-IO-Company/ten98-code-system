import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync, copyFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { collectReleaseIdentity } from '../check.mjs';

function fixture(t, version = '1.2.3') {
  const directory = mkdtempSync(join(tmpdir(), 'ten98-release-'));
  t.after(() => {
    assert.equal(resolve(directory).startsWith(join(tmpdir(), 'ten98-release-')), true);
    rmSync(directory, { recursive: true, force: true });
  });
  const run = (command, args) => {
    const result = spawnSync(command, args, { cwd: directory, encoding: 'utf8', timeout: 15_000, windowsHide: true });
    assert.equal(result.status, 0, result.error?.message ?? result.stderr);
    return result.stdout.trim();
  };
  const git = (...args) => run('git', ['-c', 'user.name=Release Test', '-c', 'user.email=release@example.invalid', '-c', 'commit.gpgsign=false', '-c', 'tag.gpgsign=false', ...args]);
  const write = (name, data) => writeFileSync(join(directory, name), JSON.stringify(data));
  const manifest = { name: '@ten98/fixture', version };
  const lock = { name: manifest.name, version, lockfileVersion: 3, packages: { '': { ...manifest } } };
  git('init', '--quiet');
  write('package.json', manifest); write('package-lock.json', lock);
  const commit = () => { git('add', '.'); git('commit', '--quiet', '-m', 'Fixture'); return git('rev-parse', 'HEAD'); };
  const options = { tag: `v${version}`, commit: commit() };
  git('tag', '-a', options.tag, '-m', 'Qualified fixture');
  const check = extra => collectReleaseIdentity(directory, { ...options, ...extra });
  const pack = (identity = manifest) => {
    mkdirSync(join(directory, 'package'), { recursive: true });
    write('package/package.json', identity);
    const archive = join(directory, `ten98-fixture-${version}.tgz`);
    run('tar', ['-czf', archive, 'package/package.json']);
    return archive;
  };
  return { directory, run, git, write, manifest, lock, commit, options, check, pack };
}

test('collects real tag, committed package/lock and actual archive bytes', t => {
  const f = fixture(t), tagObject = f.git('rev-parse', f.options.tag);
  f.write('package.json', { ...f.manifest, version: '99.0.0' });
  const archive = f.pack(), evidence = f.check({ tagObject, archive });
  assert.equal(evidence.version, '1.2.3');
  assert.equal(evidence.commit, f.options.commit);
  assert.equal(evidence.archive.bytes, readFileSync(archive).length);
  assert.equal(evidence.archive.priorBytesVerified, false);
  assert.equal(f.check({ archive, archiveSha256: evidence.archive.sha256 }).archive.priorBytesVerified, true);
  assert.match(f.check().tagHistory, /unverified/u);
  f.write('push.json', { ref: 'refs/tags/v1.2.3', created: true, deleted: false, forced: false, before: '0'.repeat(40), after: f.options.commit });
  assert.equal(f.check({ event: join(f.directory, 'push.json') }).tagHistory, 'new-tag push event');
});

test('rejects non-normal versions, lightweight tags and aliased annotations', t => {
  const f = fixture(t);
  for (const tag of ['v1.2.3-preview.1', 'v1.2.3+build', 'v01.2.3', '1.2.3']) assert.throws(() => f.check({ tag }), /normal/u);
  f.git('tag', '-d', f.options.tag); f.git('tag', f.options.tag);
  assert.throws(() => f.check(), /annotated/u);
  f.git('tag', '-a', 'different-name', '-m', 'Alias');
  f.git('update-ref', `refs/tags/${f.options.tag}`, f.git('rev-parse', 'different-name'));
  assert.throws(() => f.check(), /tag name/u);
});

test('rejects another checkout, moved tags, replaced annotations and tag-update events', t => {
  const f = fixture(t), tagObject = f.git('rev-parse', f.options.tag);
  f.git('tag', '-f', '-a', f.options.tag, '-m', 'Replacement annotation');
  assert.throws(() => f.check({ tagObject }), /moved|replaced/u);
  f.write('extra.json', { changed: true }); const changed = f.commit();
  assert.throws(() => f.check(), /qualified commit/u);
  f.git('tag', '-f', '-a', f.options.tag, '-m', 'Moved commit');
  assert.throws(() => f.check(), /qualified commit/u);
  assert.throws(() => f.check({ commit: changed, tagObject }), /moved|replaced/u);
  f.write('push.json', { ref: 'refs/tags/v1.2.3', created: false, deleted: false, forced: true, before: tagObject, after: changed });
  assert.throws(() => f.check({ commit: changed, event: join(f.directory, 'push.json') }), /new tag/u);
  f.write('push.json', { ref: 'refs/tags/v1.2.3', created: true, deleted: false, forced: false, before: '0'.repeat(40), after: '1'.repeat(40) });
  assert.throws(() => f.check({ commit: changed, event: join(f.directory, 'push.json') }), /new tag/u);
});

test('rejects committed package and both root lock identity mismatches', t => {
  const f = fixture(t);
  const retag = () => { f.options.commit = f.commit(); f.git('tag', '-f', '-a', f.options.tag, '-m', 'Mismatch fixture'); };
  f.write('package.json', { ...f.manifest, version: '1.2.4' }); retag();
  assert.throws(() => f.check(), /Committed package/u);
  f.write('package.json', f.manifest); f.write('package-lock.json', { ...f.lock, version: '1.2.4' }); retag();
  assert.throws(() => f.check(), /root lock/u);
  f.write('package-lock.json', { ...f.lock, packages: { '': { ...f.manifest, name: '@ten98/wrong' } } }); retag();
  assert.throws(() => f.check(), /root lock/u);
});

test('rejects archive filename, actual packed identity and retained-byte mismatches', t => {
  const f = fixture(t), archive = f.pack(), digest = f.check({ archive }).archive.sha256;
  const wrongName = join(f.directory, 'wrong.tgz'); copyFileSync(archive, wrongName);
  assert.throws(() => f.check({ archive: wrongName }), /filename/u);
  f.pack({ ...f.manifest, version: '1.2.4' });
  assert.throws(() => f.check({ archive }), /packed package/u);
  f.pack({ ...f.manifest, description: 'Changed bytes, same identity' });
  assert.throws(() => f.check({ archive, archiveSha256: digest }), /bytes differ/u);
  assert.throws(() => f.check({ archiveSha256: digest }), /needs an archive/u);
});
