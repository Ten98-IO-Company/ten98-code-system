import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import { normalizeLighthouseReport } from '../lighthouse-report.mjs';

const expectedUrl = 'https://example.com/path?a=1&a=2';
const metricIds = ['first-contentful-paint', 'largest-contentful-paint', 'total-blocking-time',
  'cumulative-layout-shift', 'speed-index', 'interactive', 'interaction-to-next-paint', 'server-response-time'];

function fixture() {
  return {
    gatherMode: 'navigation', lighthouseVersion: '13.6.0', requestedUrl: expectedUrl,
    mainDocumentUrl: 'https://example.com/redirected', finalUrl: 'https://example.com/legacy',
    finalDisplayedUrl: 'https://example.com/redirected#section', fetchTime: '2026-11-03T01:02:03.000Z',
    configSettings: { formFactor: 'mobile' }, runWarnings: [] as unknown[],
    categories: Object.fromEntries(['performance', 'accessibility', 'best-practices', 'seo'].map((id, i) =>
      [id, { score: i / 3, auditRefs: [{ id: 'test-check' }] }])),
    audits: {
      ...Object.fromEntries(metricIds.map((id, i) => [id, {
        id, score: i === 0 ? 0 : 1, numericValue: i, displayValue: `${i} ms`, scoreDisplayMode: 'numeric',
      }])),
      'test-check': { id: 'test-check', title: 'Review this check', description: 'Actionable description',
        score: 0, scoreDisplayMode: 'binary', details: { overallSavingsMs: 0, items: [{ url: 'https://example.com/a', wastedBytes: 0 }] } },
    } as Record<string, Record<string, unknown>>,
  };
}

test('normalizes local navigation identity, separate redirects, four scores and eight metrics including zero', () => {
  const raw = fixture();
  raw.requestedUrl = 'https://EXAMPLE.com:443/path?a=1&a=2#top';
  const result = normalizeLighthouseReport(raw, expectedUrl);
  assert.ok(result);
  assert.equal(result.status, 'complete');
  assert.equal(result.requestedUrl, expectedUrl);
  assert.equal(result.mainDocumentUrl, 'https://example.com/redirected');
  assert.equal(result.finalDisplayedUrl, 'https://example.com/redirected#section');
  assert.deepEqual(result.scores, { performance: 0, accessibility: 33, 'best-practices': 67, seo: 100 });
  assert.equal(Object.keys(result.metrics).length, 8);
  assert.deepEqual(result.metrics.firstContentfulPaint, { numericValue: 0, score: 0, displayValue: '0 ms' });
  assert.equal(result.checks[0].score, 0);
  assert.equal(result.checks[0].state, 'failed');
  assert.equal(result.checks[0].severity, 'critical');
  assert.match(result.checks[0].items[0], /wastedBytes: 0/);
  assert.equal(result.coverage.complete, true);
  assert.equal(normalizeLighthouseReport({ ...raw, mainDocumentUrl: undefined }, expectedUrl)?.mainDocumentUrl, raw.finalUrl);
});

test('rejects identity changes, unsafe URLs, unsupported reports and malformed dates', () => {
  const raw = fixture();
  for (const requestedUrl of ['https://example.com/path?a=2&a=1', 'https://example.com/path?a=1',
    'https://other.example/path?a=1&a=2', 'https://user:pass@example.com/path?a=1&a=2', 'file:///path', 'x'.repeat(2049)]) {
    assert.equal(normalizeLighthouseReport({ ...raw, requestedUrl }, expectedUrl), null, requestedUrl);
  }
  for (const fetchTime of ['2026-02-30T01:02:03.000Z', '2026-13-03T01:02:03.000Z', 'yesterday', '', 0]) {
    assert.equal(normalizeLighthouseReport({ ...raw, fetchTime }, expectedUrl), null, String(fetchTime));
  }
  for (const patch of [{ gatherMode: 'snapshot' }, { lighthouseVersion: '13.5.0' }, { mainDocumentUrl: 'javascript:alert(1)' },
    { finalDisplayedUrl: 'https://user@example.com/' }, { configSettings: { formFactor: 'tablet' } }, { audits: null }]) {
    assert.equal(normalizeLighthouseReport({ ...raw, ...patch }, expectedUrl), null);
  }
  assert.equal(normalizeLighthouseReport(raw, 'https://user@example.com/path?a=1&a=2'), null);
  assert.equal(normalizeLighthouseReport({ ...raw, fetchTime: '2026-11-03T01:02:03Z' }, expectedUrl)?.fetchTime, raw.fetchTime);
});

test('missing and nonfinite scores or values remain null; INP never inherits TBT', () => {
  const raw = fixture();
  delete raw.audits['interaction-to-next-paint'];
  raw.audits['total-blocking-time'].numericValue = 987;
  for (const invalid of [NaN, Infinity, -1, '0']) {
    raw.audits['first-contentful-paint'].numericValue = invalid;
    raw.audits['first-contentful-paint'].score = invalid;
    raw.audits['test-check'].score = invalid;
    raw.categories.performance.score = invalid as number;
    const result = normalizeLighthouseReport(raw, expectedUrl)!;
    assert.equal(result.metrics.firstContentfulPaint.numericValue, null);
    assert.equal(result.metrics.firstContentfulPaint.score, null);
    assert.equal(result.metrics.interactionToNextPaint.numericValue, null);
    assert.equal(result.scores.performance, null);
    assert.equal(result.checks[0].state, 'unknown');
    assert.equal(result.status, 'partial');
    assert.ok(result.coverage.invalidValues > 0);
  }
  raw.audits['test-check'].score = 1.1;
  assert.equal(normalizeLighthouseReport(raw, expectedUrl)!.checks[0].score, null);
});

test('optional lab metrics remain explicitly missing without downgrading a complete core report', () => {
  const raw = fixture();
  for (const id of ['interactive', 'interaction-to-next-paint', 'server-response-time']) delete raw.audits[id];
  const result = normalizeLighthouseReport(raw, expectedUrl)!;
  assert.equal(result.status, 'complete');
  assert.deepEqual(result.coverage.missingMetrics, ['timeToInteractive', 'interactionToNextPaint', 'serverResponseTime']);
  assert.equal(result.metrics.interactionToNextPaint.numericValue, null);
  delete raw.audits['largest-contentful-paint'];
  assert.equal(normalizeLighthouseReport(raw, expectedUrl)!.status, 'partial');
});

test('missing core metric scores and empty category references cannot claim complete coverage', () => {
  const raw = fixture();
  delete raw.audits['first-contentful-paint'].score;
  assert.equal(normalizeLighthouseReport(raw, expectedUrl)!.status, 'partial');
  raw.audits['first-contentful-paint'].score = 1;
  raw.categories.seo.auditRefs = [];
  const result = normalizeLighthouseReport(raw, expectedUrl)!;
  assert.equal(result.status, 'partial');
  assert.equal(result.coverage.missingAuditRefs, 1);
});

test('manual, informative, not applicable and errors cannot become passes, including contradictory scores', () => {
  const raw = fixture();
  for (const mode of ['manual', 'informative', 'notApplicable', 'error']) {
    raw.audits['test-check'].scoreDisplayMode = mode;
    raw.audits['test-check'].score = 1;
    const result = normalizeLighthouseReport(raw, expectedUrl)!;
    assert.equal(result.checks[0].state, mode);
    assert.equal(result.checks[0].score, null);
  }
  raw.audits['test-check'].scoreDisplayMode = 'binary';
  raw.audits['test-check'].errorMessage = 'Unable to run';
  assert.equal(normalizeLighthouseReport(raw, expectedUrl)!.checks[0].state, 'error');
  raw.audits['first-contentful-paint'].scoreDisplayMode = 'error';
  const result = normalizeLighthouseReport({ ...raw, runtimeError: { code: 'NO_FCP', message: 'No paint', stack: 'SECRET STACK' } }, expectedUrl)!;
  assert.equal(result.status, 'failed');
  assert.equal(result.metrics.firstContentfulPaint.numericValue, null);
  assert.ok(Object.values(result.scores).every(value => value === null));
  assert.ok(result.checks.every(check => check.state !== 'passed'));
  assert.deepEqual(result.runtimeError, { code: 'NO_FCP', message: 'No paint' });
  assert.ok(result.coverage.auditErrors > 0);
});

test('deduplicates by category and id, bounds collections and text, and exposes dropped coverage', () => {
  const raw = fixture();
  raw.audits['test-check'].title = 't'.repeat(700);
  raw.audits['test-check'].description = 'd'.repeat(3000);
  raw.audits['test-check'].details = { items: Array.from({ length: 15 }, () => ({ label: 'l'.repeat(600),
    node: { snippet: '<script>SECRET</script>' }, value: { nested: 'SECRET' }, unknown: 'SECRET' })) };
  raw.categories.performance.auditRefs = [{ id: 'test-check' }, { id: 'test-check' }, { id: 'missing-check' }, { id: '' }];
  raw.runWarnings = Array.from({ length: 25 }, () => 'w'.repeat(700));
  const result = normalizeLighthouseReport(raw, expectedUrl)!;
  assert.equal(result.checks.length, 4);
  assert.equal(result.coverage.duplicateRefs, 1);
  assert.equal(result.coverage.droppedChecks, 2);
  assert.ok(result.coverage.droppedItems > 0);
  assert.ok(result.coverage.omittedDetailFields > 0);
  assert.ok(result.coverage.truncatedTexts > 0);
  assert.equal(result.warnings.length, 20);
  assert.equal(result.coverage.droppedWarnings, 5);
  assert.equal(result.status, 'partial');
  for (const check of result.checks) {
    assert.equal(check.title.length, 512);
    assert.equal(check.description.length, 2048);
    assert.equal(check.items.length, 10);
    assert.ok(check.items.every(item => item.length <= 512));
  }
  assert.ok(!JSON.stringify(result).includes('SECRET'));
  raw.categories.performance.auditRefs = Array.from({ length: 1000 }, (_, i) => ({ id: `check-${i}` }));
  for (let i = 0; i < 1000; i++) raw.audits[`check-${i}`] = { ...raw.audits['test-check'], id: `check-${i}` };
  const bounded = normalizeLighthouseReport(raw, expectedUrl)!;
  assert.equal(bounded.checks.length, 300);
  assert.equal(bounded.coverage.droppedChecks, 703);
});

test('retains numeric failures, reference severity thresholds and partial category coverage without arbitrary metadata', () => {
  const raw = fixture();
  raw.audits['test-check'].scoreDisplayMode = 'numeric';
  raw.audits['test-check'].score = 0.95;
  raw.audits['test-check'].details = { overallSavingsMs: 100, overallSavingsBytes: 0 };
  delete raw.categories.seo;
  const result = normalizeLighthouseReport({ ...raw, cost: 5, budget: 7, rawHtml: 'SECRET', screenshots: 'SECRET' }, expectedUrl)!;
  assert.equal(result.checks[0].state, 'failed');
  assert.equal(result.checks[0].severity, 'warning');
  assert.deepEqual(result.coverage.missingCategories, ['seo']);
  assert.equal(result.scores.seo, null);
  assert.equal(result.coverage.missingAuditRefs, 1);
  assert.doesNotMatch(JSON.stringify(result), /SECRET|"cost"|"budget"|"screenshots"/);
  assert.equal(normalizeLighthouseReport({ get gatherMode() { throw new Error('SECRET'); } }, expectedUrl), null);
});

test('identity regression detects removal of the requested URL binding', async () => {
  const source = await readFile(new URL('../lighthouse-report.mjs', import.meta.url), 'utf8');
  const mutant = source.replace('requestedUrl !== reportUrl(expectedUrl, true)', 'false');
  assert.notEqual(mutant, source);
  const module = await import(`data:text/javascript;base64,${Buffer.from(mutant).toString('base64')}`);
  const wrongIdentity = { ...fixture(), requestedUrl: 'https://unrelated.example/' };
  assert.equal(normalizeLighthouseReport(wrongIdentity, expectedUrl), null);
  assert.notEqual(module.normalizeLighthouseReport(wrongIdentity, expectedUrl), null);
});
