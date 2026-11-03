// Metric mapping and severity adapted from every-app/open-seo@89e5a00717cdf049b7c2b4e29646edb3a7d4995b
// src/server/lib/lighthouseStoredPayload.ts (MIT); see THIRD_PARTY_NOTICES.md.
// Local Lighthouse 13.6.0 report contract: GoogleChrome/lighthouse@edc407d72179bbc4d4de8a40ef0311ca87dff89c.

const categories = ['performance', 'accessibility', 'best-practices', 'seo'] as const;
export type LighthouseCategory = typeof categories[number];
export type LighthouseCheckState = 'passed' | 'failed' | 'manual' | 'informative' | 'notApplicable' | 'error' | 'unknown';
export interface LighthouseMetric {
  readonly score: number | null;
  readonly numericValue: number | null;
  readonly displayValue: string | null;
}
export interface LighthouseCheck {
  readonly category: LighthouseCategory;
  readonly auditKey: string;
  readonly title: string;
  readonly description: string;
  readonly score: number | null;
  readonly scoreDisplayMode: string | null;
  readonly state: LighthouseCheckState;
  readonly displayValue: string | null;
  readonly impactMs: number | null;
  readonly impactBytes: number | null;
  readonly severity: 'critical' | 'warning' | 'info';
  readonly items: readonly string[];
}
const metricIds = {
  firstContentfulPaint: 'first-contentful-paint', largestContentfulPaint: 'largest-contentful-paint',
  totalBlockingTime: 'total-blocking-time', cumulativeLayoutShift: 'cumulative-layout-shift',
  speedIndex: 'speed-index', timeToInteractive: 'interactive',
  interactionToNextPaint: 'interaction-to-next-paint', serverResponseTime: 'server-response-time',
} as const;
export interface LighthouseCoverage {
  complete: boolean;
  missingCategories: LighthouseCategory[];
  /** Includes optional INP and legacy metrics; only missing core navigation metrics imply partial coverage. */
  missingMetrics: string[];
  invalidValues: number;
  missingAuditRefs: number;
  droppedChecks: number;
  duplicateRefs: number;
  droppedItems: number;
  omittedDetailFields: number;
  truncatedTexts: number;
  droppedWarnings: number;
  auditErrors: number;
}
export interface NormalizedLighthouseReport {
  readonly source: 'local-lighthouse';
  readonly requestedUrl: string;
  readonly mainDocumentUrl: string;
  readonly finalDisplayedUrl: string;
  readonly fetchTime: string;
  readonly lighthouseVersion: '13.6.0';
  readonly formFactor: 'mobile' | 'desktop';
  readonly status: 'complete' | 'partial' | 'failed';
  readonly runtimeError: { readonly code: string; readonly message: string } | null;
  readonly scores: Readonly<Record<LighthouseCategory, number | null>>;
  readonly metrics: Readonly<Record<keyof typeof metricIds, LighthouseMetric>>;
  readonly checks: readonly LighthouseCheck[];
  readonly warnings: readonly string[];
  readonly coverage: Readonly<LighthouseCoverage>;
}

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function reportUrl(value: unknown, removeFragment = false): string | null {
  if (typeof value !== 'string' || value.length === 0 || value.length > 2048) return null;
  const url = URL.parse(value);
  if (!url || !['http:', 'https:'].includes(url.protocol) || url.username || url.password) return null;
  if (removeFragment) url.hash = '';
  return url.href.length <= 2048 ? url.href : null;
}

function finiteNonnegative(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : null;
}

function score(value: unknown): number | null {
  const number = finiteNonnegative(value);
  return number !== null && number <= 1 ? number : null;
}

function severity(value: number | null, ms: number | null, bytes: number | null): LighthouseCheck['severity'] {
  if ((ms ?? 0) >= 300 || (bytes ?? 0) >= 150_000 || (value !== null && value < 0.5)) return 'critical';
  if ((ms ?? 0) >= 100 || (bytes ?? 0) >= 50_000 || (value !== null && value < 0.9)) return 'warning';
  return 'info';
}

const displayModes = new Set(['numeric', 'binary', 'metricSavings', 'manual', 'informative', 'notApplicable', 'error']);
const scalarDetailFields = ['url', 'source', 'nodeLabel', 'label', 'value', 'totalBytes', 'wastedBytes', 'wastedMs'];
// Screenshot and debugging payloads are intentionally excluded even if referenced by a category.
const excludedAuditIds = new Set(['screenshot-thumbnails', 'final-screenshot', 'script-treemap-data']);
const coreMetrics = new Set(['firstContentfulPaint', 'largestContentfulPaint', 'totalBlockingTime', 'cumulativeLayoutShift', 'speedIndex']);

/** Pure report projection, not URL authorization or permission to make a network request. */
export function normalizeLighthouseReport(raw: unknown, expectedUrl: string): NormalizedLighthouseReport | null {
  try {
    if (!record(raw) || raw.gatherMode !== 'navigation' || raw.lighthouseVersion !== '13.6.0') return null;
    const requestedUrl = reportUrl(raw.requestedUrl, true);
    if (!requestedUrl || requestedUrl !== reportUrl(expectedUrl, true)) return null;
    const mainDocumentUrl = reportUrl(raw.mainDocumentUrl ?? raw.finalUrl);
    const finalDisplayedUrl = reportUrl(raw.finalDisplayedUrl);
    if (!mainDocumentUrl || !finalDisplayedUrl || !record(raw.configSettings)) return null;
    const formFactor = raw.configSettings.formFactor;
    if (formFactor !== 'mobile' && formFactor !== 'desktop') return null;
    if (typeof raw.fetchTime !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(raw.fetchTime)) return null;
    const date = new Date(raw.fetchTime);
    const canonicalTime = raw.fetchTime.includes('.') ? raw.fetchTime : raw.fetchTime.replace('Z', '.000Z');
    if (!Number.isFinite(date.getTime()) || date.toISOString() !== canonicalTime) return null;
    if (!record(raw.audits) || !record(raw.categories)) return null;
    const audits = raw.audits;
    const coverage: LighthouseCoverage = {
      complete: false, missingCategories: [], missingMetrics: [], invalidValues: 0, missingAuditRefs: 0,
      droppedChecks: 0, duplicateRefs: 0, droppedItems: 0, omittedDetailFields: 0,
      truncatedTexts: 0, droppedWarnings: 0, auditErrors: 0,
    };
    const text = (value: unknown, limit: number): string | null => {
      if (typeof value !== 'string') return null;
      if (value.length > limit) coverage.truncatedTexts++;
      return value.slice(0, limit).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '');
    };
    const runtimeError = raw.runtimeError == null ? null : {
      code: text(record(raw.runtimeError) ? raw.runtimeError.code : null, 512) ?? 'UNKNOWN_ERROR',
      message: text(record(raw.runtimeError) ? raw.runtimeError.message : null, 512) ?? 'Lighthouse reported a runtime error.',
    };
    const readScore = (value: unknown): number | null => {
      const result = score(value);
      if (value != null && result === null) coverage.invalidValues++;
      return result;
    };
    const readNumber = (value: unknown): number | null => {
      const result = finiteNonnegative(value);
      if (value != null && result === null) coverage.invalidValues++;
      return result;
    };
    const metrics = {} as Record<keyof typeof metricIds, LighthouseMetric>;
    for (const [key, id] of Object.entries(metricIds) as [keyof typeof metricIds, string][]) {
      const audit = record(audits[id]) ? audits[id] : null;
      const error = !audit || !['numeric', 'binary', 'metricSavings'].includes(String(audit.scoreDisplayMode))
        || audit.errorMessage != null || runtimeError !== null;
      const numericValue = error ? null : readNumber(audit.numericValue);
      const metricScore = error ? null : readScore(audit.score);
      if (numericValue === null) coverage.missingMetrics.push(key);
      if (audit && metricScore === null && coreMetrics.has(key)) coverage.invalidValues++;
      metrics[key] = {
        score: metricScore, numericValue,
        displayValue: error ? null : text(audit.displayValue, 512),
      };
    }
    const scores = {} as Record<LighthouseCategory, number | null>;
    const checks: LighthouseCheck[] = [];
    for (const category of categories) {
      const data = record(raw.categories[category]) ? raw.categories[category] : null;
      const categoryScore = data ? readScore(data.score) : null;
      scores[category] = runtimeError || categoryScore === null ? null : Math.round(categoryScore * 100);
      if (categoryScore === null) coverage.missingCategories.push(category);
      const refs = data?.auditRefs;
      if (!Array.isArray(refs) || refs.length === 0) { coverage.missingAuditRefs++; continue; }
      const seen = new Set<string>();
      coverage.droppedChecks += Math.max(0, refs.length - 300);
      for (const ref of refs.slice(0, 300)) {
        const id = record(ref) ? ref.id : null;
        if (typeof id !== 'string' || !/^[a-z0-9][a-z0-9-]{0,127}$/.test(id)) { coverage.droppedChecks++; continue; }
        if (seen.has(id)) { coverage.duplicateRefs++; continue; }
        seen.add(id);
        const audit = audits[id];
        if (checks.length >= 300 || excludedAuditIds.has(id) || !record(audit) || (audit.id != null && audit.id !== id)) {
          coverage.droppedChecks++;
          continue;
        }
        const mode = typeof audit.scoreDisplayMode === 'string' && displayModes.has(audit.scoreDisplayMode) ? audit.scoreDisplayMode : null;
        const failedAudit = mode === 'error' || audit.errorMessage != null;
        const rawScore = readScore(audit.score);
        const scored = mode === 'numeric' || mode === 'binary' || mode === 'metricSavings';
        const auditScore = failedAudit || !scored || runtimeError ? null : rawScore;
        const state: LighthouseCheckState = failedAudit ? 'error'
          : mode === 'manual' || mode === 'informative' || mode === 'notApplicable' ? mode
          : auditScore === null ? 'unknown' : auditScore === 1 ? 'passed' : 'failed';
        if (failedAudit) coverage.auditErrors++;
        if (mode === null || state === 'unknown') coverage.invalidValues++;
        const details = record(audit.details) ? audit.details : null;
        if (audit.details != null && details === null) coverage.omittedDetailFields++;
        if (details && Object.keys(details).some(field => !['type', 'headings', 'items', 'overallSavingsMs', 'overallSavingsBytes'].includes(field))) {
          coverage.omittedDetailFields++;
        }
        const impactMs = readNumber(details?.overallSavingsMs);
        const impactBytes = readNumber(details?.overallSavingsBytes);
        const rawItems = details?.items;
        const items: string[] = [];
        const itemList = Array.isArray(rawItems) ? rawItems : record(rawItems) ? [rawItems] : [];
        if (rawItems != null && itemList.length === 0 && !Array.isArray(rawItems)) coverage.droppedItems++;
        coverage.droppedItems += Math.max(0, itemList.length - 10);
        for (const item of itemList.slice(0, 10)) {
          if (!record(item)) { coverage.droppedItems++; continue; }
          const parts: string[] = [];
          for (const field of scalarDetailFields) {
            const value = item[field];
            if (value == null) continue;
            if (typeof value === 'string') parts.push(`${field}: ${text(value, 512)}`);
            else if (typeof value === 'number' && Number.isFinite(value)) parts.push(`${field}: ${value}`);
            else if (typeof value === 'boolean') parts.push(`${field}: ${value}`);
            else coverage.omittedDetailFields++;
          }
          // Flag unrepresented node objects, HTML snippets and any unknown fields without copying them.
          if (Object.keys(item).some(field => !scalarDetailFields.includes(field))) coverage.omittedDetailFields++;
          if (parts.length) items.push(text(parts.join('; '), 512)!);
          else coverage.droppedItems++;
        }
        checks.push({
          category, auditKey: id, title: text(audit.title, 512) ?? id,
          description: text(audit.description, 2048) ?? '', score: auditScore, scoreDisplayMode: mode, state,
          displayValue: text(audit.displayValue, 512), impactMs, impactBytes,
          severity: severity(auditScore, impactMs, impactBytes), items,
        });
      }
    }
    const warnings: string[] = [];
    if (Array.isArray(raw.runWarnings)) {
      coverage.droppedWarnings += Math.max(0, raw.runWarnings.length - 20);
      for (const warning of raw.runWarnings.slice(0, 20)) {
        const value = text(warning, 512);
        if (value === null) coverage.droppedWarnings++; else warnings.push(value);
      }
    } else if (raw.runWarnings != null) coverage.droppedWarnings++;
    coverage.complete = runtimeError === null && warnings.length === 0 && coverage.missingCategories.length === 0
      && !coverage.missingMetrics.some(key => coreMetrics.has(key)) && Object.entries(coverage).every(([key, value]) =>
        key === 'complete' || Array.isArray(value) || value === 0);
    return {
      source: 'local-lighthouse', requestedUrl, mainDocumentUrl, finalDisplayedUrl, fetchTime: date.toISOString(),
      lighthouseVersion: '13.6.0', formFactor, status: runtimeError ? 'failed' : coverage.complete ? 'complete' : 'partial',
      runtimeError, scores, metrics, checks, warnings, coverage,
    };
  } catch {
    // Accessors and proxies in non-JSON inputs cannot escape validation with raw exception data.
    return null;
  }
}
