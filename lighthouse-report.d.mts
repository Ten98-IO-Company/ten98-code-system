declare const categories: readonly ['performance', 'accessibility', 'best-practices', 'seo'];
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
declare const metricIds: {
    readonly firstContentfulPaint: 'first-contentful-paint';
    readonly largestContentfulPaint: 'largest-contentful-paint';
    readonly totalBlockingTime: 'total-blocking-time';
    readonly cumulativeLayoutShift: 'cumulative-layout-shift';
    readonly speedIndex: 'speed-index';
    readonly timeToInteractive: 'interactive';
    readonly interactionToNextPaint: 'interaction-to-next-paint';
    readonly serverResponseTime: 'server-response-time';
};
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
    readonly runtimeError: {
        readonly code: string;
        readonly message: string;
    } | null;
    readonly scores: Readonly<Record<LighthouseCategory, number | null>>;
    readonly metrics: Readonly<Record<keyof typeof metricIds, LighthouseMetric>>;
    readonly checks: readonly LighthouseCheck[];
    readonly warnings: readonly string[];
    readonly coverage: Readonly<LighthouseCoverage>;
}
/** Pure report projection, not URL authorization or permission to make a network request. */
export declare function normalizeLighthouseReport(raw: unknown, expectedUrl: string): NormalizedLighthouseReport | null;
export {};
