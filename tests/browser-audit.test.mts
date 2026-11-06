import './fixtures/browser-audit/controller.mts';
import './fixtures/browser-audit/capsule.mts';
import './fixtures/browser-audit/egress-proxy.mts';
import './fixtures/browser-audit/egress-limits.mts';

type AuditEqual<A,B> = (<T>() => T extends A ? 1 : 2) extends (<T>() => T extends B ? 1 : 2) ? true : false;
type AuditAssert<T extends true> = T;

import {createBrowserAuditControl,createPublicEgressProxy,type BrowserControlOptions,type PublicEgressOptions,type ObserverTransport} from '@ten98/runtime/browser-audit';
export const controlFactory: (options: BrowserControlOptions) => ReturnType<typeof createBrowserAuditControl> = createBrowserAuditControl;
export const egressFactory: (options: PublicEgressOptions) => ReturnType<typeof createPublicEgressProxy> = createPublicEgressProxy;
export type ObserverApi = AuditAssert<AuditEqual<Awaited<ReturnType<Awaited<ReturnType<typeof createBrowserAuditControl>>['createObserverTransport']>>,ObserverTransport>>;

import assert from 'node:assert/strict';
import test from 'node:test';
import {readFileSync,existsSync} from 'node:fs';
import * as browserAudit from '@ten98/runtime/browser-audit';
test('the browser-audit catalogue entry binds actual server exports and package files',()=>{
 const catalog=JSON.parse(readFileSync(new URL('../features/catalog.json',import.meta.url),'utf8'));
 const entry=catalog.portableImports.browserAudit;
 assert.deepEqual(Object.keys(browserAudit).sort(),entry.exports.slice().sort());
 for(const file of [...entry.entrypoints,...entry.tests]) assert(existsSync(new URL('../'+file,import.meta.url)),file);
});
