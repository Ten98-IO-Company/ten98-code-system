import * as current from '../index.mjs';
import type * as previous from './fixtures/runtime-0.1.4.mjs';
type Equal<A, B> = (<T>() => T extends A ? 1 : 2) extends (<T>() => T extends B ? 1 : 2) ? true : false;
type Assert<T extends true> = T;
// Additions are allowed; every value exported by 0.1.4 must remain assignable.
export type PublicValuesCompatible = Assert<typeof current extends typeof previous ? true : false>;
export type PublicRoleUnchanged = Assert<Equal<current.WorkspaceRole, previous.WorkspaceRole>>;
// A structural stand-in for pg's Client.query: generic rows bounded by QueryResultRow.
interface PgLikeClient { query<R extends { [column: string]: any } = any>(text: string, values?: unknown[]): Promise<{ rows: R[]; rowCount: number | null }> }
declare const pgClient: PgLikeClient;
export const pgClientIsMigrationClient: current.MigrationClient = pgClient;

// Node's current and future usage union can be wider than the DOM CryptoKey usage union.
declare const nodeShopifyKey: Omit<CryptoKey, 'usages'> & { usages: ('verify' | 'encapsulateBits')[] };
declare const browserShopifyKey: CryptoKey;
export const nodeShopifyVerification = current.verifyShopifyCrawlerAccess({}, nodeShopifyKey);
export const browserShopifyVerification = current.verifyShopifyCrawlerAccess({}, browserShopifyKey);

export const resolveNetworkHostType: (hostname: string, signal: AbortSignal) => Promise<current.NetworkAddress[]> = current.resolveNetworkHost;
export const normalizeLighthouseReportType: (raw: unknown, expectedUrl: string) => current.NormalizedLighthouseReport | null = current.normalizeLighthouseReport;

export const readChatType: (message: unknown, finishReason: unknown, options: current.OpenRouterChatOptionsV1) => current.OpenRouterAssistantResultV1 = current.readOpenRouterAssistantMessageV1;
export const validateChatHistoryType: (history: unknown, options: current.OpenRouterChatOptionsV1) => current.OpenRouterChatMessageV1[] = current.validateOpenRouterToolHistoryV1;
export const chatOptions: current.OpenRouterChatOptionsV1 = { allowedToolNames: ['read_evidence'], maxContextBytes: 131072, maxArgumentBytes: 8192, maxMessageBytes: 2097152 };
export const nativeToolResult: current.OpenRouterChatMessageV1 = { role: 'tool', tool_call_id: 'call_1', content: '{}' };

export const multiplyMoneyType: (amount: bigint, rate: string, rounding: current.MoneyRounding) => bigint = current.multiplyMoney;
export const allocateMoneyType: (total: bigint, weights: readonly bigint[]) => bigint[] = current.allocateMoney;
export const bahrainiDinar: current.MoneyExponent = 3;
