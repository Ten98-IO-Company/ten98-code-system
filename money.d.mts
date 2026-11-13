/** Minor-unit digits of a currency: 0 (JPY), 2 (AED, SAR, QAR, USD) or 3 (BHD, KWD, OMR). */
export type MoneyExponent = 0 | 2 | 3;
/**
 * How a result between two minor units is rounded. Every mode is symmetric in sign, so `-x` rounds to `-(round x)`:
 * `half-up` rounds a half away from zero, `half-even` rounds a half to the even unit, `down` truncates toward zero.
 */
export type MoneyRounding = 'half-up' | 'half-even' | 'down';
/** The smallest amount a PostgreSQL `bigint` (int8) column stores. */
export declare const MONEY_MIN: bigint;
/** The largest amount a PostgreSQL `bigint` (int8) column stores. */
export declare const MONEY_MAX: bigint;
/**
 * Throws RangeError unless `value` fits a PostgreSQL `bigint` column (`MONEY_MIN` to `MONEY_MAX`), and TypeError unless
 * it is a bigint. `parseMoney` applies it to every parsed amount; arithmetic does not bound its results, so call it on a
 * computed amount before persisting it.
 */
export declare function assertMoneyInRange(value: unknown): asserts value is bigint;
/**
 * Minor units from a decimal string: `parseMoney('12.5', 3) === 12500n`. More fraction digits than the exponent are
 * refused rather than rounded, so an entered amount is never silently changed, and an amount outside the PostgreSQL
 * `bigint` range is refused with a RangeError.
 */
export declare function parseMoney(text: string, exponent: MoneyExponent): bigint;
/** The canonical decimal string for minor units: `formatMoney(-5n, 3) === '-0.005'`. No grouping or currency sign. */
export declare function formatMoney(amount: bigint, exponent: MoneyExponent): string;
/** `a + b` for bigint minor units of one currency; the caller keeps currencies apart. */
export declare function addMoney(a: bigint, b: bigint): bigint;
/** `a - b` for bigint minor units of one currency. */
export declare function subtractMoney(a: bigint, b: bigint): bigint;
/** -1, 0 or 1 as `a` is below, equal to or above `b`; usable as an Array sort comparator. */
export declare function compareMoney(a: bigint, b: bigint): -1 | 0 | 1;
/** `amount × rate` in minor units of the amount's scale, for a decimal-string rate such as `'3.6725'`. */
export declare function multiplyMoney(amount: bigint, rate: string, rounding: MoneyRounding): bigint;
/** `amount × percent / 100`, for a decimal-string percentage such as VAT `'5'` or `'15'`. */
export declare function percentOfMoney(amount: bigint, percent: string, rounding: MoneyRounding): bigint;
/**
 * Splits `total` across non-negative bigint weights (at least one positive) by the largest-remainder method. The parts
 * always sum to `total`, a zero weight always receives 0n, leftover units go to the largest remainders with ties to
 * the earlier index, and a negative total splits as the exact negation of its positive split.
 */
export declare function allocateMoney(total: bigint, weights: readonly bigint[]): bigint[];
