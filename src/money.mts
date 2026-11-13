// Exact money arithmetic on bigint minor units (fils, cents, yen). Nothing here converts an amount to a Number or uses
// floating point, so results never depend on binary rounding. No Node built-ins: the browser entry re-exports it.
// Apps keep currency selection, display locale, ledger postings and which rounding mode a rule requires.

/** Minor-unit digits of a currency: 0 (JPY), 2 (AED, SAR, QAR, USD) or 3 (BHD, KWD, OMR). */
export type MoneyExponent = 0 | 2 | 3;

/**
 * How a result between two minor units is rounded. Every mode is symmetric in sign, so `-x` rounds to `-(round x)`:
 * `half-up` rounds a half away from zero, `half-even` rounds a half to the even unit, `down` truncates toward zero.
 */
export type MoneyRounding = 'half-up' | 'half-even' | 'down';

/** The smallest amount a PostgreSQL `bigint` (int8) column stores. */
export const MONEY_MIN: bigint = -(2n ** 63n);
/** The largest amount a PostgreSQL `bigint` (int8) column stores. */
export const MONEY_MAX: bigint = 2n ** 63n - 1n;

// Bounds parsing work on untrusted text; rates may need more digits than the int8 range, amounts are bounded below.
const MAX_TEXT = 64;
const DECIMAL = /^(-?)(\d+)(?:\.(\d+))?$/u;
const ROUNDING: readonly string[] = ['half-up', 'half-even', 'down'] satisfies MoneyRounding[];

function amountOf(value: unknown, label: string): bigint {
  if (typeof value !== 'bigint') throw new TypeError(`${label} must be a bigint amount in minor units.`);
  return value;
}

function exponentOf(value: unknown): MoneyExponent {
  if (value !== 0 && value !== 2 && value !== 3) throw new RangeError('Currency exponent must be 0, 2 or 3.');
  return value;
}

function roundingOf(value: unknown): MoneyRounding {
  if (typeof value !== 'string' || !ROUNDING.includes(value)) throw new TypeError(`Rounding must be one of ${ROUNDING.join(', ')}.`);
  return value as MoneyRounding;
}

// A plain decimal such as "12", "-0.125" or "15.0000": no exponent notation, grouping, spaces or leading plus.
function decimalOf(text: unknown, label: string): { units: bigint; scale: number } {
  const match = typeof text === 'string' && text.length <= MAX_TEXT ? DECIMAL.exec(text) : null;
  if (!match) throw new TypeError(`${label} must be a plain decimal string of at most ${MAX_TEXT} characters.`);
  const [, sign, whole, fraction = ''] = match;
  const units = BigInt(whole + fraction);
  return { units: sign ? -units : units, scale: fraction.length };
}

// The exact quotient numerator / denominator (denominator > 0) rounded to an integer by the given mode.
function divideRounded(numerator: bigint, denominator: bigint, rounding: MoneyRounding): bigint {
  const quotient = numerator / denominator, remainder = numerator % denominator;
  if (remainder === 0n || rounding === 'down') return quotient;
  const twice = (remainder < 0n ? -remainder : remainder) * 2n;
  const away = twice > denominator || twice === denominator && (rounding === 'half-up' || quotient % 2n !== 0n);
  return away ? quotient + (numerator < 0n ? -1n : 1n) : quotient;
}

/**
 * Throws RangeError unless `value` fits a PostgreSQL `bigint` column (`MONEY_MIN` to `MONEY_MAX`), and TypeError unless
 * it is a bigint. `parseMoney` applies it to every parsed amount; arithmetic does not bound its results, so call it on a
 * computed amount before persisting it.
 */
export function assertMoneyInRange(value: unknown): asserts value is bigint {
  const amount = amountOf(value, 'Amount');
  if (amount < MONEY_MIN || amount > MONEY_MAX) throw new RangeError('Amount is outside the PostgreSQL bigint range.');
}

/**
 * Minor units from a decimal string: `parseMoney('12.5', 3) === 12500n`. More fraction digits than the exponent are
 * refused rather than rounded, so an entered amount is never silently changed, and an amount outside the PostgreSQL
 * `bigint` range is refused with a RangeError.
 */
export function parseMoney(text: string, exponent: MoneyExponent): bigint {
  const digits = exponentOf(exponent), { units, scale } = decimalOf(text, 'Amount');
  if (scale > digits) throw new RangeError(`Amount has more than ${digits} fraction digits.`);
  const amount = units * 10n ** BigInt(digits - scale);
  assertMoneyInRange(amount);
  return amount;
}

/** The canonical decimal string for minor units: `formatMoney(-5n, 3) === '-0.005'`. No grouping or currency sign. */
export function formatMoney(amount: bigint, exponent: MoneyExponent): string {
  const value = amountOf(amount, 'Amount'), digits = exponentOf(exponent);
  const magnitude = (value < 0n ? -value : value).toString().padStart(digits + 1, '0');
  const split = magnitude.length - digits;
  return `${value < 0n ? '-' : ''}${magnitude.slice(0, split)}${digits ? `.${magnitude.slice(split)}` : ''}`;
}

/** `a + b` for bigint minor units of one currency; the caller keeps currencies apart. */
export function addMoney(a: bigint, b: bigint): bigint {
  return amountOf(a, 'First amount') + amountOf(b, 'Second amount');
}

/** `a - b` for bigint minor units of one currency. */
export function subtractMoney(a: bigint, b: bigint): bigint {
  return amountOf(a, 'First amount') - amountOf(b, 'Second amount');
}

/** -1, 0 or 1 as `a` is below, equal to or above `b`; usable as an Array sort comparator. */
export function compareMoney(a: bigint, b: bigint): -1 | 0 | 1 {
  const left = amountOf(a, 'First amount'), right = amountOf(b, 'Second amount');
  return left < right ? -1 : left > right ? 1 : 0;
}

/** `amount × rate` in minor units of the amount's scale, for a decimal-string rate such as `'3.6725'`. */
export function multiplyMoney(amount: bigint, rate: string, rounding: MoneyRounding): bigint {
  const value = amountOf(amount, 'Amount'), mode = roundingOf(rounding), { units, scale } = decimalOf(rate, 'Rate');
  return divideRounded(value * units, 10n ** BigInt(scale), mode);
}

/** `amount × percent / 100`, for a decimal-string percentage such as VAT `'5'` or `'15'`. */
export function percentOfMoney(amount: bigint, percent: string, rounding: MoneyRounding): bigint {
  const value = amountOf(amount, 'Amount'), mode = roundingOf(rounding), { units, scale } = decimalOf(percent, 'Percent');
  return divideRounded(value * units, 10n ** BigInt(scale + 2), mode);
}

/**
 * Splits `total` across non-negative bigint weights (at least one positive) by the largest-remainder method. The parts
 * always sum to `total`, a zero weight always receives 0n, leftover units go to the largest remainders with ties to
 * the earlier index, and a negative total splits as the exact negation of its positive split.
 */
export function allocateMoney(total: bigint, weights: readonly bigint[]): bigint[] {
  const value = amountOf(total, 'Total');
  // An index loop, not some/map/reduce, which skip the holes of a sparse array such as [, 1n].
  let valid = Array.isArray(weights) && weights.length > 0;
  for (let index = 0; valid && index < weights.length; index++) valid = typeof weights[index] === 'bigint' && weights[index]! >= 0n;
  if (!valid) throw new TypeError('Weights must be a non-empty list of non-negative bigint values.');
  const sum = weights.reduce((accumulated, weight) => accumulated + weight, 0n);
  if (sum === 0n) throw new RangeError('At least one weight must be positive.');
  const magnitude = value < 0n ? -value : value;
  const parts = weights.map(weight => magnitude * weight / sum);
  // Each remainder is below sum, so fewer than leftover + 1 parts with a nonzero remainder can ever be skipped.
  let leftover = magnitude - parts.reduce((accumulated, part) => accumulated + part, 0n);
  const order = weights.map((weight, index) => ({ index, remainder: magnitude * weight % sum }))
    .sort((a, b) => a.remainder === b.remainder ? a.index - b.index : a.remainder > b.remainder ? -1 : 1);
  for (const { index } of order) {
    if (leftover === 0n) break;
    parts[index]! += 1n;
    leftover -= 1n;
  }
  return value < 0n ? parts.map(part => -part) : parts;
}
