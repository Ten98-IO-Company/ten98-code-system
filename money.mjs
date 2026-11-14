// Exact money arithmetic on bigint minor units (fils, cents, yen). Nothing here converts an amount to a Number or uses
// floating point, so results never depend on binary rounding. No Node built-ins: the browser entry re-exports it.
// Apps keep currency selection, display locale, ledger postings and which rounding mode a rule requires.
/** The smallest amount a PostgreSQL `bigint` (int8) column stores. */
export const MONEY_MIN = -(2n ** 63n);
/** The largest amount a PostgreSQL `bigint` (int8) column stores. */
export const MONEY_MAX = 2n ** 63n - 1n;
// Bounds parsing work on untrusted text; rates may need more digits than the int8 range, amounts are bounded below.
const MAX_TEXT = 64;
const DECIMAL = /^(-?)(\d+)(?:\.(\d+))?$/u;
const ROUNDING = ['half-up', 'half-even', 'down'];
// Rates accept and produce at most this many fraction digits.
const MAX_RATE_PLACES = 10;
function amountOf(value, label) {
    if (typeof value !== 'bigint')
        throw new TypeError(`${label} must be a bigint amount in minor units.`);
    return value;
}
function exponentOf(value) {
    if (value !== 0 && value !== 2 && value !== 3)
        throw new RangeError('Currency exponent must be 0, 2 or 3.');
    return value;
}
function roundingOf(value) {
    if (typeof value !== 'string' || !ROUNDING.includes(value))
        throw new TypeError(`Rounding must be one of ${ROUNDING.join(', ')}.`);
    return value;
}
// A plain decimal such as "12", "-0.125" or "15.0000": no exponent notation, grouping, spaces or leading plus.
function decimalOf(text, label) {
    const match = typeof text === 'string' && text.length <= MAX_TEXT ? DECIMAL.exec(text) : null;
    if (!match)
        throw new TypeError(`${label} must be a plain decimal string of at most ${MAX_TEXT} characters.`);
    const [, sign, whole, fraction = ''] = match;
    const units = BigInt(whole + fraction);
    return { units: sign ? -units : units, scale: fraction.length };
}
// A rate for convertMoney: a plain decimal above zero with at most MAX_RATE_PLACES fraction digits.
function rateOf(text) {
    const rate = decimalOf(text, 'Rate');
    if (rate.units <= 0n)
        throw new RangeError('Rate must be above zero.');
    if (rate.scale > MAX_RATE_PLACES)
        throw new RangeError(`Rate has more than ${MAX_RATE_PLACES} fraction digits.`);
    return rate;
}
// The decimal text of `value / 10^digits`, with exactly `digits` fraction digits and no grouping.
function decimalText(value, digits) {
    const magnitude = (value < 0n ? -value : value).toString().padStart(digits + 1, '0');
    const split = magnitude.length - digits;
    return `${value < 0n ? '-' : ''}${magnitude.slice(0, split)}${digits ? `.${magnitude.slice(split)}` : ''}`;
}
// The exact quotient numerator / denominator (denominator > 0) rounded to an integer by the given mode.
function divideRounded(numerator, denominator, rounding) {
    const quotient = numerator / denominator, remainder = numerator % denominator;
    if (remainder === 0n || rounding === 'down')
        return quotient;
    const twice = (remainder < 0n ? -remainder : remainder) * 2n;
    const away = twice > denominator || twice === denominator && (rounding === 'half-up' || quotient % 2n !== 0n);
    return away ? quotient + (numerator < 0n ? -1n : 1n) : quotient;
}
/**
 * Throws RangeError unless `value` fits a PostgreSQL `bigint` column (`MONEY_MIN` to `MONEY_MAX`), and TypeError unless
 * it is a bigint. `parseMoney` applies it to every parsed amount; arithmetic does not bound its results, so call it on a
 * computed amount before persisting it.
 */
export function assertMoneyInRange(value) {
    const amount = amountOf(value, 'Amount');
    if (amount < MONEY_MIN || amount > MONEY_MAX)
        throw new RangeError('Amount is outside the PostgreSQL bigint range.');
}
/**
 * Minor units from a decimal string: `parseMoney('12.5', 3) === 12500n`. More fraction digits than the exponent are
 * refused rather than rounded, so an entered amount is never silently changed, and an amount outside the PostgreSQL
 * `bigint` range is refused with a RangeError.
 */
export function parseMoney(text, exponent) {
    const digits = exponentOf(exponent), { units, scale } = decimalOf(text, 'Amount');
    if (scale > digits)
        throw new RangeError(`Amount has more than ${digits} fraction digits.`);
    const amount = units * 10n ** BigInt(digits - scale);
    assertMoneyInRange(amount);
    return amount;
}
/** The canonical decimal string for minor units: `formatMoney(-5n, 3) === '-0.005'`. No grouping or currency sign. */
export function formatMoney(amount, exponent) {
    return decimalText(amountOf(amount, 'Amount'), exponentOf(exponent));
}
/** `a + b` for bigint minor units of one currency; the caller keeps currencies apart. */
export function addMoney(a, b) {
    return amountOf(a, 'First amount') + amountOf(b, 'Second amount');
}
/** `a - b` for bigint minor units of one currency. */
export function subtractMoney(a, b) {
    return amountOf(a, 'First amount') - amountOf(b, 'Second amount');
}
/** -1, 0 or 1 as `a` is below, equal to or above `b`; usable as an Array sort comparator. */
export function compareMoney(a, b) {
    const left = amountOf(a, 'First amount'), right = amountOf(b, 'Second amount');
    return left < right ? -1 : left > right ? 1 : 0;
}
/** `amount × rate` in minor units of the amount's scale, for a decimal-string rate such as `'3.6725'`. */
export function multiplyMoney(amount, rate, rounding) {
    const value = amountOf(amount, 'Amount'), mode = roundingOf(rounding), { units, scale } = decimalOf(rate, 'Rate');
    return divideRounded(value * units, 10n ** BigInt(scale), mode);
}
/** `amount × percent / 100`, for a decimal-string percentage such as VAT `'5'` or `'15'`. */
export function percentOfMoney(amount, percent, rounding) {
    const value = amountOf(amount, 'Amount'), mode = roundingOf(rounding), { units, scale } = decimalOf(percent, 'Percent');
    return divideRounded(value * units, 10n ** BigInt(scale + 2), mode);
}
/**
 * `amount × rate` from one currency's minor units to another's, with one rounding: `convertMoney(700n, 2, '3.67', 2,
 * 'half-up') === 2569n` (USD 7.00 at 3.67 is AED 25.69). The rate is target units per source unit, a plain decimal
 * above zero with at most 10 fraction digits; anything else is a TypeError or RangeError. The result equals
 * `round(amount × units × 10^(toExponent − fromExponent) / 10^places)` computed on exact integers, the same form as
 * PostgreSQL `numeric` integer arithmetic with `div`. It is not range-checked: call `assertMoneyInRange` before
 * storing it.
 */
export function convertMoney(amount, fromExponent, rate, toExponent, rounding) {
    const value = amountOf(amount, 'Amount'), from = exponentOf(fromExponent), to = exponentOf(toExponent);
    const mode = roundingOf(rounding), { units, scale } = rateOf(rate);
    const up = to > from ? BigInt(to - from) : 0n, down = from > to ? BigInt(from - to) : 0n;
    return divideRounded(value * units * 10n ** up, 10n ** (BigInt(scale) + down), mode);
}
/**
 * The rate (target units per source unit) that two amounts imply, as a decimal string with exactly `places` digits
 * (an integer from 0 to 10), rounded once: `rateOfAmounts(2571n, 2, 700n, 2, 4, 'half-up') === '3.6729'`. It is the
 * exact `target × 10^(sourceExponent + places) / (source × 10^targetExponent)` rounded by one integer division, so
 * it never rounds twice. For half-up on positive amounts it equals the PostgreSQL integer form
 * `(2 × T × 10^(sourceExponent + places) + S × 10^targetExponent) div (2 × S × 10^targetExponent)`. A zero `source`
 * is a RangeError.
 *
 * Converting `source` back at this rate drifts from `target` by at most
 * `|source| × 10^(targetExponent − sourceExponent − places) / 2` before rounding, plus half a unit after it.
 * A result of zero (`'0.0000'`) and a rate too large for the caller's column are returned, not refused: the caller
 * decides whether to accept them.
 */
export function rateOfAmounts(target, targetExponent, source, sourceExponent, places, rounding) {
    const to = amountOf(target, 'Target'), toDigits = exponentOf(targetExponent);
    const from = amountOf(source, 'Source'), fromDigits = exponentOf(sourceExponent), mode = roundingOf(rounding);
    if (!Number.isSafeInteger(places) || places < 0 || places > MAX_RATE_PLACES) {
        throw new RangeError(`Places must be an integer from 0 to ${MAX_RATE_PLACES}.`);
    }
    if (from === 0n)
        throw new RangeError('Source amount must not be zero.');
    // divideRounded needs a positive denominator; moving the source's sign onto the numerator keeps the quotient.
    const numerator = to * 10n ** BigInt(fromDigits + places), denominator = from * 10n ** BigInt(toDigits);
    return decimalText(divideRounded(from < 0n ? -numerator : numerator, from < 0n ? -denominator : denominator, mode), places);
}
/**
 * Splits `total` across non-negative bigint weights (at least one positive) by the largest-remainder method. The parts
 * always sum to `total`, a zero weight always receives 0n, leftover units go to the largest remainders with ties to
 * the earlier index, and a negative total splits as the exact negation of its positive split.
 */
export function allocateMoney(total, weights) {
    const value = amountOf(total, 'Total');
    // An index loop, not some/map/reduce, which skip the holes of a sparse array such as [, 1n].
    let valid = Array.isArray(weights) && weights.length > 0;
    for (let index = 0; valid && index < weights.length; index++)
        valid = typeof weights[index] === 'bigint' && weights[index] >= 0n;
    if (!valid)
        throw new TypeError('Weights must be a non-empty list of non-negative bigint values.');
    const sum = weights.reduce((accumulated, weight) => accumulated + weight, 0n);
    if (sum === 0n)
        throw new RangeError('At least one weight must be positive.');
    const magnitude = value < 0n ? -value : value;
    const parts = weights.map(weight => magnitude * weight / sum);
    // Each remainder is below sum, so fewer than leftover + 1 parts with a nonzero remainder can ever be skipped.
    let leftover = magnitude - parts.reduce((accumulated, part) => accumulated + part, 0n);
    const order = weights.map((weight, index) => ({ index, remainder: magnitude * weight % sum }))
        .sort((a, b) => a.remainder === b.remainder ? a.index - b.index : a.remainder > b.remainder ? -1 : 1);
    for (const { index } of order) {
        if (leftover === 0n)
            break;
        parts[index] += 1n;
        leftover -= 1n;
    }
    return value < 0n ? parts.map(part => -part) : parts;
}
