// Exact money arithmetic on bigint minor units (fils, cents, yen). Nothing here converts an amount to a Number or uses
// floating point, so results never depend on binary rounding. No Node built-ins: the browser entry re-exports it.
// Apps keep currency selection, display locale, ledger postings and which rounding mode a rule requires.
// Bounds parsing work on untrusted text; far beyond any ledger amount or rate.
const MAX_TEXT = 64;
const DECIMAL = /^(-?)(\d+)(?:\.(\d+))?$/u;
const ROUNDING = ['half-up', 'half-even', 'down'];
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
 * Minor units from a decimal string: `parseMoney('12.5', 3) === 12500n`. More fraction digits than the exponent are
 * refused rather than rounded, so an entered amount is never silently changed.
 */
export function parseMoney(text, exponent) {
    const digits = exponentOf(exponent), { units, scale } = decimalOf(text, 'Amount');
    if (scale > digits)
        throw new RangeError(`Amount has more than ${digits} fraction digits.`);
    return units * 10n ** BigInt(digits - scale);
}
/** The canonical decimal string for minor units: `formatMoney(-5n, 3) === '-0.005'`. No grouping or currency sign. */
export function formatMoney(amount, exponent) {
    const value = amountOf(amount, 'Amount'), digits = exponentOf(exponent);
    const magnitude = (value < 0n ? -value : value).toString().padStart(digits + 1, '0');
    const split = magnitude.length - digits;
    return `${value < 0n ? '-' : ''}${magnitude.slice(0, split)}${digits ? `.${magnitude.slice(split)}` : ''}`;
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
 * Splits `total` across non-negative bigint weights (at least one positive) by the largest-remainder method. The parts
 * always sum to `total`, a zero weight always receives 0n, leftover units go to the largest remainders with ties to
 * the earlier index, and a negative total splits as the exact negation of its positive split.
 */
export function allocateMoney(total, weights) {
    const value = amountOf(total, 'Total');
    if (!Array.isArray(weights) || !weights.length || weights.some(weight => typeof weight !== 'bigint' || weight < 0n)) {
        throw new TypeError('Weights must be a non-empty list of non-negative bigint values.');
    }
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
