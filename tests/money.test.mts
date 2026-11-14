import assert from 'node:assert/strict';
import test from 'node:test';
import { addMoney, allocateMoney, assertMoneyInRange, compareMoney, convertMoney, formatMoney, MONEY_MAX, MONEY_MIN, multiplyMoney, parseMoney, percentOfMoney, rateOfAmounts, subtractMoney } from '../index.mjs';
import type { MoneyExponent, MoneyRounding } from '../index.mjs';

const EXPONENTS: MoneyExponent[] = [0, 2, 3];
const MODES: MoneyRounding[] = ['half-up', 'half-even', 'down'];

// A seeded generator keeps the property runs reproducible; bigint state avoids floating point in the tests too.
function generator(seed: bigint): (bound: bigint) => bigint {
  let state = seed;
  return bound => {
    state = (state * 6364136223846793005n + 1442695040888963407n) % (1n << 64n);
    return state % bound;
  };
}
const next = generator(20261113n);
const signed = (bound: bigint): bigint => next(2n) ? -next(bound) : next(bound);

// An independent oracle: round the exact decimal digits of n / 10^k by inspecting the dropped digits as text.
function oracle(numerator: bigint, places: number, mode: MoneyRounding): bigint {
  const negative = numerator < 0n, digits = (negative ? -numerator : numerator).toString().padStart(places + 1, '0');
  let kept = BigInt(digits.slice(0, digits.length - places));
  const dropped = digits.slice(digits.length - places);
  const half = `5${'0'.repeat(Math.max(places - 1, 0))}`;
  if (places && /[1-9]/u.test(dropped) && mode !== 'down') {
    if (dropped > half || dropped === half && (mode === 'half-up' || kept % 2n === 1n)) kept += 1n;
  }
  return negative ? -kept : kept;
}

test('parse and format round-trip every exponent, including three-decimal BHD, KWD and OMR', () => {
  for (const [text, exponent, minor] of [
    ['0', 0, 0n], ['1500', 0, 1500n], ['-7', 0, -7n],
    ['12.34', 2, 1234n], ['12.3', 2, 1230n], ['12', 2, 1200n], ['-0.01', 2, -1n], ['0.00', 2, 0n],
    ['1.234', 3, 1234n], ['0.005', 3, 5n], ['-0.005', 3, -5n], ['12.5', 3, 12500n], ['1000000000000.999', 3, 1000000000000999n],
  ] as const) {
    assert.equal(parseMoney(text, exponent), minor, `${text} @ ${exponent}`);
  }
  assert.equal(formatMoney(-5n, 3), '-0.005');
  assert.equal(formatMoney(12500n, 3), '12.500');
  assert.equal(formatMoney(-1n, 2), '-0.01');
  assert.equal(formatMoney(0n, 2), '0.00');
  assert.equal(formatMoney(1500n, 0), '1500');
  assert.equal(formatMoney(10n ** 30n + 1n, 2), '10000000000000000000000000000.01');
  for (let index = 0; index < 2000; index++) {
    const exponent = EXPONENTS[index % 3]!, amount = signed(10n ** 18n);
    const text = formatMoney(amount, exponent);
    assert.equal(parseMoney(text, exponent), amount, text);
    assert.equal(formatMoney(parseMoney(text, exponent), exponent), text);
  }
});

test('parsing refuses unsafe text and extra precision instead of rounding', () => {
  for (const text of ['', ' 1', '1 ', '+1', '1.', '.5', '1e3', '1,000', '0x10', '١٢', 'NaN', '--1', '1.2.3', '1_000', '1'.repeat(65)]) {
    assert.throws(() => parseMoney(text, 2), TypeError, JSON.stringify(text));
  }
  assert.throws(() => parseMoney(12 as unknown as string, 2), TypeError);
  assert.throws(() => parseMoney('1.234', 2), RangeError);
  assert.throws(() => parseMoney('1.5', 0), RangeError);
  assert.throws(() => parseMoney('1.0001', 3), RangeError);
  for (const exponent of [1, 4, -1, 2.5, '2', null]) assert.throws(() => parseMoney('1', exponent as MoneyExponent), RangeError);
  assert.throws(() => formatMoney(1 as unknown as bigint, 2), TypeError);
});

test('parsed amounts must fit a PostgreSQL bigint column', () => {
  assert.equal(MONEY_MIN, -9223372036854775808n);
  assert.equal(MONEY_MAX, 9223372036854775807n);
  assert.equal(parseMoney('9223372036854775807', 0), MONEY_MAX);
  assert.equal(parseMoney('-9223372036854775808', 0), MONEY_MIN);
  assert.equal(parseMoney('92233720368547758.07', 2), MONEY_MAX);
  assert.equal(parseMoney('-9223372036854775.808', 3), MONEY_MIN);
  for (const [text, exponent] of [['9223372036854775808', 0], ['-9223372036854775809', 0], ['92233720368547758.08', 2], ['9223372036854775808', 2], ['-9223372036854775.809', 3], ['9'.repeat(64), 2]] as const) {
    assert.throws(() => parseMoney(text, exponent), RangeError, `${text} @ ${exponent}`);
  }
  assertMoneyInRange(MONEY_MAX);
  assertMoneyInRange(MONEY_MIN);
  assertMoneyInRange(0n);
  assert.throws(() => assertMoneyInRange(MONEY_MAX + 1n), RangeError);
  assert.throws(() => assertMoneyInRange(MONEY_MIN - 1n), RangeError);
  assert.throws(() => assertMoneyInRange(addMoney(MONEY_MAX, 1n)), RangeError);
  assert.throws(() => assertMoneyInRange(1), TypeError);
});

test('add, subtract and compare accept only bigint minor units', () => {
  assert.equal(addMoney(1234n, -34n), 1200n);
  assert.equal(subtractMoney(5n, 12n), -7n);
  assert.deepEqual([3n, -1n, 2n, -1n].sort(compareMoney), [-1n, -1n, 2n, 3n]);
  assert.equal(compareMoney(0n, -0n), 0);
  for (let index = 0; index < 500; index++) {
    const a = signed(10n ** 20n), b = signed(10n ** 20n);
    assert.equal(subtractMoney(addMoney(a, b), b), a);
    assert.equal(compareMoney(a, b), -compareMoney(b, a));
  }
  assert.throws(() => addMoney(1 as unknown as bigint, 1n), TypeError);
  assert.throws(() => subtractMoney(1n, '1' as unknown as bigint), TypeError);
  assert.throws(() => compareMoney(1n, 1.5 as unknown as bigint), TypeError);
});

test('rounding boundaries follow each mode exactly at, below and above a half', () => {
  const cases: [bigint, string, Record<MoneyRounding, bigint>][] = [
    [25n, '0.1', { 'half-up': 3n, 'half-even': 2n, down: 2n }],
    [35n, '0.1', { 'half-up': 4n, 'half-even': 4n, down: 3n }],
    [-25n, '0.1', { 'half-up': -3n, 'half-even': -2n, down: -2n }],
    [-35n, '0.1', { 'half-up': -4n, 'half-even': -4n, down: -3n }],
    [249n, '0.01', { 'half-up': 2n, 'half-even': 2n, down: 2n }],
    [251n, '0.01', { 'half-up': 3n, 'half-even': 3n, down: 2n }],
    [-251n, '0.01', { 'half-up': -3n, 'half-even': -3n, down: -2n }],
    [5n, '0.1', { 'half-up': 1n, 'half-even': 0n, down: 0n }],
    [-5n, '0.1', { 'half-up': -1n, 'half-even': 0n, down: 0n }],
    [1000n, '3.6725', { 'half-up': 3673n, 'half-even': 3672n, down: 3672n }],
    [7n, '0', { 'half-up': 0n, 'half-even': 0n, down: 0n }],
  ];
  for (const [amount, rate, expected] of cases) for (const mode of MODES) {
    assert.equal(multiplyMoney(amount, rate, mode), expected[mode], `${amount} × ${rate} ${mode}`);
  }
  // Three-decimal VAT: 5% of 0.010 BHD is 0.0005, exactly half a fils.
  assert.equal(percentOfMoney(10n, '5', 'half-up'), 1n);
  assert.equal(percentOfMoney(10n, '5', 'half-even'), 0n);
  assert.equal(percentOfMoney(10n, '5', 'down'), 0n);
  assert.equal(percentOfMoney(parseMoney('199.990', 3), '5', 'half-up'), parseMoney('9.999', 3) + 1n);
  assert.equal(percentOfMoney(parseMoney('100.00', 2), '15', 'half-even'), parseMoney('15.00', 2));
  assert.equal(percentOfMoney(-1n, '50', 'half-up'), -1n);
  assert.equal(multiplyMoney(1n, '-0.5', 'half-up'), -1n);
});

test('multiplication and percentages match an independent digit-rounding oracle and are sign-symmetric', () => {
  for (let index = 0; index < 3000; index++) {
    const amount = signed(10n ** 15n), places = Number(next(7n)), rateUnits = next(10n ** 9n);
    const digits = rateUnits.toString().padStart(places + 1, '0');
    const rate = places ? `${digits.slice(0, -places)}.${digits.slice(-places)}` : digits;
    for (const mode of MODES) {
      const product = multiplyMoney(amount, rate, mode);
      assert.equal(product, oracle(amount * rateUnits, places, mode), `${amount} × ${rate} ${mode}`);
      assert.equal(multiplyMoney(-amount, rate, mode), -product);
      assert.equal(multiplyMoney(amount, `-${rate}`, mode), -product);
      assert.equal(percentOfMoney(amount, rate, mode), oracle(amount * rateUnits, places + 2, mode), `${amount} × ${rate}% ${mode}`);
    }
  }
  for (const rate of ['', '1e2', '+1', '.5', '5%', ' 5', '1'.repeat(65)]) assert.throws(() => multiplyMoney(1n, rate, 'down'), TypeError, rate);
  for (const mode of ['up', 'HALF-UP', '', undefined]) assert.throws(() => multiplyMoney(1n, '1', mode as MoneyRounding), TypeError);
  assert.throws(() => percentOfMoney(1 as unknown as bigint, '5', 'down'), TypeError);
});

test('allocation always sums to the total, favours larger remainders, then earlier parts, and mirrors negatives', () => {
  assert.deepEqual(allocateMoney(100n, [1n, 1n, 1n]), [34n, 33n, 33n]);
  assert.deepEqual(allocateMoney(-100n, [1n, 1n, 1n]), [-34n, -33n, -33n]);
  assert.deepEqual(allocateMoney(5n, [3n, 7n]), [2n, 3n]);
  assert.deepEqual(allocateMoney(1n, [0n, 1n, 1n]), [0n, 1n, 0n]);
  assert.deepEqual(allocateMoney(0n, [2n, 5n]), [0n, 0n]);
  assert.deepEqual(allocateMoney(10n, [1n, 0n, 0n]), [10n, 0n, 0n]);
  // 1.000 KWD over three equal lines: 0.334 + 0.333 + 0.333.
  assert.deepEqual(allocateMoney(parseMoney('1', 3), [1n, 1n, 1n]).map(part => formatMoney(part, 3)), ['0.334', '0.333', '0.333']);
  for (let index = 0; index < 2000; index++) {
    const total = signed(10n ** 18n), weights = Array.from({ length: 1 + Number(next(8n)) }, () => next(3n) ? next(10n ** 6n) : 0n);
    if (!weights.some(weight => weight > 0n)) weights[0] = 1n;
    const parts = allocateMoney(total, weights), sum = weights.reduce((a, b) => a + b, 0n);
    assert.equal(parts.reduce((a, b) => a + b, 0n), total);
    assert.deepEqual(allocateMoney(-total, weights), parts.map(part => -part));
    parts.forEach((part, at) => {
      // Each part is within one unit of its exact share, and a zero weight receives nothing.
      const exact = total * weights[at]! / sum;
      assert.ok(part === exact || part === exact + (total < 0n ? -1n : 1n), `${part} vs ${exact}`);
      if (weights[at] === 0n) assert.equal(part, 0n);
    });
  }
  assert.throws(() => allocateMoney(1n, []), TypeError);
  // Sparse arrays: array methods skip holes, so a hole must still be refused rather than returned as a missing part.
  assert.throws(() => allocateMoney(10n, [, 1n] as bigint[]), TypeError);
  assert.throws(() => allocateMoney(10n, [1n, , 1n] as bigint[]), TypeError);
  assert.throws(() => allocateMoney(10n, new Array<bigint>(2)), TypeError);
  assert.throws(() => allocateMoney(1n, [1n, -1n]), TypeError);
  assert.throws(() => allocateMoney(1n, [1 as unknown as bigint]), TypeError);
  assert.throws(() => allocateMoney(1n, [0n, 0n]), RangeError);
  assert.throws(() => allocateMoney(1 as unknown as bigint, [1n]), TypeError);
});

// An independent reference for any rational n / d (d > 0): take the floor and the unit above it, then pick the nearer
// by exact cross-multiplication, settling a tie by the mode. It shares no code or remainder logic with the module.
function rationalOracle(numerator: bigint, denominator: bigint, mode: MoneyRounding): bigint {
  const negative = numerator < 0n, n = negative ? -numerator : numerator;
  const low = n / denominator, high = low + 1n;
  let kept = low;
  if (low * denominator !== n && mode !== 'down') {
    const below = n - low * denominator, above = high * denominator - n;
    if (above < below || above === below && (mode === 'half-up' || low % 2n === 1n)) kept = high;
  }
  return negative ? -kept : kept;
}
const pow10 = (digits: number): bigint => 10n ** BigInt(digits);
const unitsOf = (rate: string): bigint => BigInt(rate.replace('.', ''));
const placesOf = (rate: string): number => rate.includes('.') ? rate.length - rate.indexOf('.') - 1 : 0;
// The rate text for integer units at `digits` places, as a caller would store it.
function formatRate(value: bigint, digits: number): string {
  const text = value.toString().padStart(digits + 1, '0');
  return digits ? `${text.slice(0, text.length - digits)}.${text.slice(text.length - digits)}` : text;
}

test('convertMoney gives the specified cases, across exponents, with one rounding', () => {
  assert.equal(convertMoney(10000n, 2, '3.75', 2, 'half-up'), 37500n);
  assert.equal(convertMoney(700n, 2, '3.67', 2, 'half-up'), 2569n);
  assert.equal(convertMoney(25n, 2, '3.70', 2, 'half-up'), 93n);
  assert.equal(convertMoney(25n, 2, '3.70', 2, 'half-even'), 92n);
  assert.equal(convertMoney(25n, 2, '3.70', 2, 'down'), 92n);
  assert.equal(convertMoney(120125n, 3, '12.0503', 2, 'half-up'), 144754n);
  // JPY 1000 at 0.0245 is USD 24.50; USD 24.50 at 40.8163 is JPY 1000 (999.99935 rounded).
  assert.equal(convertMoney(1000n, 0, '0.0245', 2, 'half-up'), 2450n);
  assert.equal(convertMoney(2450n, 2, '40.8163', 0, 'half-up'), 1000n);
  // BHD 1.000 at 9.7400 is AED 9.74, and AED 9.74 at 0.1027 is BHD 1.000 (1.000298 rounded).
  assert.equal(convertMoney(1000n, 3, '9.7400', 2, 'half-up'), 974n);
  assert.equal(convertMoney(974n, 2, '0.1027', 3, 'half-up'), 1000n);
  // JPY 5 at 0.0001 is 0.5 of a fils, an exact half; whole units scale exactly in both directions.
  assert.equal(convertMoney(5n, 0, '0.0001', 3, 'half-up'), 1n);
  assert.equal(convertMoney(5n, 0, '0.0001', 3, 'half-even'), 0n);
  assert.equal(convertMoney(1n, 0, '1', 3, 'half-up'), 1000n);
  assert.equal(convertMoney(1999n, 3, '1', 0, 'half-up'), 2n);
  assert.equal(convertMoney(-25n, 2, '3.70', 2, 'half-up'), -93n);
  assert.equal(convertMoney(0n, 2, '3.67', 3, 'half-up'), 0n);
});

test('rateOfAmounts gives the specified cases and rounds a half by the mode', () => {
  assert.equal(rateOfAmounts(37033n, 2, 10000n, 2, 4, 'half-up'), '3.7033');
  assert.equal(rateOfAmounts(2571n, 2, 700n, 2, 4, 'half-up'), '3.6729');
  assert.equal(rateOfAmounts(2571n, 2, 700n, 2, 4, 'down'), '3.6728');
  // 1 / 8 = 0.125 and 3 / 8 = 0.375 exactly: halves at two places.
  assert.equal(rateOfAmounts(1n, 2, 8n, 2, 2, 'half-up'), '0.13');
  assert.equal(rateOfAmounts(1n, 2, 8n, 2, 2, 'half-even'), '0.12');
  assert.equal(rateOfAmounts(3n, 2, 8n, 2, 2, 'half-even'), '0.38');
  assert.equal(rateOfAmounts(-1n, 2, 8n, 2, 2, 'half-up'), '-0.13');
  assert.equal(rateOfAmounts(1n, 2, -8n, 2, 2, 'half-even'), '-0.12');
  // Too small to show at four places: returned as zero, and the caller refuses it.
  assert.equal(rateOfAmounts(1n, 2, 10n ** 9n, 2, 4, 'half-up'), '0.0000');
  assert.equal(rateOfAmounts(0n, 2, 700n, 2, 4, 'half-up'), '0.0000');
  // Across exponents: AED 9.74 per BHD 1.000, JPY 1000 per USD 24.50, and zero or ten places.
  assert.equal(rateOfAmounts(974n, 2, 1000n, 3, 4, 'half-up'), '9.7400');
  assert.equal(rateOfAmounts(1000n, 0, 2450n, 2, 4, 'half-up'), '40.8163');
  assert.equal(rateOfAmounts(2450n, 2, 1000n, 0, 6, 'half-up'), '0.024500');
  assert.equal(rateOfAmounts(7n, 0, 2n, 0, 0, 'half-up'), '4');
  assert.equal(rateOfAmounts(7n, 0, 2n, 0, 0, 'half-even'), '4');
  assert.equal(rateOfAmounts(5n, 0, 2n, 0, 0, 'half-even'), '2');
  assert.equal(rateOfAmounts(1n, 0, 3n, 0, 10, 'half-up'), '0.3333333333');
});

test('conversion and rate derivation refuse malformed arguments', () => {
  for (const rate of ['0', '0.0000', '-3.67', '-0.0001']) assert.throws(() => convertMoney(1n, 2, rate, 2, 'half-up'), RangeError, rate);
  assert.throws(() => convertMoney(1n, 2, '1.00000000001', 2, 'half-up'), RangeError);
  assert.equal(convertMoney(10n ** 10n, 2, '1.0000000001', 2, 'half-up'), 10n ** 10n + 1n);
  for (const rate of ['', '3.', '.5', '1e2', '3,67', ' 3.67', '+1', 3.67]) assert.throws(() => convertMoney(1n, 2, rate as string, 2, 'half-up'), TypeError, String(rate));
  assert.throws(() => convertMoney(1 as unknown as bigint, 2, '1', 2, 'half-up'), TypeError);
  assert.throws(() => convertMoney(1n, 1 as MoneyExponent, '1', 2, 'half-up'), RangeError);
  assert.throws(() => convertMoney(1n, 2, '1', 4 as MoneyExponent, 'half-up'), RangeError);
  assert.throws(() => convertMoney(1n, 2, '1', 2, 'ceiling' as MoneyRounding), TypeError);
  assert.throws(() => rateOfAmounts(1n, 2, 0n, 2, 4, 'half-up'), RangeError);
  for (const count of [-1, 11, 2.5, NaN, Infinity, '4']) assert.throws(() => rateOfAmounts(1n, 2, 1n, 2, count as number, 'half-up'), RangeError, String(count));
  assert.throws(() => rateOfAmounts(1 as unknown as bigint, 2, 1n, 2, 4, 'half-up'), TypeError);
  assert.throws(() => rateOfAmounts(1n, 2, 1 as unknown as bigint, 2, 4, 'half-up'), TypeError);
  assert.throws(() => rateOfAmounts(1n, 5 as MoneyExponent, 1n, 2, 4, 'half-up'), RangeError);
  assert.throws(() => rateOfAmounts(1n, 2, 1n, 2, 4, 'up' as MoneyRounding), TypeError);
});

test('conversion and rate derivation match an independent rational reference and are sign-symmetric', () => {
  for (let index = 0; index < 4000; index++) {
    const from = EXPONENTS[index % 3]!, to = EXPONENTS[Math.floor(index / 3) % 3]!, mode = MODES[Math.floor(index / 9) % 3]!;
    const amount = signed(10n ** 15n), rate = formatRate(next(10n ** 9n) + 1n, Number(next(9n)));
    const expected = rationalOracle(amount * unitsOf(rate) * pow10(to), pow10(placesOf(rate) + from), mode);
    assert.equal(convertMoney(amount, from, rate, to, mode), expected, `${amount}@${from} × ${rate} → ${to} ${mode}`);
    assert.equal(convertMoney(-amount, from, rate, to, mode), -expected);

    const target = signed(10n ** 15n), source = (next(10n ** 12n) + 1n) * (next(2n) ? -1n : 1n), count = Number(next(11n));
    const derived = rateOfAmounts(target, to, source, from, count, mode), sign = source < 0n ? -1n : 1n;
    assert.equal(unitsOf(derived), rationalOracle(sign * target * pow10(from + count), sign * source * pow10(to), mode), `${target}@${to} / ${source}@${from} at ${count} ${mode}`);
    assert.equal(placesOf(derived), count);
    const negated = derived.startsWith('-') ? derived.slice(1) : unitsOf(derived) === 0n ? derived : `-${derived}`;
    assert.equal(rateOfAmounts(-target, to, source, from, count, mode), negated);
    assert.equal(rateOfAmounts(target, to, -source, from, count, mode), negated);
  }
});

test('the derived rate agrees with the PostgreSQL integer form, and converting back stays within the documented bound', () => {
  for (let index = 0; index < 10000; index++) {
    const f = EXPONENTS[index % 3]!, b = EXPONENTS[Math.floor(index / 3) % 3]!;
    const foreign = next(10n ** 13n) + 1n, rate = formatRate(next(10n ** 8n) + 1n, 4);
    // Rate entered, as the database guard writes it: B = (2 × F × R × 10^b + 10^(4 + f)) div (2 × 10^(4 + f)).
    const base = convertMoney(foreign, f, rate, b, 'half-up');
    assert.equal(base, (2n * foreign * unitsOf(rate) * pow10(b) + pow10(4 + f)) / (2n * pow10(4 + f)));
    if (base === 0n) continue;
    // Base entered: R = (2 × B × 10^(4 + f − b) + F) div (2 × F), with 10^b moved to the divisor so no power is negative.
    const derived = rateOfAmounts(base, b, foreign, f, 4, 'half-up');
    assert.equal(unitsOf(derived), (2n * base * pow10(4 + f) + foreign * pow10(b)) / (2n * foreign * pow10(b)), `${base}@${b} / ${foreign}@${f}`);
    if (unitsOf(derived) === 0n) continue;
    // Before rounding: 2 × |F × R' × 10^b − B × 10^(4 + f)| ≤ F × 10^b.
    const drift = foreign * unitsOf(derived) * pow10(b) - base * pow10(4 + f);
    assert.ok(2n * (drift < 0n ? -drift : drift) <= foreign * pow10(b), `drift ${drift} for ${foreign}@${f} → ${base}@${b}`);
    // After rounding: 2 × |B' − B| × 10^(4 + f) ≤ F × 10^b + 10^(4 + f).
    const moved = convertMoney(foreign, f, derived, b, 'half-up') - base;
    assert.ok(2n * (moved < 0n ? -moved : moved) * pow10(4 + f) <= foreign * pow10(b) + pow10(4 + f), `moved ${moved}`);
  }
});

test('conversion and rate derivation hold at the bigint range limits', () => {
  assert.equal(convertMoney(MONEY_MAX, 2, '1', 2, 'half-up'), MONEY_MAX);
  assert.equal(convertMoney(MONEY_MIN, 3, '1.0000', 3, 'half-even'), MONEY_MIN);
  assert.equal(convertMoney(MONEY_MAX, 3, '1', 2, 'half-up'), (MONEY_MAX + 5n) / 10n);
  assert.equal(convertMoney(MONEY_MIN, 3, '1', 2, 'down'), MONEY_MIN / 10n);
  // A result past the range is returned exactly, and the caller's guard refuses it.
  const over = convertMoney(MONEY_MAX, 2, '1', 3, 'half-up');
  assert.equal(over, MONEY_MAX * 10n);
  assert.throws(() => assertMoneyInRange(over), RangeError);
  assert.throws(() => assertMoneyInRange(convertMoney(MONEY_MAX, 2, '1.0001', 2, 'half-up')), RangeError);
  assertMoneyInRange(convertMoney(MONEY_MAX, 2, '0.9999', 2, 'half-up'));
  assert.equal(rateOfAmounts(MONEY_MAX, 2, MONEY_MAX, 2, 4, 'half-up'), '1.0000');
  assert.equal(rateOfAmounts(MONEY_MIN, 3, MONEY_MAX, 3, 10, 'half-up'), '-1.0000000000');
  assert.equal(rateOfAmounts(MONEY_MAX, 2, 1n, 2, 4, 'half-up'), `${MONEY_MAX}.0000`);
  assert.equal(rateOfAmounts(1n, 0, MONEY_MAX, 0, 10, 'half-up'), '0.0000000000');
  assert.equal(rateOfAmounts(MONEY_MIN, 3, -1n, 0, 0, 'half-up'), (-MONEY_MIN / 1000n + 1n).toString());
});
