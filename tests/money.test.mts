import assert from 'node:assert/strict';
import test from 'node:test';
import { addMoney, allocateMoney, compareMoney, formatMoney, multiplyMoney, parseMoney, percentOfMoney, subtractMoney } from '../index.mjs';
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
    const exponent = EXPONENTS[index % 3]!, amount = signed(10n ** 22n);
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
  assert.throws(() => allocateMoney(1n, [1n, -1n]), TypeError);
  assert.throws(() => allocateMoney(1n, [1 as unknown as bigint]), TypeError);
  assert.throws(() => allocateMoney(1n, [0n, 0n]), RangeError);
  assert.throws(() => allocateMoney(1 as unknown as bigint, [1n]), TypeError);
});
