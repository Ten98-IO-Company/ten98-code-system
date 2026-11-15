import assert from 'node:assert/strict';
import test from 'node:test';
import pg from 'pg';
import { convertMoney, rateOfAmounts } from '../index.mjs';
import type { MoneyExponent } from '../index.mjs';

// Agreement with PostgreSQL's own numeric arithmetic, opt-in: set TEN98_TEST_DATABASE_URL to a disposable server. It
// only runs SELECTs, so it creates no database. These are the sign-magnitude half-up forms the adoption guide gives.
const url = process.env.TEN98_TEST_DATABASE_URL;
const skip = url ? false : 'set TEN98_TEST_DATABASE_URL to a disposable PostgreSQL to check money arithmetic against numeric';

const CONVERT = `SELECT (sign(f) * div(2 * abs(f) * r * power(10::numeric, b) + power(10::numeric, p + fe),
  2 * power(10::numeric, p + fe)))::text AS value
  FROM unnest($1::numeric[], $2::numeric[], $3::int[], $4::int[], $5::int[]) WITH ORDINALITY AS c(f, r, p, fe, b, i) ORDER BY i`;
const RATE = `SELECT (sign(t) * sign(s) * div(2 * abs(t) * power(10::numeric, se + p) + abs(s) * power(10::numeric, te),
  2 * abs(s) * power(10::numeric, te)))::text AS value
  FROM unnest($1::numeric[], $2::int[], $3::numeric[], $4::int[], $5::int[]) WITH ORDINALITY AS c(t, te, s, se, p, i) ORDER BY i`;
const EXPONENTS: MoneyExponent[] = [0, 2, 3];
// numeric results may carry a zero fraction; the integer part is the value.
const integer = (text: string): bigint => BigInt(text.replace(/\.0*$/u, ''));

// The same seeded generator as the unit tests, with a different seed, so the cases are reproducible.
function generator(seed: bigint): (bound: bigint) => bigint {
  let state = seed;
  return bound => {
    state = (state * 6364136223846793005n + 1442695040888963407n) % (1n << 64n);
    return state % bound;
  };
}

test('convertMoney and rateOfAmounts agree with PostgreSQL numeric on signed amounts', { skip }, async () => {
  const next = generator(20261115n), signed = (bound: bigint) => next(2n) ? -next(bound) : next(bound);
  const conversions: { amount: bigint; units: bigint; places: number; from: MoneyExponent; to: MoneyExponent }[] = [
    { amount: -9439157537n, units: 284825395697801n, places: 5, from: 0, to: 2 },
  ];
  const rates: { target: bigint; to: MoneyExponent; source: bigint; from: MoneyExponent; places: number }[] = [
    { target: 1249n, to: 0, source: 10000n, from: 0, places: 2 },
  ];
  for (let index = 0; index < 400; index++) {
    const from = EXPONENTS[index % 3]!, to = EXPONENTS[Math.floor(index / 3) % 3]!;
    conversions.push({ amount: signed(10n ** 15n), units: next(10n ** 12n) + 1n, places: Number(next(11n)), from, to });
    rates.push({ target: signed(10n ** 15n), to, source: (next(10n ** 12n) + 1n) * (next(2n) ? -1n : 1n), from, places: Number(next(11n)) });
  }
  const client = new pg.Client({ connectionString: url });
  await client.connect();
  try {
    const converted = await client.query<{ value: string }>(CONVERT, [
      conversions.map(c => c.amount.toString()), conversions.map(c => c.units.toString()),
      conversions.map(c => c.places), conversions.map(c => c.from), conversions.map(c => c.to),
    ]);
    conversions.forEach((c, index) => {
      const rate = c.places ? `${c.units.toString().padStart(c.places + 1, '0').replace(new RegExp(`(\\d{${c.places}})$`, 'u'), '.$1')}` : c.units.toString();
      assert.equal(convertMoney(c.amount, c.from, rate, c.to, 'half-up'), integer(converted.rows[index]!.value), `${c.amount}@${c.from} × ${rate} → ${c.to}`);
    });
    const derived = await client.query<{ value: string }>(RATE, [
      rates.map(r => r.target.toString()), rates.map(r => r.to), rates.map(r => r.source.toString()), rates.map(r => r.from), rates.map(r => r.places),
    ]);
    rates.forEach((r, index) => {
      const text = rateOfAmounts(r.target, r.to, r.source, r.from, r.places, 'half-up');
      assert.equal(BigInt(text.replace('.', '')), integer(derived.rows[index]!.value), `${r.target}@${r.to} / ${r.source}@${r.from} at ${r.places}`);
    });
  } finally {
    await client.end();
  }
});
