import assert from 'node:assert/strict';
import test from 'node:test';
import { csvCell, csvRow, toCsv } from '../index.mjs';

const [TAB, CR, LF, BOM, NBSP] = [9, 13, 10, 0xfeff, 0xa0].map(code => String.fromCharCode(code));

// Discover src/server/explorer-input.ts csvCell (dev, 2026-10-25), verbatim, as the oracle for its existing exports.
function discoverCsvCell(value: unknown): string {
  let cell = value === null || value === undefined ? 'Unavailable' : typeof value === 'object' ? JSON.stringify(value) : String(value);
  if (/^[\s\uFEFF]*[=+@-]/u.test(cell) || /^[\t\r\n]/.test(cell)) cell = `'${cell}`;
  return `"${cell.replaceAll('"', '""')}"`;
}

test('csvCell quotes every field and neutralises spreadsheet formulas', () => {
  for (const [value, expected] of [
    ['plain', '"plain"'], ['say "hi"', '"say ""hi"""'], ['a,b', '"a,b"'], [`two${CR}${LF}lines`, `"two${CR}${LF}lines"`],
    [42, '"42"'], [true, '"true"'], [{ a: 1 }, '"{""a"":1}"'], [['x', 2], '"[""x"",2]"'],
    ['=SUM(A1)', `"'=SUM(A1)"`], ['+1', `"'+1"`], ['-1', `"'-1"`], ['@cmd', `"'@cmd"`],
    // Campaign's old guard missed these.
    [' =1+1', `"' =1+1"`], [`${LF}=1`, `"'${LF}=1"`], [`${BOM}=1`, `"'${BOM}=1"`], [`${TAB}x`, `"'${TAB}x"`], [`${CR}x`, `"'${CR}x"`], [`${LF}x`, `"'${LF}x"`],
    ['a=b', '"a=b"'], ['email@example.com', '"email@example.com"'],
  ] as const) assert.equal(csvCell(value), expected, JSON.stringify(value));
  assert.equal(csvCell(null), '""');
  assert.equal(csvCell(undefined, { missing: 'Unavailable' }), '"Unavailable"');
  assert.equal(csvCell(null, { missing: '=x' }), `"'=x"`);
});

test('csvCell matches Discover\'s exporter byte for byte with missing set to Unavailable', () => {
  const values: unknown[] = [null, undefined, '', 0, -3.5, 1e21, Number.NaN, false, 'x', ' -1', `${BOM}+`, `${TAB}`, '"', '""', {}, [], { nested: { q: '"=' } }, 'ünïcode', '😀=', `${NBSP}=1`];
  for (const value of values) assert.equal(csvCell(value, { missing: 'Unavailable' }), discoverCsvCell(value), JSON.stringify(value));
});

test('csvRow and toCsv end each record with CRLF', () => {
  assert.equal(csvRow(['a', 1, null]), `"a","1",""${CR}${LF}`);
  assert.equal(toCsv([['h1', 'h2'], ['=x', null]], { missing: '-' }), `"h1","h2"${CR}${LF}"'=x","'-"${CR}${LF}`);
  assert.equal(toCsv([]), '');
});
