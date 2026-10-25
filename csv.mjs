// Spreadsheet-safe CSV, promoted from Discover src/server/explorer-input.ts csvCell (dev, 2026-10-25), which about 12
// exporters use. No Node built-ins, so the browser entry re-exports it. Saving a file stays in @ten98/ui (saveFile).
/**
 * One quoted CSV field. Objects become JSON. Quoting alone does not stop a spreadsheet from executing a formula, so a
 * cell that starts with `=`, `+`, `-` or `@` after any whitespace or BOM, or that starts with a tab, CR or LF, gets a
 * leading apostrophe (OWASP CSV injection guidance). In JavaScript `\s` already includes the BOM (U+FEFF).
 */
export function csvCell(value, { missing = '' } = {}) {
    let cell = value === null || value === undefined ? missing : typeof value === 'object' ? JSON.stringify(value) : String(value);
    if (/^\s*[=+@-]/u.test(cell) || /^[\t\r\n]/.test(cell))
        cell = `'${cell}`;
    return `"${cell.replaceAll('"', '""')}"`;
}
/** One CSV record, ending with CRLF (RFC 4180). */
export function csvRow(cells, options) {
    return `${cells.map(cell => csvCell(cell, options)).join(',')}\r\n`;
}
/** A whole CSV document: each row as a CRLF-terminated record. */
export function toCsv(rows, options) {
    return rows.map(row => csvRow(row, options)).join('');
}
