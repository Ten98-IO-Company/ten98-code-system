export interface CsvOptions {
    /** Text for null and undefined cells; Discover's exports use 'Unavailable'. */
    readonly missing?: string;
}
/**
 * One quoted CSV field. Objects become JSON. Quoting alone does not stop a spreadsheet from executing a formula, so a
 * cell that starts with `=`, `+`, `-` or `@` after any whitespace or BOM, or that starts with a tab, CR or LF, gets a
 * leading apostrophe (OWASP CSV injection guidance). In JavaScript `\s` already includes the BOM (U+FEFF).
 */
export declare function csvCell(value: unknown, { missing }?: CsvOptions): string;
/** One CSV record, ending with CRLF (RFC 4180). */
export declare function csvRow(cells: readonly unknown[], options?: CsvOptions): string;
/** A whole CSV document: each row as a CRLF-terminated record. */
export declare function toCsv(rows: readonly (readonly unknown[])[], options?: CsvOptions): string;
