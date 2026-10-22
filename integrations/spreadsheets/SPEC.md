# Datumesh in spreadsheets: Excel add-in and Google Sheets add-on

Status: **design, non-normative, not built.** This document specifies two future integrations so that their tests can be written before their code. It does not change the protocol (`../../SPEC.md`, `spec-0.3.0`). Where it uses protocol terms (cell, receipt, slice, `asof`) they mean what the protocol says.

Dependencies that do not exist yet: a mesh that resolves function names and serves receipts (SPEC 5.3), and a function-resolution endpoint returning descriptors. Verification reuses the JavaScript verifier `@datumesh/verify`.

Every requirement has an ID (`SS-…`). The conversion cases in `cases.json` reference these IDs and are the test suite both add-ins must pass. Requirements marked **[Excel]** or **[Sheets]** apply to one host only; the rest apply to both.

## 1. Functions

| Excel | Sheets | Returns |
|---|---|---|
| `DATUMESH.CELL(function, args…)` | `DATUMESH_CELL(function, args…)` | the cell's value, converted to a sheet value (section 4) |
| `DATUMESH.TEXT(function, args…)` | `DATUMESH_TEXT(function, args…)` | the value's exact lexical form, as text |
| `DATUMESH.RECEIPT(function, args…)` | `DATUMESH_RECEIPT(function, args…)` | the receipt hash (64 hex) |
| `DATUMESH.SLICE(function, args…)` | `DATUMESH_SLICE(function, args…)` | a two-column spilled array: open argument values, cell values |
| `DATUMESH.UNIT(function, args…)` | `DATUMESH_UNIT(function, args…)` | the value's resolved unit as text (`USD/EUR`, `degC`), or empty text when the function does not return a number (SPEC 7.1) |

- **SS-F1** `function` is a fully qualified function name (SPEC 2.3), given as text or a reference to a cell containing it. Aliases are not accepted (`E_CANON_NAME`).
- **SS-F2** Arguments are given as name/value pairs, either inline (`"base", B2, "quote", C2`) or as one two-column range (names in the first column). An odd number of inline arguments, a non-text name, or a range that is not two columns wide is `E_SHEET_ARGS`.
- **SS-F3** The pair named `asof` sets the transaction time (section 5). It is not a function argument.
- **SS-F4** Every argument the function declares must be given (`E_ARG_MISSING`); undeclared names are `E_ARG_UNKNOWN`. In `CELL`, `TEXT` and `RECEIPT`, the value `"*"` is an error (`E_SHEET_SLICE`); in `SLICE`, at least one argument must be `"*"`.
- **SS-F5** **[Excel]** Names are `DATUMESH.*` because Office add-in custom functions live under a namespace. **[Sheets]** Names are `DATUMESH_*` because Apps Script function names cannot contain dots.

## 2. Resolution and argument types

- **SS-R1** The add-in resolves `function` to its current descriptor through the mesh, and takes every argument's type from `signature.args`. Sheet values are never typed by guessing.
- **SS-R2** The add-in builds the cell reference from the converted arguments and sends it to the mesh. Its canonical form is computed with `@datumesh/verify`; the add-in contains no second canonicaliser.

## 3. Converting sheet values to arguments

What a host hands the add-in: Excel passes numbers (dates included, as serial numbers), text, booleans and errors. Sheets passes numbers, text, booleans, JavaScript `Date` objects for date/time cells, and `""` for an empty cell.

General rules:

- **SS-C1** Never guess. A sheet value whose kind does not match the declared type is `E_SHEET_TYPE`, with a message saying what was expected. For example, the number `7` for a `string` argument is an error, not `"7"`. A product code like `007` typed into a cell becomes the number 7, and silently sending `"7"` would query the wrong cell.
- **SS-C2** An empty cell is `E_SHEET_EMPTY`. Datumesh has no null, and `""` is a real string value, so an empty cell cannot stand for one.
- **SS-C2a** **[Sheets]** Sheets passes both an empty cell and a formula returning `""` as `""`, and the two cannot be told apart. In Sheets, `""` is therefore always `E_SHEET_EMPTY`, and the empty string cannot be given as an argument. **[Excel]** distinguishes the two: empty text `""` is the empty string.
- **SS-C3** A sheet error value (`#N/A`, `#DIV/0!`, …) as an argument is `E_SHEET_VALUE`.
- **SS-C4** Text is accepted for any type if it is already the exact lexical form (SPEC section 3), and is then passed through unchanged. This is the exact path for values a double or a serial number cannot carry. Text that is not canonical fails with the protocol code (`E_CANON_NUMBER`, …); it is not repaired.

Per type:

- **SS-C5 number.** A sheet number is converted as follows:
  1. Round to 15 significant digits, which is Excel's own precision.
  2. Write it as a plain decimal: no exponent, no trailing fractional zeros, no trailing point.
  3. Write zero (including negative zero) as `0`.

  A result longer than 128 characters is `E_CANON_LIMIT`. This makes `=0.1+0.2` become `"0.3"`, matching what the sheet displays. It also means integers above 15 digits are rounded, so use text for those (SS-C4).
- **SS-C6 date [Excel].** The number must be a whole serial number, otherwise `E_SHEET_DATE`. In the 1900 date system, serial *n* is the day *n* days after 1899-12-30, valid from 61 (1900-03-01). Serials below 61 are `E_SHEET_DATE`: they fall in the range distorted by Excel's fictitious 29 February 1900, so earlier dates must be given as text. In the 1904 date system, serial *n* is *n* days after 1904-01-01. The add-in MUST determine which system the workbook uses. If it cannot, numeric dates are `E_SHEET_DATE_SYSTEM`, and only text dates work.
- **SS-C7 date [Sheets].** The value must be a `Date` that is exactly midnight in the spreadsheet's time zone (File → Settings), otherwise `E_SHEET_DATE`. It is written as `YYYY-MM-DD` *in that time zone*. Formatting in UTC would turn 15 March into 14 March east of Greenwich.
- **SS-C8 instant [Excel].** Excel date-times have no time zone, so a numeric date-time for an `instant` argument is `E_SHEET_ZONE`. Instants are given as text (SS-C4).
- **SS-C9 instant [Sheets].** A `Date` is an absolute time: convert it to UTC and write it with six fractional digits. Sheets carries milliseconds, so the last three digits are `000`.
- **SS-C10 string.** Only text is accepted. It must satisfy SPEC 3.5 exactly; text that is not NFC or contains line breaks is `E_CANON_STRING`, not normalised.
- **SS-C11 boolean.** Only TRUE or FALSE. The text `"TRUE"` is `E_SHEET_TYPE`.
- **SS-C12 blob.** Only text, in the exact blob form (SPEC 3.7, SS-C4). A blob that is not canonical is `E_CANON_BLOB`. The add-in never fetches or hashes blob content to build an argument.

## 4. Converting values back to the sheet

- **SS-V1 number.** `CELL` returns a sheet number (a double). `TEXT` returns the exact decimal.
- **SS-V2 date.** **[Excel]** returns the serial number in the workbook's date system; the user applies a date format, because custom functions cannot set one. For a date before 1900-03-01, or when the date system is unknown, it returns text. **[Sheets]** returns a `Date` at midnight in the spreadsheet's time zone.
- **SS-V3 instant.** Returns the canonical text (`…Z`) in both hosts. A zone-less serial would invite misreading.
- **SS-V4 string, boolean.** Returned as text and TRUE/FALSE.
- **SS-V4a blob.** Returned as the blob text. The add-in does not download content into the sheet.
- **SS-V4b units.** `CELL` returns a bare number; its unit is not shown in the value. `UNIT` gives the unit, resolved from the descriptor and the cell's arguments with `@datumesh/verify`'s `resolvedUnit`.
- **SS-V5** `SLICE` returns one row per cell, sorted by the open arguments' canonical values, with each value converted as above.

## 5. Transaction time and recalculation

- **SS-T1** An `asof` pair pins the result: the same formula returns the same value forever, so a sheet with explicit `asof` is reproducible.
- **SS-T2** Without `asof`, the add-in asks for "now". The function is not volatile: it does not change on every recalculation. Values refresh only when an argument changes or the user runs the add-in's **Refresh Datumesh values** command.
- **SS-T3** `DATUMESH.ASOF(…)` / `DATUMESH_ASOF(…)` takes the same arguments as `CELL` and returns the `asof` actually used, as text, so a sheet can record when a "now" value was read.

## 6. Verification

- **SS-V6** Every value shown has been verified to SPEC 10.1 step 6 (signature-valid) with `@datumesh/verify`, using keys fetched with its `fetchKeys`. A receipt that fails shows as an error with the protocol code (`E_SIGNATURE`, `E_KEY_UNAVAILABLE`, …). There is no setting that shows unverified values.
- **SS-V7** Keys are cached per host for at most one hour. Receipts are cached by (cell id, `asof`). A cached receipt is shown only after it has been verified.
- **SS-V8** **[Sheets]** Apps Script has SHA-256 but no Ed25519 or Web Crypto. The add-on bundles `@datumesh/verify` as one script with pure-JavaScript cryptography; if the library cannot run there, the add-on is blocked, not shipped unverified.

## 7. Errors

- **SS-E1** Every failure shows the code first, then a short explanation: `E_CANON_NUMBER: "1.50" is not canonical; write 1.5`. **[Excel]** As `#VALUE!` (custom function error with message). **[Sheets]** As `#ERROR!` with the message.
- **SS-E2** Add-in codes, in addition to the protocol's:

| Code | Meaning |
|---|---|
| `E_SHEET_ARGS` | Arguments are not name/value pairs (odd count, non-text name, range not two columns). |
| `E_SHEET_TYPE` | The sheet value's kind does not match the declared type. |
| `E_SHEET_EMPTY` | An argument cell is empty. |
| `E_SHEET_VALUE` | An argument is a sheet error value. |
| `E_SHEET_DATE` | Not a whole serial number / not midnight / before 1900-03-01 as a serial. |
| `E_SHEET_DATE_SYSTEM` | **[Excel]** The workbook's date system could not be determined. |
| `E_SHEET_ZONE` | **[Excel]** A zone-less numeric date-time for an `instant` argument. |
| `E_SHEET_SLICE` | `"*"` outside `SLICE`, or `SLICE` without `"*"`. |
| `E_SHEET_NETWORK` | The mesh could not be reached or timed out. |

## 8. Network, privacy, limits

- **SS-N1** All requests use HTTPS to the mesh and key hosts; nothing else is contacted.
- **SS-N2** The mesh sees which cells a sheet reads. The add-in's description says so.
- **SS-N3** **[Sheets]** Apps Script quotas apply (URL fetch calls per day, 30 s per custom function call). On a quota error, the result is `E_SHEET_NETWORK`, naming the quota.

## 9. Test plan

1. **Conversion cases:** `cases.json`, one test per case, run against the add-in's conversion module with no network. Each case gives the host, the declared type, the sheet value, the context (date system, spreadsheet time zone), and the expected argument text or error code.
2. **Requirement tests:** one test per `SS-` ID not covered by a case, against a mock mesh that serves the protocol's vectors (`../../vectors/receipt/`), including tampered receipts for SS-V6.
3. **Host smoke tests:** in a real Excel and a real Sheets, the formulas of section 1 against a test mesh.

Sheet values in `cases.json` are written as `{"number": …}`, `{"text": …}`, `{"boolean": …}`, `{"date": "<ISO local date-time>"}` (a Sheets `Date` with that wall-clock time in `context.timezone`), `{"empty": true}` or `{"error": "#N/A"}`.
