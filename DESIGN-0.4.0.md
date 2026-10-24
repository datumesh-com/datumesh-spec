# spec-0.4.0 design memo: the formula dialect and slice-as-lineage

Status: accepted on 2026-10-24 with the user's decisions below (phase 1 of step 1.3, part 1).
Base: `main` at `3bac3d4` (tag `spec-0.3.0`).

## Decisions after review (the user, 2026-10-24)

1. **`-2^2` and `2^3^2`** are rejected (`E_FORMULA_AMBIGUOUS`), as proposed.
2. **Positional arguments bind by a declared order, `signature.order`**, not by ascending name
   order. `order` is an optional member of the signature: an array listing every argument name
   exactly once. When absent, a descriptor's bytes and hash are exactly as before, so no existing
   descriptor or receipt hash changes. In a read, positional arguments bind by `order` and labelled
   ones by name; positional arguments come first; more positional arguments than `order` has is an
   error; a positional argument in a read of a function without `order` is refused at define time.
   Formula descriptors always carry `order`. Classes (1.3b) use the same `order` for key tuples.
   The canonical AST still turns positional arguments into labelled ones. Older verifiers reject a
   descriptor with `order`, as with `extent`. Amended: 1.3, 2.1, 3.3, 6.3, section 18 (D43 replaced
   by D64).
3. **Run-time faults give `not_covered`, carrying the formula code** in the envelope, so a fault is
   not mistaken for missing data. The envelope gains an optional member on `not_covered` only; no
   existing envelope vector's result changes. The engine variant is a later library step. Amended:
   3.5, D58.
4. **Test 7**: two slice entries (temperatures and weights) are acceptable. Amended: 7.6.
5. **Accepted as proposed**: case-insensitive built-ins and keywords, printed lowercase; the three
   whitespace-sensitive lexical rules; bare literals take the context's unit except against
   percent, permille and bp; `first_known`, `last_corrected` and `superseded` deferred to the
   standard library; `E_INPUT_SUPERSEDED` as success at level `signed` with the code; the units
   `min`, `h`, `d` and `km`; asof-dependent receipts one per requested asof, with the mesh rule.
6. **Excel equivalence vectors** are based on Microsoft's documented semantics, with the
   documentation page cited per function in the table, and are marked documentation-derived. No
   real Excel is used.

Two small simplifications made while implementing, recorded here: `degC` multiplied or divided by
anything is `E_FORMULA_UNIT_OFFSET` (5.4 had an exception for a bare `1`, which bought nothing),
and `not_covered`'s new member is named `fault`, not `error`, so that `error` keeps one meaning
across outcomes (3.5).

---

## Phase 1 memo (as reviewed, amended where marked)

Read for it: the user's brief (`BRIEF-1.3.md`, whose fixed decisions, required grammar and stop
conditions are not reopened here), the user's decision log (as saved on 2026-10-24), SPEC.md,
`units.md`, README, `crosscheck/`, `tools/canon.py`, `tools/gen_vectors.py`, `tests/`,
`schemas/`, the spec-0.3.0 contract, the engine's crate documentation (`Runtime`, `Inputs`, the
answering rule, how a computed receipt's `asof` and `tx` are chosen), the core's `Resolver`, and
the DEFECTS files of the three libraries.

Every choice below is a proposal with the main alternative and the reason. Section 18 collects
them as draft rows D36-D64 for SPEC.md section 13. Section 16 lists the stop-condition risks;
none holds. Section 17 lists the points that need the user.

**Conflicts between the brief and the decision log** (the brief wins; named so nobody is
surprised):

- The log targets slice-as-lineage at "spec-0.3.x"; the brief puts it in spec-0.4.0. It goes in
  0.4.0.
- The log's set primitives list `last-before` and `next-after` as aggregates; the brief has the
  lookups `last_before` and `first_after`. The brief's names and kinds are used.
- The log says unbounded slices over tick histories "are refused by the budget with a typed
  error"; the brief says an unbounded slice over a function with no declared extent is refused
  at define time. These are reconciled, not in conflict: a stored function's extent is its
  recorded cells, so an unbounded slice over a stored tick history is accepted at define time
  and limited by fuel at run time, while an unbounded slice over a computed function without a
  declared extent is refused at define time (6.4).
- The log writes class keys unquoted (`fx_pair(EUR, USD)`, `forward(1M, …)`). In 0.4.0 strings
  are quoted; the unquoted forms are reserved for 1.3b (15.2).

---

## 1. Grammar

### 1.1 Shape

A formula body is one expression. There are no statements, no comments, no loops and no
user-defined functions inside a body. Whitespace between tokens is SP, HTAB or LF; CR is not
allowed (`code.body` already forbids it). Whitespace is never allowed inside a token.

The grammar is given as ABNF for readers and is, normatively, a PEG: alternatives are ordered
and the first that matches wins. A PEG cannot be ambiguous by construction; section 1.4 shows
that the ordered choices only ever pick between a valid and an invalid reading, never between
two valid ones, and that every place where two readings are plausible is either resolved by a
stated lexical rule or rejected.

### 1.2 Lexical rules

Tokens are recognised by **longest match**, trying the token classes in the order below at each
position. The longest-match rules are what settle the hazards of 1.4.

| # | Token | Form | Notes |
|---|---|---|---|
| L1 | instant | `date "T" 2DIGIT ":" 2DIGIT ":" 2DIGIT "." 6DIGIT "Z"` | Only the canonical form of 3.3. A token of this shape that is not a real instant is `E_FORMULA_INSTANT`. A shorter time (`2024-03-15T16:00Z`) is `E_FORMULA_INSTANT`, not subtraction. |
| L2 | date | `4DIGIT "-" 2DIGIT "-" 2DIGIT` | Always a date, never subtraction. Not a real day: `E_FORMULA_DATE`. |
| L3 | qualified name | `dns-name 1*( "/" name )` | A DNS name as in 2.1, so it contains at least one dot and its last label is not all digits. The last segment is the function (2.3). |
| L4 | alias | `"@" alias-path`, `alias-path = name *( "/" name )` | A short name, looked up in the resolver's alias map at define time. |
| L5 | number | `( "0" / %x31-39 *DIGIT ) [ "." *DIGIT %x31-39 ]` | Non-negative and canonical as in 3.1: no exponent, no leading zero, no trailing fractional zero, no leading or trailing point. A run of digits and points that is not canonical (`1.50`, `01`, `1.`, `.5`, `1e5`) is `E_FORMULA_NUMBER`. `1..2` is `1`, `..`, `2`. |
| L6 | unit suffix | after a number token, optional SP, then the **longest unit literal of `units.md`** (including index units) followed by a character that cannot continue a word | `10 m/s` is ten metres per second; `10 m / s` is ten metres divided by `s`. A word after a number that is not a unit is `E_FORMULA_UNIT`, except that digits directly followed by `D`, `M` or `Y` (`1M`, `10Y`) are reserved for period keys (15.2, `E_FORMULA_RESERVED`). |
| L7 | string | `DQUOTE *( string-char / 2DQUOTE ) DQUOTE` | Excel's quoting: `""` is a quote. No other escapes. The content follows 3.5 (assigned, NFC, no controls, so no raw LF or TAB) and the 1024-byte limit; failures `E_FORMULA_STRING`. |
| L8 | word | `ALPHA *( ALPHA / DIGIT / "_" )` | Classified in 1.2.1. |
| L9 | punctuation | `..` `->` `<>` `<=` `>=` `(` `)` `[` `]` `,` `:` `*` `+` `-` `/` `^` `&` `=` `<` `>` | Two-character tokens first. `==`, `!=`, `!`, `{`, `}`, `;`, `.` alone, `'`, `#`, `$`, `%`, `|`, `~`, and `` ` `` are `E_FORMULA_SYNTAX` (with a hint for `==` and `!=`: write `=` and `<>`). |

#### 1.2.1 Words

Keywords and built-in function names are **case-insensitive** and printed in lowercase.
Everything else is case-sensitive.

1. **Keywords** (any case): `if then else let in and or not true false`.
2. **Reserved** (any case): `this` (classes, 1.3b, the brief), `super` (classes: "super compiles to
   the parent's hash"). Any use is `E_FORMULA_RESERVED`.
3. **Forbidden function names** (any case), when followed by `(`: `now today rand randbetween
   randarray indirect offset info cell clock time random sleep fetch http eval`. `E_FORMULA_FORBIDDEN`;
   the error names the token (vectors carry it as `token`). Without `(` such a word is an
   ordinary variable (`time` may be an argument name).
4. **Built-in function**: a word followed by `(` that names a built-in (section 8 and the list in
   1.6). A word followed by `(` that is none of these is `E_FORMULA_UNKNOWN_FUNCTION`; user
   functions are always written qualified or as an `@alias`.
5. **Variable**: a word not followed by `(` that is a name (2.2): an argument of the function
   being defined, a `let` name or a lambda parameter.
6. A word not followed by `(` that contains an uppercase letter is `E_FORMULA_RESERVED`: such
   words are kept free for class key literals in 1.3b (15.2).

*Main alternative:* case-sensitive built-ins, rejecting `SUM` with a hint. Rejected because the
dialect's users type Excel function names in capitals, the brief itself writes `ASOF()`, and
case folding of built-in names cannot reach hashed data: the stored body is the printed form
(section 2), so there is still one spelling of every body. Function, argument and namespace
names stay case-sensitive and lowercase (D10).

### 1.3 ABNF sketch

```
body          = ws expr ws
expr          = or-expr / if-expr / let-expr                  ; ordered (PEG)
if-expr       = "if" expr "then" expr "else" expr
let-expr      = "let" name "=" expr "in" expr
or-expr       = and-expr *( "or" and-expr )
and-expr      = not-expr *( "and" not-expr )
not-expr      = "not" not-expr / cmp-expr
cmp-expr      = cat-expr [ cmp-op cat-expr ]                   ; at most one comparison
cmp-op        = "=" / "<>" / "<" / "<=" / ">" / ">="
cat-expr      = add-expr *( "&" add-expr )
add-expr      = mul-expr *( ( "+" / "-" ) mul-expr )
mul-expr      = unary *( ( "*" / "/" ) unary )
unary         = 1*"-" postfix / power                          ; "-" never takes a power
power         = postfix [ "^" exponent ]                       ; at most one "^"
exponent      = *"-" postfix
postfix       = primary                                        ; 1.3b: *( "." name "(" [ args ] ")" )
primary       = literal / read / builtin-call / bool-call / variable / "(" expr ")"
literal       = number [ unit ] / string / date / instant / "true" / "false"
read          = ( qualified / alias ) "(" [ read-arg *( "," read-arg ) ] ")"
read-arg      = [ label ] ( open / range / expr )
open          = "*"                                            ; only when followed by "," or ")"
range         = "[" expr ".." expr "]"
label         = name ":"
builtin-call  = builtin "(" [ call-arg *( "," call-arg ) ] ")"
call-arg      = [ label ] ( lambda / expr )
lambda        = name "->" expr / "(" name *( "," name ) ")" "->" expr
bool-call     = ( "and" / "or" ) "(" expr 1*( "," expr ) ")"   ; Excel AND(a, b), OR(a, b)
                                                               ; "if" "(" e "," e "," e ")" is a builtin-call
ws            = *( SP / HTAB / LF )                            ; between any two tokens
```

Positional arguments come first, then labelled ones (`E_FORMULA_ARG_ORDER`); a label appears
once (`E_FORMULA_ARG_DUPLICATE`). *(Amended after review.)* In a read, positional arguments bind
by the callee's `signature.order`; a read with a positional argument of a function without
`order` is `E_FORMULA_POSITIONAL`, and more positional arguments than `order` lists is
`E_FORMULA_ARITY`.

### 1.4 Precedence and associativity

From tightest to loosest:

| Level | Construct | Associativity | Notes |
|---|---|---|---|
| 1 | literals, reads, calls, `( )` | — | unit suffix is part of the number literal |
| 2 | postfix `.m(…)` | left | reserved for 1.3b; `).` is `E_FORMULA_RESERVED` now |
| 3 | `^` | **none** | `a^b^c` is `E_FORMULA_AMBIGUOUS` |
| 4 | unary `-` | prefix | `-a^b` is `E_FORMULA_AMBIGUOUS`; no unary `+` |
| 5 | `*` `/` | left | |
| 6 | `+` `-` | left | |
| 7 | `&` | left | as in Excel: below arithmetic, above comparison |
| 8 | `= <> < <= > >=` | **none** | `a < b < c` is `E_FORMULA_CHAIN` |
| 9 | `not` | prefix | `not a = b` is `not (a = b)` |
| 10 | `and` | left | |
| 11 | `or` | left | |
| 12 | `if … then … else …`, `let … in …`, `x -> …` | extend as far right as possible | allowed only where a whole `expr` is expected |

The AST is binary at every level: `a + b + c` is `(a + b) + c`. Rounding (section 4) makes `+`
and `*` non-associative, so the tree shape is part of the meaning.

### 1.5 The hazards, one by one

**`ns/fn(args)` against division.** A qualified name is one token (L3), and it must start with a
DNS name, which always contains a dot (2.1). A variable never contains a dot. So `x/f(y)`, with
`x` an argument, is `x` divided by the built-in call `f(y)` (or `E_FORMULA_UNKNOWN_FUNCTION`
when `f` is not a built-in), never a function `x/f`. `x / example.org/f(y)` divides by a read;
`example.org/f(y) / 2` reads and divides. A qualified name not followed by `(` is
`E_FORMULA_SYNTAX`: there are no first-class functions.

The one residue is a hyphenated host. `a-b.org/f(x)` is a single token, the call of `a-b.org/f`,
because longest match takes the whole DNS name (`open-meteo.com` is a real case). To subtract,
write `a - b.org/f(x)`. The printer always puts spaces round binary operators, so a printed body
can never contain the case, and vectors pin both readings.

**Short names.** An alias is written `@ecb/fx_rate(…)` or `@fx_rate(…)` (L4). Without the sigil,
`ecb/fx_rate(x)` could be a division or an alias, and which would depend on what is in scope.
The sigil makes it lexical. An alias missing from the map is `E_FORMULA_ALIAS`. Aliases are
replaced by full names in the AST (section 2), so they never reach hashed data.
*Alternative:* bare aliases, resolved by scope. Rejected: every new argument or built-in name
could silently change the meaning of an existing body.

**Unit suffix against identifiers and juxtaposition.** Juxtaposition means nothing in the
dialect (no implicit multiplication, no application by juxtaposition), so a word directly after
a number can only be a unit suffix (L6). The suffix is the longest listed unit, matched as a
whole word: `0.05 percent`, `20 degC`, `100 EUR`, `5 kWh`, `10 m/s`, `3 W/m2`,
`100 index:2015=100`. `10 m / s` is a division by the variable `s` (whitespace inside a token is
never allowed, and `m/s` is one token). `5 x` with `x` not a unit is `E_FORMULA_UNIT`, which
also catches the Excel habit of implicit multiplication. A number followed by a number is
`E_FORMULA_SYNTAX`. The unit `1` cannot be a suffix: a bare literal already is dimensionless
(5.3).

**`[lo..hi]` against decimals.** A number's fraction needs at least one digit after the point
(L5), and `..` is a token. So `[1..2]` is `1 .. 2`, `[1.5..2]` is `1.5 .. 2`, `[1...2]` is
`1 .. .2`, which is `E_FORMULA_NUMBER`, and `[2024-01-01..2024-12-31]` is date, `..`, date.
Ranges are allowed only as an argument of a read (`E_FORMULA_PLACEMENT` elsewhere); `[`
appears nowhere else.

**Unary minus with `^`, and `^` chains.** Excel reads `-2^2` as 4 and `2^3^2` as 64;
mathematics, Python and most languages read them as -4 and 512. Either choice silently
misleads half the users, so both are rejected (`E_FORMULA_AMBIGUOUS`): write `(-2)^2`,
`-(2^2)`, `(2^3)^2` or `2^(3^2)`. A unary minus in the exponent is fine: `2^-1` is 0.5.

**Comparison chaining.** `a < b < c` is `E_FORMULA_CHAIN`. Excel evaluates it as
`(a < b) < c`, comparing a boolean with a number, which a typed dialect cannot do, and
Python's `a < b and b < c` is a second meaning. Write the `and`.

**`if then else` and `let in` extent.** Both extend as far right as possible, and `else` is
mandatory, so there is no dangling else. They are allowed only where a whole expression is
expected: the body, a parenthesised expression, an argument, a `then`/`else` branch, a `let`
value or body, a lambda body. `1 + if a then b else c` is `E_FORMULA_PLACEMENT`; write
`1 + (if a then b else c)`. Excel's function form `if(c, a, b)` is a built-in call and may
appear anywhere; `if (c) then a else b` is the keyword form, because the ordered choice tries
`or-expr` (where `if(` must be followed by three comma-separated arguments) before `if-expr`.
The two forms give the same AST. `let x = a = b in x` binds `x` to `a = b`.

**Date and instant literals.** `2024-03-15` is always a date (L2) and `2024-03-15T16:00:00.000000Z`
always an instant (L1); to subtract numbers, write spaces (`2024 - 3 - 15`). With leading zeros
forbidden (L5), most such runs could not be subtraction anyway; `2024-10-15` could, and is
taken as a date. The bare form matches the decision log's examples (`forward(1M, 2026-10-24)`)
and the cell URI. *Alternative:* a sigil or function (`date("2024-03-15")`, `#2024-03-15#`).
Rejected as noisier than a rule that only bites a subtraction nobody writes without spaces.

**Keywords against function names.** Only the ten keywords and two reserved words are taken
from the identifier space. Built-in names such as `at`, `first`, `last`, `sum` and `count` are
not keywords: they are built-ins only when followed by `(`, so an argument named `count` or
`first` still works as a variable. `in` is a keyword, so a formula function cannot
have an argument named `in`, `and`, `or`, `not`, `if`, `then`, `else`, `let`, `true`, `false`,
`this` or `super` (`E_FORMULA_RESERVED` at define). Labels may be any name, so other functions'
arguments with those names can still be passed by label (`f(in: 3)`). `asof` cannot be an
argument name at all (2.4), so `asof()` and `asof(cell, T)` never meet a variable; they are
told apart by arity.

**Case.** See 1.2.1: built-ins and keywords in any case, printed lowercase; names
case-sensitive. `SUM(x.org/f(*))` and `sum(x.org/f(*))` have one AST.

**`*` as open marker against multiplication.** In a read argument, `*` followed by `,` or `)`
is the open marker; nothing else can start with `*`, because there is no unary `*`.
`f(2 * 3)` multiplies. In a built-in's arguments `*` alone is `E_FORMULA_PLACEMENT`.

**Lambdas.** A lambda is allowed only as the function argument of `map` and `filter`
(`E_FORMULA_PLACEMENT` elsewhere). `x -> e` is recognised by the token `->` after a name;
`(x, station) -> e` by `(` name `,` or `(` name `)` `->`, which a parenthesised expression can
never be, since expressions have no commas outside calls. `->` is one token, so `a->b` is never
`a - > b` (which would be an error anyway).

### 1.6 Built-ins

Aggregates (one slice, or one or more scalars of one type): `sum count mean min max first last
median stdev stdev_p`. Lookups: `at latest last_before first_after nearest within interpolate`.
Scans: `scan map filter window`. Fallback: `otherwise`. Transaction time: `asof versions`, and
`asof()`. Arithmetic: `abs round round_up round_down floor ceiling mod sqrt convert`. Logic:
`if and or`. Dates: `date year month day weekday end_of_month add_days add_months business_days
year_fraction is_holiday`. Text: `len upper lower trim concat substr find text fixed`. Each has
a fixed parameter list (positional order and labels), stated in SPEC.md's table in phase 2.

---

## 2. Canonical form and hashes

### 2.1 Two trees

Parsing gives a surface tree. **Resolution** at define time turns it into the **canonical
AST**:

- aliases replaced by fully qualified names (from the resolver's alias map);
- built-in names and keywords lowercased; `if(c, a, b)` and `and(a, b, c)` turned into the
  keyword forms (`and(a, b, c)` is `(a and b) and c`);
- positional arguments of reads turned into labelled ones, by the callee's declared
  `signature.order` *(amended after review: not by ascending name order)*. Built-ins have their
  own fixed parameter order;
- nothing else: no constant folding, no reordering, no simplification. `-5` stays `neg(5)`;
  `1 + 2` stays a sum.

The canonical AST is JSON. One object per node, discriminated by `node`, e.g.

```json
{"node": "op", "op": "*", "args": [
  {"node": "var", "name": "amount"},
  {"node": "read", "fn": "rates.example.org/fx_rate", "args": {
     "base": {"node": "var", "name": "base"},
     "date": {"node": "open"},
     "quote": {"node": "str", "value": "USD"}}}]}
```

Node kinds: `num` (`value`, optional `unit`), `str`, `bool`, `date`, `instant`, `var`, `op`
(binary and unary operators, `and`, `or`, `not`, `&`, comparisons), `if`, `let`, `read`
(arguments: an expression, `{"node": "open"}`, or `{"node": "range", "lo", "hi"}`), `call`
(built-ins, with `args` and `named`), `lambda` (`params`, `body`). Numbers keep their canonical
lexical form as strings; there are no JSON numbers in the AST.

### 2.2 What is hashed

- **The function hash is unchanged in definition**: SHA-256 of the descriptor's canonical bytes
  (7). For `lang = "formula"`, `code.body` is the **printed canonical AST**: `print(ast)`
  followed by one LF. A formula descriptor whose body is not the print of its own AST is not a
  formula descriptor (`E_FORMULA_NOT_CANONICAL`), so every formula has exactly one body and one
  hash. *Alternative:* hash the AST and store it as the body (JSON in `code.body`). Rejected: the
  body is what people and agents read in a descriptor, and the printed form is already one
  spelling per AST.
- **`inputs`** is the derived set (3.4), never declared by the author. A descriptor whose
  `inputs` differs from it is `E_FORMULA_INPUTS`.
- **The canonical AST hash** is SHA-256 of the JCS bytes of the canonical AST. It appears in no
  protocol object. It is what a grammar vector pins, so that two parsers are compared on their
  trees, not on their printers. A grammar vector's environment (section 13) supplies the
  signatures and alias map that resolution needs.

### 2.3 The printer

`print` writes: single spaces round every binary operator, `let` and `if` keywords and `->`; no
space inside parentheses or before commas, one after; reads as `ns/fn(a: x, b: y)` with labels in
ascending order; built-ins positionally in their declared order, with optional parameters
labelled; unit suffix after one space (`0.05 percent`); strings with `""` for quotes; the
minimum parentheses that the precedence table needs, plus those it requires for the rejected
forms (`(-2)^2`, `(2^3)^2`, `(if … )` as an operand). One line, then LF.

The property **parse(print(ast)) = ast** holds for every canonical AST, and is tested on fuzzed
trees (13.4). It needs no environment: printed bodies contain only full names and labelled
reads.

The existing `expr` vector body `amount * rates.example.org/fx_rate(base: base, date: date, quote: quote)\n`
is already a canonical formula body. Its descriptor stays `lang = "expr"` and keeps its hash;
nothing reinterprets it.

---

## 3. Types and checking at define time

### 3.1 Types

- The six scalars. `number` carries a unit (section 5); the others have none.
- **`slice<T, keys>`**: a set of members, each a key tuple (the open arguments, each with its
  declared type) and a value of type `T` (with its unit when `T` is `number`). Slices exist only
  inside a body: an argument, a `let` value or a function's return cannot be a slice
  (`E_FORMULA_SLICE_VALUE`).
- **Lambdas** only as the second argument of `map` and `filter`.

`blob` values can be passed, compared with `=`/`<>`, returned and used as keys; nothing else
(`E_FORMULA_TYPE`). There are no implicit conversions between types: `"a" & 1` is
`E_FORMULA_TYPE` (write `"a" & text(1)`).

### 3.2 What is checked when

**At define time** (all static, all in the reference checker, each with its own code):
syntax and literals; names, aliases and bindings (the callee names resolve as of the define
time); built-in arity and parameter labels; read arguments against the callee's signature
(unknown, missing, type); types of every node; units (section 5); purity (forbidden names,
`this`, no reads inside lambdas); slice placement and extents (6.4); return type and unit
against `signature.returns`; that the descriptor's `inputs` equals the derived set; that the
body is canonical; static limits (AST depth at most 256, at most 65,536 nodes).

**At evaluation time**: division by zero; domain errors (non-integer exponent, square root of a
negative number, `add_months` past year 9999); range (a number whose canonical form exceeds
128 characters, a string over 1024 bytes); absence (a lookup with no qualifying member, an
aggregate that needs a member over an empty slice, an input with no value); a transaction-time
read in the future of the evaluation asof; fuel. A callee name rebound since define time to a
function with another signature or no extent is checked again at evaluation, with the same
codes.

### 3.3 Error codes

A new family. Define-time codes are what `define` and the reference checker report; evaluation
codes are what an evaluator reports. None of them is a verification code (10.2): a mesh never
signs a receipt for a failed evaluation. How the engine maps them is in 3.5.

| Code | Rule |
|---|---|
| `E_FORMULA_SYNTAX` | Not a sentence of the grammar; a stray or unknown character |
| `E_FORMULA_NUMBER` | A number literal not in canonical form (L5) |
| `E_FORMULA_STRING` | A string literal unterminated, not NFC, with a control or unassigned character, or over 1024 bytes |
| `E_FORMULA_DATE` | A date-shaped token that is not a real day |
| `E_FORMULA_INSTANT` | An instant-shaped token not in the canonical form, or not a real time |
| `E_FORMULA_UNIT` | A unit suffix that is not a listed unit |
| `E_FORMULA_NAME` | A qualified name or alias that breaks 2.1-2.3 |
| `E_FORMULA_RESERVED` | `this`, `super`, a keyword used as a name, an uppercase word (1.2.1), `).` |
| `E_FORMULA_FORBIDDEN` | A forbidden function name followed by `(` (1.2.1); the token is reported |
| `E_FORMULA_DYNAMIC_NAME` | A call whose callee is not a name: `(e)(x)`, `"a.org/f"(x)` |
| `E_FORMULA_AMBIGUOUS` | `-a^b` or `a^b^c` without parentheses |
| `E_FORMULA_CHAIN` | Two comparisons chained |
| `E_FORMULA_PLACEMENT` | `if`/`let` as an operand; `*` or a range outside a read; a lambda outside `map`/`filter` |
| `E_FORMULA_LIMIT` | AST depth or node limit exceeded |
| `E_FORMULA_UNKNOWN_FUNCTION` | A bare call that is not a built-in |
| `E_FORMULA_ALIAS` | An alias not in the alias map |
| `E_FORMULA_UNRESOLVED` | A qualified function name with no binding at define time |
| `E_FORMULA_UNKNOWN_NAME` | A variable not in scope |
| `E_FORMULA_SHADOW` | A `let` name or lambda parameter equal to a name already in scope |
| `E_FORMULA_ARITY` | A built-in called with the wrong number of arguments |
| `E_FORMULA_ARG_UNKNOWN` | A label the callee does not declare |
| `E_FORMULA_ARG_MISSING` | A callee argument not bound (open arguments are written `*`) |
| `E_FORMULA_ARG_DUPLICATE` | An argument bound twice |
| `E_FORMULA_ARG_ORDER` | A positional argument after a labelled one |
| `E_FORMULA_POSITIONAL` | A positional argument in a read of a function whose signature has no `order` *(added after review)* |
| `E_FORMULA_ORDER` | A formula descriptor whose signature has no `order` *(added after review)* |
| `E_FORMULA_TYPE` | A type mismatch anywhere |
| `E_FORMULA_SLICE_VALUE` | A slice where a scalar is required, including the function's result |
| `E_FORMULA_UNIT_MISMATCH` | Units differ where they must agree (5.2) |
| `E_FORMULA_UNIT_OFFSET` | An offset unit used where only differences make sense (5.4) |
| `E_FORMULA_UNIT_UNKNOWN` | A unit that cannot be determined statically (5.5) |
| `E_FORMULA_EXPONENT` | A unit-bearing base with a non-literal or non-integer exponent; `sqrt` of an odd unit power |
| `E_FORMULA_RETURN_TYPE` | The body's type differs from `signature.returns` |
| `E_FORMULA_RETURN_UNIT` | The body's unit differs from the declared return unit |
| `E_FORMULA_UNBOUNDED` | An open or range argument over a function with no extent for it (6.4) |
| `E_FORMULA_SLICE_BOUND` | A range on an argument type with no order (boolean, blob) |
| `E_FORMULA_METRIC` | A metric lookup on a dimension with no metric (string, boolean, blob), or a bound in the wrong unit |
| `E_FORMULA_ALONG` | A lookup or scan whose dimension cannot be chosen (8.1) |
| `E_FORMULA_JOIN` | An operator over two slices whose open argument names or key types differ |
| `E_FORMULA_LAMBDA_PARAM` | A lambda parameter after the first that is not an open argument of the slice |
| `E_FORMULA_LAMBDA_READ` | A cell read inside a lambda |
| `E_FORMULA_ENUM` | A method, convention, roll or aggregate parameter that is not a literal from its list |
| `E_FORMULA_TX_ARG` | The first argument of `asof(…, T)` or `versions` is not a single-cell read |
| `E_FORMULA_UNSUPPORTED` | A construct the grammar parses but 0.4.0 does not implement: `point` metrics, key-set arguments (8.1) |
| `E_FORMULA_INPUTS` | A descriptor's `inputs` differs from the derived set |
| `E_FORMULA_NOT_CANONICAL` | A descriptor's body is not the print of its AST |
| `E_FORMULA_DIV_ZERO` | Division (or `mod`) by zero (evaluation) |
| `E_FORMULA_DOMAIN` | An argument outside an operation's domain (evaluation) |
| `E_FORMULA_RANGE` | A result outside the canonical forms: a number over 128 characters, a string over 1024 bytes, a date or instant outside 0001-9999 (evaluation) |
| `E_FORMULA_EMPTY` | An aggregate that needs members over an empty slice (evaluation; catchable by `otherwise`) |
| `E_FORMULA_ABSENT` | A lookup with no qualifying member (evaluation; catchable by `otherwise`) |
| `E_FORMULA_FUTURE` | `asof(c, T)` or `versions(c, f, T)` with `T` after the evaluation asof (evaluation) |
| `E_FORMULA_BUDGET` | Fuel exhausted (evaluation) |

The first failure in a fixed order is reported: lexing left to right, then parsing, then
resolution and checking in a depth-first, left-to-right walk of the canonical AST (arguments of
a read in ascending label order). Evaluation faults are reported in evaluation order (8.9).

### 3.4 Inputs, derived

The derived `inputs` is the set of fully qualified function names of every `read` node: cell
reads, slices, the first arguments of `asof` and `versions`, and calendar slices. Built-ins are
not inputs. A function that reads itself (fib) has its own name in it, resolved at define time
to the name being defined. The set is sorted and written as 7 already requires.

Static derivability is by construction: a callee is always a lexical name (a qualified name or
an alias resolved at define time), never a value. There is no `indirect`, no string-to-name
conversion and no way to call an expression (`E_FORMULA_DYNAMIC_NAME`). A body with a
dynamically constructed name therefore fails at parse.

### 3.5 Absence and faults at run time

Excel shows `#DIV/0!` in a cell; a receipt cannot hold an error, and there is no null. An
evaluation that faults gives the cell **no value**: the engine answers `not_covered`, as it
already does when an input has none. *(Amended after review.)* The `not_covered` envelope gains an
optional member `fault`, one of the evaluation fault codes (`E_FORMULA_DIV_ZERO`,
`E_FORMULA_DOMAIN`, `E_FORMULA_RANGE`, `E_FORMULA_EMPTY`, `E_FORMULA_ABSENT`, `E_FORMULA_FUTURE`),
so that a fault is not mistaken for missing data. Fuel exhaustion is not a fault (another mesh may
have more fuel) and stays an `error` envelope with `E_EVAL_UNAVAILABLE`. *Alternative:* an `error` envelope with
`E_EVAL_UNAVAILABLE`. Rejected: the fault is a deterministic property of the cell, not a failure
of the mesh, and any mesh will find the same; retrying cannot help. The engine needs a new
`EvalError` variant carrying the formula code (an additive change).

`otherwise(x, y)` evaluates `y` when `x` gives `E_FORMULA_EMPTY` or `E_FORMULA_ABSENT`, and only
then. Those are absences that the lineage proves: the slice's member set is pinned (section 7).
It does not catch a single-cell read with no value (the engine's `InputNotCovered`: a receipt
cannot list an absence), nor arithmetic faults (write the `if`). To make a possibly missing cell
catchable, read it through a slice: `otherwise(at(f(*), k), 0)`.

---

## 4. Decimal arithmetic

### 4.1 The rule

Every number is a decimal with at most 34 significant digits. Every operation computes its exact
result, rounds it once to 34 significant digits with round-half-even, and then checks the range
rule. This is the decimal128 contract with one simplification: the range is not an exponent
range but the canonical form itself.

- **Range rule.** After every operation, the result written in canonical form (3.1) must be at
  most 128 characters: otherwise `E_FORMULA_RANGE`. So every intermediate is a valid number
  value; magnitudes stay within 10^-126 to 10^127. There is no overflow to infinity, no
  subnormal, no silent underflow to zero.
- **Negative zero** never exists: a zero result is `0`.
- **Canonical form of a result.** Strip trailing fractional zeros, no exponent, `0` for zero
  (3.1). With the range rule this always succeeds.

*Alternative:* the full decimal128 exponent range (Emin -6143, Emax 6144) for intermediates,
checking 128 characters only on the returned value. Rejected: it adds overflow and subnormal
behaviour that every evaluator would have to reproduce exactly for no benefit, since anything
outside the canonical form could never be returned.

### 4.2 Operations

| Operation | Definition |
|---|---|
| `+` `-` `*` | exact, then rounded once |
| `/` | the correctly rounded quotient (exact rational, rounded once); divisor zero: `E_FORMULA_DIV_ZERO` |
| comparison, `=` | exact, on values; no rounding |
| `x ^ n` | `n` must be an integer (`E_FORMULA_DOMAIN` otherwise) with abs(n) at most 1024. `x^n` for n > 0 is the exact power rounded once; n = 0 gives 1 (also for x = 0); n < 0 is 1 divided by the exact power, correctly rounded; 0 to a negative power is `E_FORMULA_DIV_ZERO`. Before computing, a magnitude estimate that already exceeds the range rule fails with `E_FORMULA_RANGE` |
| `sqrt(x)` | correctly rounded square root (round-half-even); x < 0: `E_FORMULA_DOMAIN` |
| `abs`, `floor`, `ceiling` | exact |
| `round(x, n)` | Excel `ROUND`: half **away from zero** at n decimals (n an integer, may be negative); `round_up`/`round_down` away from / toward zero. These are explicit operations; the arithmetic itself always rounds half-even |
| `mod(a, b)` | Excel `MOD`: `a - b * floor(a / b)` with the quotient exact, sign of `b`; b = 0: `E_FORMULA_DIV_ZERO` |
| `sum` | exact sum of all members, rounded once (order-independent) |
| `mean` | exact sum divided by the count, rounded once |
| `median` | odd count: the middle member's value; even count: the exact sum of the two middle values divided by 2, rounded once |
| `stdev` (sample), `stdev_p` (population) | a fixed sequence: `m = mean`; `ss` = the exact sum of `(x_i - m)^2` (each exact), rounded once; `v = ss / (n - 1)` (or `/ n`), rounded once; result `sqrt(v)`, correctly rounded. `stdev` needs at least two members, `stdev_p` one (`E_FORMULA_EMPTY`) |
| `min`, `max` | exact comparison; ties are equal values |

`stdev` is therefore not the correctly rounded true standard deviation, but it is a fixed
sequence of correctly rounded steps, which is what determinism needs. Non-integer powers, `exp`,
`ln`, `log` and trigonometry are not in 0.4.0: no float-free correctly rounded algorithm is
required of every evaluator for them yet (they are listed as unsupported in the Excel table).

### 4.3 Reference

The Python reference evaluator implements this with integers (coefficient and exponent) and its
own rounding, which is the algorithm a Rust implementation will follow (34 digits fit in a
`u128` coefficient; products and quotients need a 256-bit or big-integer intermediate). A test
compares it with Python's `decimal` on 10,000 random cases per operation, using
`Context(prec=34, rounding=ROUND_HALF_EVEN, Emin=-6143, Emax=6144, clamp=0,
traps=[InvalidOperation, DivisionByZero, Overflow])` plus the range rule. The exponent limits are
stated for completeness: because every operand satisfies the range rule, no single operation can
come near them, so the context never overflows or goes subnormal. `decimal`'s `sqrt` and
division are correctly rounded by specification; integer powers are computed exactly with
Python integers and rounded with `Context.create_decimal`, because `decimal`'s own `power` is not
guaranteed to be correctly rounded. No float appears anywhere.

---

## 5. Unit algebra

### 5.1 Internal units

Inside the checker a unit is a map from **atoms** to non-zero integer exponents; the empty map is
`1`. An atom is either a literal unit symbol from `units.md`, treated as indivisible (`kWh`, `m/s`
and `W/m2` are atoms, as `units.md` says), or `arg:<name>`, the value of a string argument of the
function being defined. Index units are atoms. These unit expressions never appear in hashed
data and are never written by users; they exist only while checking.

Declared units map in directly: a literal is its atom with exponent 1 (`"1"` is the empty map);
`{"arg": "q"}` is `arg:q`; a rate `{"of": X, "per": Y}` is `X^1 Y^-1`.

A read's unit is the callee's declared return unit with its argument references substituted by
the units of the expressions bound to them: a string literal that is a listed unit gives that
atom; a variable that is one of the caller's own string arguments gives `arg:<caller arg>`;
a `let` name bound to one of those gives the same. Anything else is `E_FORMULA_UNIT_UNKNOWN`.
An argument reference to an open argument makes the slice's element unit vary by member; such a
slice can only be counted or filtered (`E_FORMULA_UNIT_UNKNOWN` otherwise).

### 5.2 Operators

- `*`, `/`: exponents add or subtract. `^ n` with `n` an integer literal multiplies them; a
  non-literal exponent needs a dimensionless base (`E_FORMULA_EXPONENT`). `sqrt` halves even
  exponents and rejects odd ones.
- `+`, `-`, comparison, both branches of `if`, the variadic aggregates, `otherwise`: units must
  be equal maps (`E_FORMULA_UNIT_MISMATCH`), except for bare literals (5.3).
- A read argument declared with a unit must receive that unit (after substitution); the body's
  unit must equal the declared return unit (`E_FORMULA_RETURN_UNIT`).
- `count` returns `count`. `sum`, `mean`, `min`, `max`, `median`, `stdev`, `first`, `last`, lookups
  and `interpolate` keep the element unit.
- `convert(x, "u")` converts between units of one group by an exact decimal factor: `1`,
  `percent`, `permille`, `bp`; `mm`, `cm`, `m`, `km`; `s`, `min`, `h`, `d`; and `degC` to `K`
  (adds 273.15) and back. Anything else is `E_FORMULA_UNIT_MISMATCH`. There are no implicit
  conversions.

**FX forward.** With `fx_rate(base, date, quote)` returning `{"of": {"arg": "quote"}, "per": {"arg": "base"}}`
and an interest rate `rate(currency, tenor)` in `1`, the body

```
rates.example.org/fx_rate(base: base, date: date, quote: quote)
  * (1 + rates.example.org/rate(currency: quote, tenor: tenor))
  / (1 + rates.example.org/rate(currency: base, tenor: tenor))
```

has unit `arg:quote^1 arg:base^-1`, which equals the declared
`{"of": {"arg": "quote"}, "per": {"arg": "base"}}`: quote per base. With rates in `percent` the
check fails, as it should, until the author writes `convert(r, "1")` or `r / 100 percent`.

### 5.3 Bare literals and "dimensionless `1` mixes with anything"

The brief's rule is read as follows (this needs the user's confirmation, 17.3):

- A **bare literal** (a number without a suffix) is dimensionless in `*`, `/` and `^`, so
  `price * 1.2` is in the unit of `price`.
- In `+`, `-`, comparison, `if` branches, `otherwise`, call arguments and the return, a bare
  literal takes the unit its context requires: `amount > 0`, `price + 10`, `if c then x else 0`.
- **Except** when that unit is a scaled ratio (`percent`, `permille`, `bp`), where only `0` is
  accepted: `1 + r` with `r` in percent is `E_FORMULA_UNIT_MISMATCH`, because the classic error
  is reading it as 101 %. Write `1 + r / 100 percent`, `1 percent + r` or `convert(r, "1")`.
- A **value** whose declared unit is `1` (an argument, a cell) is the identity in `*` and `/`,
  but in `+` and `-` it needs `1` on the other side: `x_eur + ratio` is an error.

*Alternative:* bare literals are always `1`, so `price + 10` fails. Rejected: comparisons with
zero and small constants are the commonest formulas there are, and an explicit unit there adds
nothing.

### 5.4 Offset units

`degC` is an offset unit ("a temperature, not a temperature difference", `units.md`). The
checker treats it as affine:

- `degC - degC` is `K` (a difference); `degC + K` and `degC - K` are `degC`; comparison of two
  `degC` is allowed; a bare literal added to `degC` takes `K`.
- `degC + degC`, `degC * x` and `degC / x` (for any `x`, *amended*), and `sum` over `degC`, are
  `E_FORMULA_UNIT_OFFSET`.
- Affine combinations are allowed: `mean`, `median`, `min`, `max`, `first`, `last`, lookups,
  `interpolate`; `stdev` of `degC` is in `K`.

So `(a + b) / 2` over two temperatures fails, and `mean(a, b)` works. *Alternative:* treat
`degC` as an ordinary unit. Rejected: the brief asks the question, and `units.md` already says
what `degC` means.

### 5.5 Durations and new units

Bounds and date arithmetic need durations. Proposed additions to `units.md` (a list revision; no
hash changes): `min`, `h`, `d` (day) and `km`. `s` and `m` exist. `km` is added now so that the
spatial example of the decision log lexes (8.1). Instant minus instant is a number in `s`
(exact, at most six decimals); instant plus or minus a duration is an instant (the duration in
any of `s min h d`, converted exactly to microseconds; a non-integer microsecond is
`E_FORMULA_DOMAIN`). Date minus date is a number in `d`; date plus or minus an integer number of
`d` is a date. A bare literal added to a date takes `d` (`d + 30`, as in Excel), to an instant
`s`.

A verifier still never checks a value against its unit (7.1); everything here happens at define
time.

---

## 6. Slices

### 6.1 Writing a slice

A read with at least one argument written `*` or `[lo..hi]` is a slice: `temp(station: "kew", t: *)`,
`daily(date: [2016-01-01..d])`. The other arguments are expressions as in a cell read; the
bounds are expressions of the argument's type, inclusive at both ends. `lo > hi` at evaluation
is `E_FORMULA_DOMAIN` (likely a bug; an empty result would hide it).

### 6.2 Membership as of A

Membership is taken at the evaluation asof A.

- **Stored function** (`lang = "stored"`): the cells of the function, with the function hash the
  name resolves to as of A, whose arguments match the pattern (bound arguments equal, ranges
  contain), and which have a version answering as of A (`tx` and `asof` at or before A, the
  engine's rule). Each member's value is that version's value.
- **Any other language**: the cells given by the declared extent (6.3) intersected with the
  pattern. Every one of them must have a value as of A, or the read is `E_FORMULA_ABSENT` as a
  whole, so the lineage never has to prove an absence it did not record.

### 6.3 Declaring an extent

A new optional member of an argument declaration: `extent`. It is either an array of lexical
values of the argument's type, strictly ascending in the type's order and unique, at most 4096
entries (`E_CANON_SET`, `E_CANON_LIMIT`), or, for `date` and integer-valued `number` arguments,
a range object `{"hi": …, "lo": …}` enumerated daily or by 1.

```json
"tenor": {"extent": ["10Y", "1M", "1Y", "2Y", "3M", "5Y", "6M"], "type": "string", "valid": false}
```

An absent member changes nothing, so **no existing descriptor's hash changes** (7, D23's
argument). Older verifiers reject a descriptor with `extent` as `E_SCHEMA`; that affects only new
descriptors, which they could not evaluate anyway. *Alternative:* a signature-level `extent`
object, or a descriptor-level member. Rejected: the per-argument member keeps an argument's
whole declaration in one place, and the descriptor keeps its three members. *Alternative:* an
extent given by another function (the decision log's class "keys" enumerator). Deferred to 1.3b,
where class extents are designed; it would make membership a read, which works with slice
lineage but needs its own rules.

### 6.4 "An unbounded slice over a function with no declared extent"

Precisely: at define time, a read of function `g` (as bound at define time) with argument `a`
written `*`, where `g`'s `lang` is not `stored` and `g`'s declaration of `a` has no `extent`.
Then `E_FORMULA_UNBOUNDED`. A range on such an argument is accepted only when the argument's type
is enumerable (a `date`, or a `number` whose bounds evaluate to integers) and both bounds are
present; a range over a string, instant or non-integer number argument of such a `g` is
`E_FORMULA_UNBOUNDED`. A range over boolean or blob is `E_FORMULA_SLICE_BOUND` for any `g`.
If `g`'s name is later rebound to a function failing this rule, evaluation fails with the same
code.

Stored functions need no declaration: at any asof their recorded cells are finite. An unbounded
slice over a long stored history is accepted and costs its member count in fuel (section 10);
the pattern for large histories is a bound (lookups narrow their slice, 8.1) or intermediate
aggregation cells, as the decision log says.

### 6.5 Order and empty slices

Members are ordered by key tuple: the open arguments in ascending name order, each compared in
its type's order (numbers numerically, dates and instants chronologically, strings by code
point, `false` before `true`, blobs by their lexical form). `first`, `last`, scans, `window` and
lookups use this order. The order never depends on positions in the source.

On an empty slice: `sum` is 0 in the element unit, `count` is 0; every other aggregate and every
lookup is `E_FORMULA_EMPTY`/`E_FORMULA_ABSENT` (catchable by `otherwise`).

### 6.6 Queries this implies

For the library steps (named here, implemented there):

- store: `slice_members(fn_hash, pattern, A)`: the member cells and the receipt answering each as
  of A, with range predicates on typed arguments (an index over typed argument columns); and
  `versions_between(cell_id, from, to, A)` (8.4);
- store: `put_manifest` and `manifest(entry)` (section 7);
- engine: a dependents index from (function hash, pattern) to the memoised answers that read the
  slice, so that `stored_version_added(cell)` dirties every slice the new cell falls into (a late
  sample, a correction) and nothing else;
- engine `Inputs`: `read_slice(fn, pattern)`, `read_asof(fn, args, T)`, `read_versions(fn, args,
  from, to)`, and the evaluation asof (`asof()`), all additive;
- core `Resolver`: `manifest(entry)` and, for 11.2, an evaluation that also returns its lineage.

---

## 7. Slice-as-lineage

### 7.1 The slice object and its id

A **slice object** is a cell object (4.4) in which at least one argument is the slice marker
`"*"` or a **range object** `{"hi": "<lexical>", "lo": "<lexical>", "type": "<type>"}`. For an
unbounded slice it is exactly the cell-with-markers object that 4.4 already allows, so its id is
the id 4.4 already defines (the vector `cell/slice` is such an id). A range object is allowed
only in slice objects; a receipt's cell still has neither (`E_SLICE`). The **slice id** is
SHA-256 of the slice object's canonical bytes.

A **version slice** (8.4) is `{"cell": <cell>, "from": <instant>, "to": <instant>}`.

Bounded slices have no cell URI in 0.4.0 (5.1 is unchanged). Lookups that narrow their slice
(8.1) record the narrowed slice object.

### 7.2 The members hash and the entry

The **members** of a read are the receipt hashes of its member cells' answering receipts (for a
version slice, of the versions), sorted ascending, no duplicates. The **members hash** is
SHA-256 of the canonical bytes of that JSON array of strings (`["h1","h2",…]`; for an empty slice,
of `[]`).

The `inputs` entry is the string

```
slice:<slice id>:<members hash>
```

135 characters: `slice:`, 64 lowercase hex digits, `:`, 64 lowercase hex digits. It is one entry
for the 4,096 limit. `inputs` stays a set of strings in ascending order (UTF-16 code unit order,
which on ASCII is byte order), so plain receipt hashes (`0-9a-f…`) sort before every slice entry
(`s…`). A receipt whose inputs are single cells has no slice entry, so its bytes are exactly
those of spec-0.3.0. The same slice read twice in one evaluation gives one entry.

*Alternatives:* `<slice id><members hash>` without separators (128 hex digits; not
self-describing, and a future entry kind would have no room), a JSON object entry (would change
`inputs` from an array of strings, so every library's step 2 would change), or a Merkle root
(allows proofs of single membership; deferred: a flat hash is enough while manifests are fetched
whole, and the entry form can carry another prefix later).

### 7.3 The manifest

```json
{"members": ["<receipt hash>", …], "slice": <slice object>}
```

A manifest is fetched by its entry. A mesh SHOULD serve it at
`https://<mesh>/slice/<slice id>/<members hash>` as `application/json`; libraries take it from a
resolver, like descriptors and receipts. Its members are fetched as receipts, by hash. A
manifest's members are at most 1,048,576 (`E_CANON_LIMIT`).

### 7.4 What the signer asserts

8.2's assertion is extended: by signing, `computed_by` asserts that each single-cell input was the
latest version of its cell as of the receipt's `asof`, except an input read at an explicit
transaction time `T` (8.4), which it asserts answered as of `T`; and that each slice entry's
members were exactly the slice's members as of the receipt's `asof`. Completeness of a stored
slice is the signer's statement, like currency: a verifier can check that every listed member
belongs to the slice, not that no member is missing.

### 7.5 Verification (10.1)

- **Step 2** is unchanged: `inputs` is an array of strings.
- **Step 3**: each entry is either 64 lowercase hex digits or a slice entry as in 7.2; anything
  else is `E_CANON_HEX`, as today. Then ascending and unique (`E_CANON_SET`), then the count
  (`E_CANON_LIMIT`).
- **Step 7.5**, for a slice entry, in order:
  1. obtain the manifest (`E_INPUT_UNAVAILABLE` if none); parse it strictly and check its
     structure (`E_SCHEMA`) and canonical form (the codes of 4, including `E_CANON_SET` for
     members);
  2. its slice object hashes to the entry's slice id and its members array to the members hash
     (`E_INPUT_UNAVAILABLE`, as for a receipt that has another hash);
  3. the slice's function (`ns/fn`, or the version slice's cell's) is in the descriptor's
     `inputs` (`E_INPUT_UNDECLARED`);
  4. for each member hash in order: obtain the receipt (`E_INPUT_UNAVAILABLE`), verify it through
     step 6 (`E_INPUT_INVALID`), check its hash (`E_INPUT_UNAVAILABLE`), check that its cell
     belongs to the slice (same `ns`, `fn` and `fn_hash`, the same argument names, bound
     arguments equal, ranged arguments of the range's type and within it; open arguments may hold
     any value, their types being checked by the member's own descriptor; for a version slice, the
     same cell and
     a `tx` within `[from, to]`) and that no two members of a membership slice are one cell
     (new code **`E_SLICE_MEMBER`**), and that its `asof` is at or before the receipt's
     (`E_TIME_ORDER`).
- **The `tx` rule** reads: if there is at least one input receipt (single-cell inputs and slice
  members together), `tx` equals the latest of their `tx`s. A receipt whose only inputs are empty
  slices has no input receipt and no `tx` constraint, like a function that reads nothing.

*Why a new code:* `E_INPUT_UNDECLARED` says the lineage names a function the code may not read; a
receipt listed under a slice it does not belong to is a different lie, and a reader should be
able to tell them apart.

**What a verifier at level `signed` must do:** accept slice entries in step 3 (pattern, order,
count). Nothing else changes; a receipt that is signature-valid under spec-0.3.0 has the same
result. **At level `recomputed`:** the manifest and member checks above, the revised `tx` rule,
and 11.2. **What the resolver must supply:** descriptors (as now), receipts by hash (members
included), manifests by entry, and the evaluation (as now; optionally with its lineage, 11.2).

The Python and JavaScript verifiers in this step need exactly these; they do not need a formula
evaluator, because evaluation comes from the resolver (or the vector's `recompute.value`), as for
every other language.

### 7.6 Test 7, read literally

The brief's test 7 says a weighted mean over 1,000 stations "records one slice input". With the
weights in a second function, `sum(temp(*, d) * weight(*)) / sum(weight(*))` reads two slices and
records two entries, one per slice, instead of 2,000 receipt hashes. *(Decided after review: two
entries are acceptable.)*

---

## 8. Lookups, scans, transaction-time reads, dates, text

### 8.1 Lookups

All lookups take a slice and work **along one dimension**: the only open argument if there is one;
otherwise the only open valid-time argument; otherwise the one named with `along: name`
(`E_FORMULA_ALONG` when none of these picks exactly one). The other open arguments are group
keys: a lookup over a k-dimensional slice gives a (k-1)-dimensional slice, or a scalar when
k = 1. So `mean(last_before(temp(*, *), t, 10 min))` is the mean over stations of each station's
last reading at or before `t` within ten minutes: the decision log's real-time aggregate at a
declared cadence (`t` is a valid-time argument of the function computing it).

**Metric from the argument type**: instants: duration; dates: days; numbers: absolute difference
in the argument's unit; `point` (1.3b): geodesic distance. Strings, booleans and blobs have no
metric: only `at` and the order-based aggregates apply (`E_FORMULA_METRIC`). The bound, when
given, is a quantity in the metric's unit (`10 min`, `3 d`, `0.5` in the argument's unit).

| Lookup | Value |
|---|---|
| `at(s, k)` | the member whose key equals `k`; otherwise absent |
| `latest(s)` | the last member along the dimension |
| `latest(s, bound)` | the same, absent if its key is earlier than `asof() - bound`; asof-dependent (section 9) |
| `last_before(s, x, bound?)` | the member with the greatest key **at or before** `x` (and within the bound) |
| `first_after(s, x, bound?)` | the member with the least key **at or after** `x` (and within the bound) |
| `nearest(s, x, bound?)` | the member with the least distance to `x`; on a tie, the earlier key |
| `within(s, x, bound)` | the slice of members within the bound of `x` (a slice, for aggregates) |
| `interpolate(s, x, method: "linear" \| "step", bound?)` | `step`: as `last_before`. `linear`: a member at `x` exactly gives its value; otherwise the neighbours `(x0, v0)` before and `(x1, v1)` after, both required (no extrapolation) and both within the bound of `x`, give `v0 + ((v1 - v0) * (x - x0)) / (x1 - x0)`, evaluated as dialect operations, each rounded. Number values only |

"At or before" rather than strictly before, because a sensor reading taken exactly at `x` is the
one wanted (kdb's as-of join does the same); `at` covers exact matches. **A bound narrows the read**:
`last_before(f(a, *), x, b)` reads, and records in lineage, the slice `f(a, [x - b..x])`;
`first_after` `[x..x + b]`; `nearest`, `within` and `interpolate` `[x - b..x + b]`; `latest(s, b)`
`[asof() - b..9999-12-31T23:59:59.999999Z]`. The narrowing is semantics, not an optimisation:
two evaluators record the same entry. Without a bound, the whole slice is read.

Enumeration words (`method`, `convention`, `roll`, `weekend`, and the aggregate of `scan` and
`window`) must be literals from their lists (`E_FORMULA_ENUM`), so they are static.

**The spatial example.** `interpolate(latest(temp(within(stations, p, 20 km), *)), p)` parses (with
`km` added to `units.md`, 5.5). It does not check in 0.4.0: a read argument bound to a key set
(`within(…)` in `temp`'s station position) and the `point` metric are `E_FORMULA_UNSUPPORTED`
until 1.3b defines `point` and class extents. The metric dispatch is in the checker now, with
`point` mapped to "unsupported". Its lineage is statically derivable (the base slices of
`stations` and `temp`), so it raises no stop condition; geodesic distance does raise a float risk
for 1.3b (16.2).

### 8.2 Scans

`scan`, `map`, `filter` and `window` produce slices; only aggregates, lookups and other scans
consume them (a function returns a scalar).

- `map(s, x -> e)` / `map(s, (x, k1, …) -> e)`: same keys, value `e`. The first parameter is the
  member's value; further parameters must be open argument names of `s` and are bound to the
  member's key values (`E_FORMULA_LAMBDA_PARAM`). Parameters may not shadow names in scope
  (`E_FORMULA_SHADOW`).
- `filter(s, x -> p)`: the members for which `p` is true.
- `scan(s, agg)`: same keys; each value is `agg` over the members up to and including it, along the
  dimension (8.1), per group.
- `window(s, n, agg)`: `agg` over the trailing `n` members including the current one; members with
  fewer than `n - 1` predecessors in their group are omitted. `n` is an integer of at least 1
  (`E_FORMULA_DOMAIN`).
- **No cell reads inside a lambda** (`E_FORMULA_LAMBDA_READ`). A per-member read would add one
  receipt per member to the lineage, the very thing slices exist to avoid; data from another
  function is joined instead.
- **Implicit join** (decision log): `+ - * /` between two slices with **the same open argument
  names and key types** is an inner join on keys; between a slice and a scalar, the scalar
  applies to every member. Different key sets are `E_FORMULA_JOIN`. Partial and outer joins, and
  joins in comparisons, are not in 0.4.0. *Alternative:* leave joins to 1.3b. Rejected: without
  them, a weighted mean or `SUMPRODUCT` needs per-member reads, which this design forbids.

Test 9's running total is `sum(daily(date: [2016-01-01..d]))`, one cell per `d`, each with one slice
entry; a correction to a day dirties exactly the cells whose ranges contain it.

### 8.3 `otherwise`, evaluation order

See 3.5 and 8.9.

### 8.4 Transaction-time reads

- `asof(c, T)`: `c` must be a single-cell read (`E_FORMULA_TX_ARG`). The value of the version of
  `c` answering as of `T` (the engine's rule). `T` after the evaluation asof is `E_FORMULA_FUTURE`:
  the future of the evaluation is unknown, and a clamp would hide the mistake. The receipt read is
  an ordinary single-cell input; its `asof` is at or before `T`, so 8.2's `asof` rule still holds.
- `versions(c, from, to)`: the slice of `c`'s versions with `tx` in `[from, to]`, as of the
  evaluation asof (`to` after it: `E_FORMULA_FUTURE`). Its one open dimension is `tx` (an instant),
  so `count(versions(…))` counts corrections and `last(versions(…))` is the latest of them. Its
  lineage is a version-slice entry (7.1).
- **`first_known`, `last_corrected`, `superseded` are not in 0.4.0.** Each is a short formula over
  `versions` and a lambda key parameter, e.g. `first(map(versions(c, 0001-01-01T00:00:00.000000Z, asof()), (v, tx) -> tx))`.
  They belong in the standard library under `datumesh.com/std/` with the decision log's views
  (`current`, `change`, `sampled`, `moving`), as published formula functions, once the standard
  library exists; built-ins are hard to change and these are easy to express. *Alternative:* add
  them as built-ins now. Rejected for that reason.

### 8.5 Calendars and dates

A calendar is data, so it is a **slice argument**: a slice whose single open argument is a date; a
date is a holiday when it is a member. `add_days(d, 5, calendar: datumesh.com/std/holiday(calendar: "gb-eaw", date: *))`.
It is therefore an input, statically named, in lineage, and its changes dirty its readers. The
weekend is a parameter, `weekend: "sat-sun"` (default), `"fri-sat"`, `"sun"` or `"none"`, because
weekends differ by country and are not usually in holiday data.

- `add_days(d, n, calendar?, weekend?)`: without a calendar `d + n d`; with one, `n` business days
  (Excel `WORKDAY`; `n = 0` gives `d`).
- `add_months(d, n, calendar?, roll?)`: Excel `EDATE` (day clamped to the month's last day); with a
  calendar, rolled to a business day by `roll`: `"following"`, `"modified_following"`,
  `"preceding"`.
- `business_days(a, b, calendar?, weekend?)`: Excel `NETWORKDAYS` (both ends inclusive).
- `is_holiday(d, calendar)`; `end_of_month(d)`; `date(y, m, d)`; `year`, `month`, `day`;
  `weekday(d)` (ISO: Monday 1).
- `year_fraction(a, b, convention)`, `convention` one of `"act/360"`, `"act/365f"`,
  `"act/act_isda"`, `"30/360"` (ISDA bond basis), `"30e/360"` (Eurobond), `"30/360_us"` (NASD, as
  Excel basis 0). Each is an exact rational, rounded once. Excel's basis 1 is its own
  actual/actual and is listed as not supported (12).

Time zones stay out: local time needs the IANA database, which is data with versions; a later step
can model it as cells.

### 8.6 Text

Strings are NFC (3.5). Lengths and positions count **code points**, 1-based as in Excel.
`len`; `upper`, `lower` (Unicode 15.1 full case mappings, locale-free); `trim` (Excel's: removes
leading and trailing U+0020 and collapses inner runs of U+0020); `concat(a, b, …)` and `&`;
`substr(s, start, length)` (Excel `MID`); `find(needle, haystack, start?)`, case-sensitive,
0 when not found; `text(x)`, the canonical lexical form of any scalar; `fixed(x, n)`, `x` rounded
half away from zero to `n` decimals and written with exactly `n` (Excel `FIXED` without
separators). **Every string result is normalised to NFC** (with Unicode 15.1 data): concatenation
and case mapping of NFC strings need not be NFC. This normalises computed values, not inputs, so
it does not conflict with "rejected, not normalised". A result over 1024 bytes is
`E_FORMULA_RANGE`. Implementations must carry their own Unicode 15.1 case and normalisation
tables (a Rust toolchain's `to_uppercase` follows its own Unicode version).

### 8.7 Instants

Comparison, arithmetic as in 5.5, `date_of(t)` (the UTC date) and `instant(d)` (midnight UTC).

### 8.8 What is not there

`for`, recursion inside a body (recursion is only through cell reads, as the decision log says),
user-defined local functions, mutable state, `iferror` over arbitrary errors, regular expressions,
wildcards, and anything that reads the clock.

### 8.9 Evaluation order

Strict and left to right, except: `if` evaluates only the chosen branch; `and` and `or`
short-circuit; `otherwise` evaluates its fallback only on absence; `let` evaluates its value first,
always. The lineage is exactly the reads performed, so this order is part of the semantics. The
first fault in this order is the one reported.

---

## 9. `asof()` and the receipt's `asof`

`asof()` (the brief's `ASOF()`; any case) is the evaluation asof A, an instant. A body is
**asof-dependent** when it contains `asof()`, or `latest` with a bound (which is defined against
`asof()`). The checker derives this flag statically.

Rule:

- For a function that is not asof-dependent, nothing changes: the receipt's `asof` is chosen from
  its inputs and bindings (11.1), and one receipt answers every asof until the next version.
- For an asof-dependent function, the receipt's `asof` SHOULD be the evaluation asof A (the
  request's `asof`, or the clock reading of the request when none was given). A verifier
  recomputes at the receipt's `asof` and gets the same value. `tx` is still the latest input `tx`
  (or none, 7.5).

Consequence for one-receipt-per-version: **it does not hold for asof-dependent cells**. Their value
may change with A alone, so each distinct requested A has its own receipt, and the engine must not
validate such a receipt for another asof (its memo interval is the single instant A). A mesh
MUST NOT serve an asof-dependent receipt as `ok` for a requested `asof` other than its own
(it would assert currency it cannot know); it evaluates again or answers `stale`. This is a rule
for meshes; the client's binding check (5.5 step 5) is unchanged, so no vector's result changes.

The guidance in the spec: prefer an explicit valid-time argument (`t`) at a declared cadence to
`asof()`. `latest_temp(station, t) = last_before(temp(station, *), t, 10 min)` has one receipt per
version per `t`; `last(temp(station, *))` has one per version; only bodies that really mean "as of
the transaction time" use `asof()`.

*Alternative:* forbid `asof()`. Rejected: the brief fixes it as a constant. *Alternative:* let the
engine choose the receipt's `asof` from inputs anyway. Rejected: the receipt would not recompute at
its own `asof`.

---

## 10. Budget

Fuel is charged per evaluation, normatively, so that two evaluators exhaust a budget at the same
point and a vector can state the fuel used:

| Work | Fuel |
|---|---|
| each AST node evaluated | 1 |
| a single-cell read (engine's charge) | 1 |
| a slice read | 1 + members |
| an aggregate or lookup over n members | n (`median`: n × ceil(log2(n + 1))) |
| `map`, `filter` over n | n × (the lambda body's fuel) |
| `scan` over n; `window` over n with width w | n; n × w |
| `x ^ n` | abs(n) |
| a string operation | 1 + (bytes of the result) / 64, rounded down |

Running out is `E_FORMULA_BUDGET` (the engine's `BudgetExceeded`, mapped to `E_EVAL_UNAVAILABLE`
for the HTTP layer and for a verifier, as today). The engine's default fuel (10,000,000) is enough
for slices of 100,000 members.

**Refused at define time**: unbounded or non-enumerable slices over functions without an extent
(6.4); a range with literal bounds over a computed function whose enumeration exceeds 1,048,576
cells (`E_FORMULA_UNBOUNDED`); AST depth over 256 and more than 65,536 nodes (`E_FORMULA_LIMIT`).
Everything that depends on data (stored slice sizes, recursion depth) is limited at run time.

---

## 11. The three 1.2b items

### 11.1 8.2's SHOULD for computed issuers

Rule 2 becomes: an issuer of a computed receipt SHOULD set `asof` to the latest of: its input
receipts' `asof`s (slice members included); the start of every name binding it relied on (the
names read, transitively, including its own name when it reads itself; the requested cell's own
name excluded, since its receipt pins the hash); every `T` of an `asof(c, T)` read and every `to`
of a `versions` read; or, for an asof-dependent function, the evaluation asof (section 9). Where
an input was kept across a change of its own inputs (early cutoff), its `asof` counts from where
its value is known again, as the engine does. A function that reads nothing and is not
asof-dependent has `tx = asof = 0001-01-01T00:00:00.000000Z`. D33's row is revised: "the SHOULD
was incomplete, not wrong". Still not checked by verification; no vector depends on it.

### 11.2 `E_INPUT_SUPERSEDED`

When an input of a receipt has been superseded at a `tx` earlier than the receipt's own `tx` (a
backdated correction, or for a slice a late member), re-evaluating at the receipt's `asof` reads
the new version and gives another value. The receipt is historical, not wrong.

- **Where.** Step 7.6, only when the evaluated value differs from the receipt's.
- **What the resolver supplies.** With the value, the evaluation's lineage: the `inputs` entries it
  read, with their receipts and manifests. (The core's `Resolver::evaluate` gains a variant that
  returns them; in vectors, `recompute.lineage`.)
- **Rule.** If at least one entry of the receipt's `inputs` is replaced in the evaluation's lineage
  by an entry for the same cell with a later `tx` (same cell id; its receipt signature-valid
  through step 6) or for the same slice id with another members hash, the result is **success at
  level `signed`, with `E_INPUT_SUPERSEDED` reported** (path `$.inputs`), not `E_VALUE_MISMATCH`.
  Otherwise `E_VALUE_MISMATCH` as today. Step 7.7 runs after it as after `E_EVAL_UNAVAILABLE`.
  Without a lineage there is no supersession check, so every existing vector keeps its result.
- **Why not a failure.** Like `E_EVAL_UNAVAILABLE` (D34): the receipt is signature-valid, its inputs
  were verified in 7.5 and pinned by hash, and the signer's statement was true when made. Failing
  it would call a correct historical statement invalid. The envelope's `superseded_by` already
  tells a client that a newer version exists.
- No hash changes: nothing is added to receipts.

10.2 gains `E_INPUT_SUPERSEDED` (not a failure) and `E_SLICE_MEMBER` (failure).

### 11.3 The six wording gaps

| Gap | Settled by |
|---|---|
| DEF-40 (Python): a descriptor given as text in an API that also takes values | 7.1 gains the proposed sentence: "An implementation whose interface also takes text in place of a parsed value says which it takes; text is then the obtained bytes." |
| DEF-41 (Python): no code when step 7 is not attempted | 7.6 gains: "A verifier that does not attempt step 7 reports no code." |
| JS 36: a JS string descriptor is JSON text | Covered by DEF-40's sentence; 11 adds that a runner whose API reads strings as text passes a vector's `descriptor` as its JSON serialisation. No rule changes. |
| JS 37: `status` of `200.0` | 11: "In an `env`, `status` is an integer HTTP status written without fraction or exponent, or the string `"error"`." The vector schema enforces it. |
| RS-29: a `recompute.inputs` entry that is not a string | 11: "Entries are always JSON strings; an entry that is not a string is a malformed vector", enforced by the vector schema (the same for the new `manifests` map). *Alternative:* treat it as an input offered (`E_INPUT_INVALID`). Rejected: it is not a receipt anyone could obtain. |
| RS-30: wording of the envelope `error` member | 5.5: "For `error`, any code in 10.2 except `E_ENVELOPE` (a client's code), for example `E_INPUT_UNAVAILABLE`, or `E_EVAL_UNAVAILABLE` when the mesh could not evaluate the cell's function." |

---

## 12. Excel compatibility table

A new SPEC section (or an appendix, normative for the "supported" column): one row per Excel
function with columns **Excel**, **Status** (`supported`, `partial`, `not supported`),
**Formula equivalent** (supported and partial), **Differences or reason**, **Vector** (the
equivalence vector's id). Excel's ranges become slices; Excel's positions become keys.

| Excel | Status | Formula | Differences or reason |
|---|---|---|---|
| `SUM` | supported | `sum(s)`, `sum(a, b, …)` | exact decimal, not double |
| `AVERAGE` | supported | `mean(s)` | |
| `COUNT`, `COUNTA` | supported | `count(s)` | members are typed, so no "counts numbers only" |
| `MIN`, `MAX` | supported | `min(s)`, `max(s)` | empty slice: absent, not 0 |
| `MEDIAN` | supported | `median(s)` | |
| `STDEV.S`, `STDEV.P` | supported | `stdev(s)`, `stdev_p(s)` | fixed rounding sequence (4.2) |
| `IF` | supported | `if c then a else b`, `if(c, a, b)` | |
| `IFS` | partial | `if c1 then v1 else if c2 then v2 else …` | needs a final `else`; Excel's `#N/A` has no equivalent |
| `AND`, `OR`, `NOT` | supported | `a and b`, `and(a, b)`, `not a` | operands must be booleans |
| `ROUND`, `ROUNDUP`, `ROUNDDOWN` | supported | `round`, `round_up`, `round_down` | half away from zero, as Excel |
| `INT`, `FLOOR.MATH`, `CEILING.MATH` (one argument) | supported | `floor`, `ceiling` | |
| `MOD` | supported | `mod(a, b)` | |
| `ABS` | supported | `abs(x)` | |
| `POWER`, `^` | partial | `x ^ n` | integer exponents only |
| `SQRT` | supported | `sqrt(x)` | correctly rounded |
| `SUMPRODUCT` | supported | `sum(a(*) * b(*))` | arrays joined on keys, not positions |
| `SUMIF`, `SUMIFS` | partial | `sum(filter(s, x -> x > 5))`, keys via lambda parameters | criteria strings become predicates; wildcard criteria (`"a*"`) not supported |
| `AVERAGEIF(S)`, `COUNTIF(S)` | partial | `mean(filter(…))`, `count(filter(…))` | as `SUMIF` |
| `VLOOKUP`, `HLOOKUP` | partial | exact: `at(s, k)`; approximate (`TRUE`): `last_before(s, k)` | by key, not column index; the looked-up function is the column |
| `XLOOKUP` | partial | `at`; match mode -1: `last_before`; 1: `first_after`; `if_not_found`: `otherwise(at(s, k), d)` | wildcard and binary-search modes not supported |
| `INDEX` + `MATCH` | partial | `at(s, k)` | positions have no meaning in a slice; `MATCH` alone not supported |
| `EDATE` | supported | `add_months(d, n)` | |
| `EOMONTH` | supported | `end_of_month(add_months(d, n))` | |
| `NETWORKDAYS` | supported | `business_days(a, b, calendar: …)` | holidays are a calendar slice; weekend parameter |
| `WORKDAY` | supported | `add_days(d, n, calendar: …)` | as `NETWORKDAYS` |
| `YEARFRAC` | partial | `year_fraction(a, b, "30/360_us" \| "act/360" \| "act/365f" \| "30e/360")` for bases 0, 2, 3, 4 | basis 1 (Excel's actual/actual) not supported; nearest: `"act/act_isda"`, which differs |
| `DATE` | supported | `date(y, m, d)` | no month or day overflow (`DATE(2024, 13, 1)` is a domain error) |
| `YEAR`, `MONTH`, `DAY`, `WEEKDAY` | supported | `year`, `month`, `day`, `weekday` | `WEEKDAY(d)` is `mod(weekday(d), 7) + 1` |
| `TEXT` | not supported | `text(x)`, `fixed(x, n)` | format strings are locale-dependent; translate the common numeric forms only |
| `LEN` | supported | `len(s)` | code points, not UTF-16 units |
| `LEFT`, `RIGHT`, `MID` | supported | `substr(s, 1, n)`, `substr(s, len(s) - n + 1, n)`, `substr(s, i, n)` | code points |
| `CONCAT`, `CONCATENATE`, `&` | supported | `concat(a, b, …)`, `a & b` | result NFC |
| `FIND` | supported | `find(needle, s, start?)` | 0 when not found, not `#VALUE!` |
| `SEARCH` | partial | `find(lower(needle), lower(s))` | wildcards not supported |
| `UPPER`, `LOWER`, `TRIM` | supported | `upper`, `lower`, `trim` | Unicode case mapping |
| `IFERROR`, `IFNA` | partial | `otherwise(x, y)` for absence from slices; arithmetic: `if b = 0 then y else a / b` | arithmetic faults are not catchable (3.5) |
| `NOW`, `TODAY` | not supported | `asof()` (transaction time) or a valid-time argument `t` | purity: no clock (the brief) |
| `RAND`, `RANDBETWEEN`, `RANDARRAY` | not supported | none; publish random values as stored cells | purity: no randomness |
| `INDIRECT` | not supported | none | inputs must be static (the brief) |
| `OFFSET` | not supported | a bounded slice with a static shape | dynamic ranges cannot be derived statically |
| `EXP`, `LN`, `LOG`, trigonometry | not supported | none | no float-free, correctly rounded algorithm required yet (4.2) |
| `VALUE`, `NUMBERVALUE` | not supported | none in 0.4.0 | locale-dependent parsing |

Equivalence vectors use sample inputs on which Excel's binary doubles give exactly the decimal
result (integers, halves, short decimals), each with the Excel formula and Excel's documented
result. Nobody in this step can run Excel; 17.10 asks whether the user wants them checked in a
real Excel before release.

What Excel users will miss first (for the final report): `IFERROR` over arithmetic, `TEXT` format
strings, wildcard criteria, cell positions (`INDEX` by row number, `OFFSET`), `NOW()`, and
non-integer powers.

---

## 13. Vectors and the reference implementation

### 13.1 Vector kinds

All under `vectors/`, described by `schemas/vector.schema.json`, generated byte for byte by the
generators.

| Kind | Input | Outputs when valid |
|---|---|---|
| `formula` | `input` (source), `env`: `{"function": <signature being defined>, "functions": {name: descriptor}, "aliases": {alias: name}}` | `ast` (canonical AST, JCS text), `ast_sha256`, `body` (printed), `inputs` (derived set), `returns` (type and unit), `asof_dependent` |
| `formula-eval` | `descriptor`, `cell`, `asof`, `world` (stored versions by cell: `tx`, `asof`, value, receipt hash; computed cells answered recursively by the reference), `fuel` | `value` (typed scalar), `lineage` (the `inputs` entries), `manifests`, `tx`, `receipt_asof`, `fuel_used` |
| `slice` | `input`: a slice object or manifest | `canonical`, `slice_id`, `members_hash`, `entry` |
| `receipt` (extended) | as now; `recompute` gains `manifests` (entry → manifest text) and optional `lineage` | as now; `code` may also be `E_INPUT_SUPERSEDED` |
| `excel` | `excel` (formula text), `sample` (inputs), `excel_result`, `formula`, `env` | `value`, which equals `excel_result` |

An invalid `formula` vector has `error` (the rule's code) and, for `E_FORMULA_FORBIDDEN`, `token`.
Every invalid vector names exactly one rule.

### 13.2 How many

- `formula`: at least 160 valid and 110 invalid (the brief asks for 100 and 60): every grammar rule
  and precedence row, both sides of every hazard in 1.5, every built-in, and at least one invalid
  vector per `E_FORMULA_*` define-time code.
- `formula-eval`: at least 100, covering every evaluation code, every aggregate and lookup with
  ties, bounds and empties, the weather example at two asofs, FX forward, `fib(90)`, the ten-tenor
  bootstrapped curve, the running total over a narrowed range, offset units, the decimal edge
  cases (half-even ties, 34-digit carries, the 128-character limit, integer powers).
- `slice`: at least 12. `receipt` with slice entries: at least 30 (valid and invalid: entry form,
  order, count, missing or mismatched manifest, member outside the slice, duplicate cell, member
  `asof` later, the `tx` rule with members, empty slices, `E_INPUT_UNDECLARED`, `E_SLICE_MEMBER`,
  `E_INPUT_SUPERSEDED`).
- `excel`: one per supported or partial row (about 45).
- Decimal: 10,000 random cases per operation in tests, and a fixed file of 2,000 cases for other
  languages (`vectors/decimal/cases.json`, one vector).

### 13.3 The reference implementation

`tools/formula.py`, standard library only (`decimal` and `fractions` for checks, integers for the
arithmetic itself): lexer, PEG parser, resolver, checker (types, units, purity, extents, derived
inputs), printer, canonical AST, evaluator over a world with fuel, and the slice-lineage builder.
It is a test tool like `canon.py`: written to be read next to the spec, not for speed.
`tools/canon.py` gains slice entries, manifests, `E_SLICE_MEMBER`, `E_INPUT_SUPERSEDED`, the new
`recompute` members and the new vector kinds. It does not import the Rust crate and is written
before it (step 1.3 part 3 builds the crate against these vectors).

### 13.4 Tests (written first, failing, in their own commits)

`tests/test_formula_grammar.py` (every vector; derived inputs equal the hand-written sets),
`test_formula_print.py` (parse(print(ast)) = ast on 100,000 fuzzed trees; print(parse(s)) is a
fixed point), `test_formula_eval.py`, `test_decimal.py` (the integer arithmetic against
`decimal`), `test_formula_purity.py` (every forbidden name in several cases), `test_units_formula.py`
(the ten mismatch cases; FX forward), `test_slice_lineage.py`, `test_excel.py`,
`test_migration_0_4_0.py` (14), and an extension of `test_fuzz.py` that evaluates 100,000 fuzzed
expressions twice and compares the receipts byte for byte.

### 13.5 Cross-check generators

`crosscheck/generate_formula.py`: random well-typed and ill-typed sources with environments and
worlds, for the Rust crate against the reference (AST hash, body, inputs, value, lineage, fuel,
error code). `crosscheck/generate_slices.py`: random receipts with slice entries, manifests and
members, about half corrupted at each new check, for the Python, JavaScript and Rust verifiers and
the reference tool. Both join `crosscheck/run.sh`.

---

## 14. Migration

`tests/test_migration_0_4_0.py`, in the pattern of `test_migration_0_3_0.py`, against the
`spec-0.3.0` files in git (`3bac3d4`):

1. Every `spec-0.3.0` vector file and example exists at the same path and is **byte-identical**,
   and its expected result is reproduced by the new `canon.py` (no expected result changes are
   planned; any that do must be listed with a reason, as 0.3.0 did).
2. For every receipt in every old vector (inputs, `recompute.inputs`, envelopes), the receipt hash,
   payload and signature computed by the new tool equal the old ones; likewise every cell id,
   function hash and canonical form.
3. **Differential**: the `spec-0.3.0` `canon.py` is loaded from git and run beside the new one on
   100,000 fuzzed receipts and descriptors whose inputs are single cells (and descriptors without
   `extent`); canonical bytes, hashes and verification results must be equal. Then the same fuzzed
   receipts with a slice entry added must be rejected by the old tool at step 3 (`E_CANON_HEX`) and
   accepted by the new one: slice entries are the only new form.

The design changes no hash by construction: receipts gain no member; `inputs` gains an entry form
that only receipts reading slices contain; descriptors gain an optional per-argument member;
`units.md` grows (units are compared as strings and never hashed except inside descriptors that
use them); `lang = "formula"` is new, and `expr` bodies are not reinterpreted. `proto` stays
`datumesh/1`.

---

## 15. Grammar changes to make before 1.3b adds classes

Three, drafted so that 1.3b adds meaning to forms 0.4.0 already parses or reserves, and changes no
existing body.

### 15.1 Method chaining after a call

```
postfix  = primary *( "." name "(" [ call-arg *( "," call-arg ) ] ")" )
```

`rates.example.org/fx_pair(base: "EUR", quote: "USD").forward(tenor: "1M", date: 2026-10-24)`. In
0.4.0, `).` is `E_FORMULA_RESERVED`, so no 0.4.0 body can contain it. `.` binds tighter than
everything (level 2 of 1.4). A method call is a read of the method's function hash with the
object's keys as its first arguments (the decision log's "a method is an ordinary function whose
first arguments are the class keys"), so lineage and inputs derivation are unchanged; bounded
dynamic dispatch adds its declared class set to `inputs`. The AST gains a node `method` that
resolution turns into a `read`, so the canonical AST, and therefore the hash, of a method call
equals that of the equivalent plain read. `this` (reserved now) names the object inside a method
body.

### 15.2 Key literals

The log writes `fx_pair(EUR, USD)` and `forward(1M, …)`. Reserve now: a word with an uppercase
letter not followed by `(` (`EUR`, `GBLO`), and digits directly followed by `D`, `M` or `Y`
(`1M`, `3M`, `10Y`, `7D`), are **key literals**. In 0.4.0 both are `E_FORMULA_RESERVED`, so no
0.4.0 body contains them. In 1.3b a key literal is a string checked against the class's
`key_normalisation` and printed quoted, so it adds no AST node: `fx_pair(EUR, USD)` and
`fx_pair("EUR", "USD")` have one AST and one hash. Units do not collide: they come only after a
number and are lowercase or listed (`1 m` is a metre, `1d` a day, `1M` a month tenor). One
collision remains and is settled now: `1W` is one watt (a listed unit), so a one-week tenor is
written `7D` or quoted.

### 15.3 Class-typed (nested) keys

In 0.4.0 every call in argument position is a read of a value. In 1.3b, when the callee's
parameter is declared with a class reference type, a call in that position is the **object key**,
not a read: `nlp.exeter.ac.uk/sentiment(scripture.example.org/verse(quran, 2, 255), en, sahih)`
passes the verse's key, encoded as its canonical key string, and reads nothing (it is not an
input). The source is the same; only resolution, driven by the callee's declared parameter type,
tells a key from a read. Settle now that (a) the canonical AST gets a separate node kind `key`
in 1.3b, chosen at resolution, printed like a call; (b) 0.4.0 signatures cannot declare a class
type, so every existing body keeps meaning a read; and (c) a key node is never an input. Without
(a), a key would be a `read` node in the AST and inputs derivation would have to special-case it;
without (b), a rebinding could turn an existing read into a key and change a function's inputs.

---

## 16. Stop-condition risks

**16.1 A receipt with single-cell inputs would change hash.** Risks: a new receipt member; a
changed `inputs` encoding; an always-present descriptor member; reinterpreting `expr`; a units
change that alters canonical forms. The design adds none of these: the slice entry is a new string
form used only by receipts that read slices; `extent` is optional and per argument; `formula` is a
new `lang`; units are only added. The migration test (14) proves it, including a differential run
of the old reference tool. Does not hold.

**16.2 Decimal determinism without a float.** Risks: non-integer powers, `exp`/`ln`, `stdev`'s
square root, `median` of two values, interpolation, year fractions, mean. All are either defined
as exact-then-correctly-rounded integer computations (`/`, `sqrt`, integer `^`, rational year
fractions) or as a fixed sequence of such steps (`stdev`, `interpolate`), or excluded (non-integer
powers, transcendental functions). Does not hold for 0.4.0. **Carried to 1.3b**: the geodesic
metric for `point` needs trigonometry; it must be specified as a float-free decimal algorithm with
a fixed number of steps, or the spatial metric hits this stop condition. Flagged now.

**16.3 A grammar rule cannot be made unambiguous.** Every hazard of the contract is settled in 1.5
either by a lexical longest-match rule (qualified names, hyphenated hosts, dates, instants, numbers
against `..`, unit suffixes, `->`), by a sigil (`@` aliases), by ordered choice where only one
reading is valid (`if(` forms, lambdas, `*` markers), or by rejection (`-a^b`, `a^b^c`, comparison
chains, `if` as an operand). The risk is a reviewer's: three rules depend on whitespace
(`a-b.org/f` against `a - b.org/f`, `2024-10-15` against `2024 - 10 - 15`, `10 m/s` against
`10 m / s`). They are deterministic and tested, the printer never produces the close forms, and
17.2 asks the user. Does not hold.

**16.4 Inputs cannot be derived statically for some construct.** Every read is a `read` node whose
callee is a lexical name; values never become names. Constructs that could have read dynamically
were designed out: reads inside lambdas are forbidden (joins instead); calendars are slices;
`asof`/`versions` take a single-cell read; `INDIRECT`/`OFFSET` do not exist. The 1.3b constructs
(key-set arguments, `within` over points, dynamic dispatch) keep static function names, with
dispatch declaring its class set. Does not hold; no construct is proposed for dropping.

**16.5 Other risks** (not stop conditions): test 7's "one slice input" with weights (7.6); slices of
100,000 members against fuel and verifier cost (benchmark in part 3); Unicode tables in Rust for
case mapping; Excel equivalence without a real Excel (12).

---

## 17. Open points for the user (all settled after review; see the top)

1. **Case.** Built-ins and keywords case-insensitive (`SUM`, `ASOF()` accepted; printed lowercase),
   names case-sensitive. Or strict lowercase with a hint?
2. **Whitespace-sensitive tokens.** Hyphenated hosts, bare dates and `/` inside unit symbols decided
   by longest match. Or sigils (`#2024-10-15#`, quoted names)?
3. **Bare literals and units** (5.3): polymorphic except against percent, permille and bp. Is that
   your meaning of "dimensionless `1` mixes with anything"?
4. **`-2^2` and `2^3^2` rejected**, since Excel and mathematics disagree. Or follow Excel?
5. **Test 7**: with weights from a second function the receipt has two slice entries. Is that
   acceptable, or should the test keep weights in one function?
6. **`first_known`, `last_corrected`, `superseded`**: deferred to the standard library (expressible
   over `versions`). Agree?
7. **`E_INPUT_SUPERSEDED` is not a failure**: success at level `signed` with the code, like
   `E_EVAL_UNAVAILABLE`. Or a failure code?
8. **New units** in `units.md`: `min`, `h`, `d`, `km`.
9. **Positional arguments** follow the ascending order of argument names, because signatures have no
   order. Agree, or forbid positional reads of functions with more than one argument?
10. **Excel equivalence**: should the vectors be checked in a real Excel before release?
11. **Evaluation faults give `not_covered`** (3.5), which needs an engine change, rather than an
    `error` envelope.
12. **Asof-dependent receipts**: one per requested asof, and a mesh MUST NOT serve one as `ok` for
    another asof (9).

---

## 18. Draft section 13 rows

| # | Choice | Alternative not taken | Why |
|---|---|---|---|
| D36 | `lang = "formula"`: a body is one expression; the grammar is a PEG with longest-match tokens | A general language; an LR grammar with precedence declarations | The brief; a PEG cannot be ambiguous, and the ordered choices only separate valid from invalid readings |
| D37 | Qualified names are one token beginning with a DNS name (so with a dot); aliases need `@` | Bare aliases resolved by scope | `x/f(y)` stays a division; meaning never depends on what is in scope |
| D38 | Built-ins and keywords case-insensitive, printed lowercase | Lowercase only | Excel users write `SUM`; the stored body is the printed form, so hashed data has one spelling |
| D39 | `-a^b`, `a^b^c` and comparison chains are rejected | Follow Excel (or mathematics) | The two traditions disagree; rejecting is the spec's rule for two readings |
| D40 | Bare ISO dates and canonical instants are literals | `date("…")` or a sigil | Matches the URI and the decision log; only a subtraction nobody writes without spaces is lost |
| D41 | Number literals must be canonical (3.1) | Accept `1.50`, `1e3` and normalise | One spelling in source and body |
| D42 | The function hash covers the printed canonical AST as `code.body`; a non-canonical body is rejected; the AST hash is a test artefact | Hash the AST JSON as the body | The body stays readable; one AST, one body, one hash |
| D43 | *(Replaced by D64 after review.)* | | |
| D44 | `inputs` is derived from the body and must equal the derived set | Declared by the author | The brief |
| D45 | Decimal: exact then round half-even to 34 digits per operation; every intermediate within the 128-character canonical form; no negative zero | decimal128's exponent range for intermediates | Fewer behaviours to reproduce; nothing outside the canonical form could be returned anyway |
| D46 | Integer exponents only, exact then rounded once; `sqrt` correctly rounded; `stdev` a fixed sequence of correctly rounded steps | Non-integer powers via `exp`/`ln` | No float-free correctly rounded algorithm needs to be specified for them |
| D47 | Units as atom-exponent maps over `units.md` symbols and argument references; listed composite symbols are atoms | A unit grammar (UCUM) | D25 stands; the algebra exists only at define time |
| D48 | Bare literals take their context's unit in `+ - <` and are dimensionless in `* /`, except against scaled ratios | Bare literals always `1` | `amount > 0` must work; `1 + r_percent` must not |
| D49 | `degC` is affine | An ordinary unit | `units.md` says it is a temperature, not a difference |
| D50 | Extent is an optional per-argument `extent` member; stored functions' extent is their recorded cells | A signature- or descriptor-level member; extents from another function | No existing hash changes; the descriptor keeps three members; function-defined extents wait for classes |
| D51 | An open or non-enumerable range argument over a non-stored function without an extent is refused at define time | Refuse at run time | The brief; stored histories are limited by fuel instead (decision log) |
| D52 | Members are ordered by key tuple, open arguments in name order | Source order | Independent of how the read was written |
| D53 | A slice entry is `slice:<slice id>:<members hash>`; the slice id is the id of the slice object (4.4 with range objects); the members hash is over the sorted member receipt hashes | No separators; an object entry; a Merkle root | Sorts after plain hashes, self-describing, one string; Merkle can come later as another prefix |
| D54 | Manifests `{members, slice}` fetched by entry | Members inline in the receipt | Keeps receipts small; that is the point |
| D55 | New code `E_SLICE_MEMBER` for a member outside its slice | Reuse `E_INPUT_UNDECLARED` | A different lie, which a reader should be able to tell apart |
| D56 | Lookups take the metric from the argument type, work along one dimension per group, and a bound narrows the recorded slice | A separate "group by"; read whole slices | Real-time aggregates at a cadence become one bounded slice per cell |
| D57 | No cell reads inside lambdas; slices join on equal open argument names | Per-member reads | Per-member reads would bring back the 4,096-entry problem |
| D58 | Evaluation faults give no value: `not_covered`, with the fault code in the envelope's optional `fault` member; `otherwise` catches only slice-proved absence | Excel-style error values; catch everything; an `error` envelope | There is no null; only slice absence is in the lineage; a fault is a property of the cell, not a failure of the mesh, but must not look like missing data |
| D59 | `asof()` is the evaluation asof; an asof-dependent receipt's `asof` is the evaluation asof, and it is not reused for other asofs | Forbid `asof()`; choose `asof` from inputs | The receipt must recompute at its own `asof` |
| D60 | `first_known`, `last_corrected`, `superseded` deferred to the standard library | Built-ins now | Expressible over `versions`; built-ins are hard to change |
| D61 | Calendars are slices; weekends a parameter | A built-in holiday table | Data is cells: lineage, versions, licences |
| D62 | `E_INPUT_SUPERSEDED` (7.6) is success at level `signed` with the code, raised when the resolver's lineage replaces an input by a later version of the same cell or slice | A failure; a bare `E_VALUE_MISMATCH` | The receipt is historical, not wrong (D34's reasoning) |
| D33 (revised) | The computed `asof` SHOULD also include binding starts, explicit transaction times read, and the evaluation asof for asof-dependent bodies | Input `asof`s only | The SHOULD was incomplete, not wrong |
| D63 | Normative fuel table | Implementation-defined fuel | Two evaluators exhaust a budget at the same point; vectors can state fuel |
| D64 | Positional arguments bind by an optional, hashed `signature.order` listing every argument once; formula descriptors always carry it; positional before labelled; a positional read of a function without `order` is refused at define time; the canonical AST is labelled (decided after review) | Ascending name order; a required `order`, which would change every descriptor and receipt hash; positional arguments only for one-argument functions, or labels only | Authors and readers expect the declared order; optional means no existing hash changes; classes (1.3b) reuse it for key tuples |

---

## 19. Phase 2, in outline (after review)

Tests first, each set committed failing before the change that makes it pass: grammar, printer
round-trip, decimal, units, purity, evaluation, slice lineage, Excel, migration. Then SPEC.md
(new section for the dialect with ABNF in Appendix A, 4.2/4.4 range objects, 7 `extent`, 7.1, 8.2,
8.4, 10.1 steps 3, 7.5, 7.6, 10.2 new codes, 11 new kinds, the Excel table, section 13 rows, section
14 entry), `units.md` additions, schemas (receipt `inputs` items, slice, manifest, vector kinds),
`tools/formula.py`, `canon.py` changes, generators, vectors, cross-check generators, README.
