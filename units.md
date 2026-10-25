# Datumesh units

Status: part of `spec-0.4.1` (unchanged since `spec-0.4.0`), normative. SPEC.md section 7.1 says where units appear; this document says which units exist.

A function declares the unit of every number it takes or returns. The unit lives in the function's signature, so the function hash commits to it and every receipt inherits it through `cell.fn_hash`. A receipt never carries a unit itself.

Three rules hold throughout:

- **The list is closed.** A unit is valid only if this document lists it. Anything else fails with `E_CANON_UNIT`. The list is extended only by revisions of the specification, never by publishers.
- **Units are compared byte for byte, never parsed.** `degC` and `°C` are different strings, and only `degC` is on the list. `kWh` is one unit, not `k` × `W` × `h`. No verifier converts between units or checks dimensions.
- **There is no unit grammar** beyond the two fixed patterns in sections 2.4 (indices) and 1 (rates).

The fenced blocks tagged `units-…` below are the machine-readable list. `tools/canon.py` reads them, and the verifier libraries embed copies of them.

## 1. Forms in a signature

A unit in a signature is one of three JSON forms:

| Form | Example | Meaning |
|---|---|---|
| Literal | `"degC"` | A unit from section 2. |
| Argument reference | `{"arg": "currency"}` | The unit is the value of the named argument. |
| Rate | `{"of": "USD", "per": {"arg": "base"}}` | Units of `of` per one unit of `per`. |

- An **argument reference** names an argument of the same signature whose type is `string`. The descriptor check is only that: the argument exists and is a string (`E_CANON_UNIT` otherwise). A name that is not an argument of the signature, whether or not it is a well-formed name (`{"arg": "Bad"}`), is `E_CANON_UNIT`. By convention such an argument holds a currency or unit code, and the publisher documents it as one.
- A **rate** has exactly the members `of` and `per`. Each is a currency code from section 2.1 or an argument reference. Rates of other units, and rates of rates, cannot be written. Because rates have this one form, the string `"USD/EUR"` is not a unit.
- A literal is a JSON string, a reference is an object with exactly the member `arg` whose value is a string, and a rate is an object with exactly `of` and `per`, each a string or a reference. Any other JSON shape is `E_SCHEMA`, and is found while checking the descriptor's structure, before any canonical-form check (SPEC.md 7).

Examples:

```json
{"type": "number", "unit": {"of": {"arg": "quote"}, "per": {"arg": "base"}}}
{"type": "number", "unit": {"of": {"arg": "quote"}, "per": "EUR"}}
{"type": "number", "unit": {"arg": "base"}, "valid": false}
{"type": "number", "unit": "index:2015=100"}
```

## 2. Literal units

### 2.1 Currencies

A currency code denotes an amount of money in that currency. The list contains ISO 4217 List One, as published on 2026-09-17, without `XXX` ("no currency"):

```units-currency
AED AFN ALL AMD AOA ARS AUD AWG AZN BAM BBD BDT BHD BIF BMD BND BOB BOV BRL BSD
BTN BWP BYN BZD CAD CDF CHE CHF CHW CLF CLP CNY COP COU CRC CUP CVE CZK DJF DKK
DOP DZD EGP ERN ETB EUR FJD FKP GBP GEL GHS GIP GMD GNF GTQ GYD HKD HNL HTG HUF
IDR ILS INR IQD IRR ISK JMD JOD JPY KES KGS KHR KMF KPW KRW KWD KYD KZT LAK LBP
LKR LRD LSL LYD MAD MDL MGA MKD MMK MNT MOP MRU MUR MVR MWK MXN MXV MYR MZN NAD
NGN NIO NOK NPR NZD OMR PAB PEN PGK PHP PKR PLN PYG QAR RON RSD RUB RWF SAR SBD
SCR SDG SEK SGD SHP SLE SOS SRD SSP STN SVC SYP SZL THB TJS TMT TND TOP TRY TTD
TWD TZS UAH UGX USD USN UYI UYU UYW UZS VED VES VND VUV WST XAD XAF XAG XAU XBA
XBB XBC XBD XCD XCG XDR XOF XPD XPF XPT XSU XTS XUA YER ZAR ZMW ZWG
```

It also contains these withdrawn codes, because historical European Central Bank reference rates use them:

```units-currency
BGN CYP EEK GRD HRK LTL LVL MTL ROL SIT SKK TRL
```

A code that leaves List One stays on this list, because receipts that use it remain valid forever.

### 2.2 Physical units

The seven SI base units, plus the other units listed here, written with their standard symbols in ASCII:

```units-physical
m kg s A K mol cd
degC m/s W kWh
mm cm km/h hPa W/m2
min h d km deg
```

| Unit | Quantity |
|---|---|
| `m` | metre |
| `kg` | kilogram |
| `s` | second |
| `A` | ampere |
| `K` | kelvin |
| `mol` | mole |
| `cd` | candela |
| `degC` | degree Celsius (a temperature, not a temperature difference) |
| `m/s` | metre per second, as one fixed symbol |
| `W` | watt |
| `kWh` | kilowatt-hour |
| `mm` | millimetre |
| `cm` | centimetre |
| `km/h` | kilometre per hour, as one fixed symbol |
| `hPa` | hectopascal |
| `W/m2` | watt per square metre, as one fixed symbol (ASCII `2`, not `²`) |
| `min` | minute (60 s) |
| `h` | hour (3600 s) |
| `d` | day (86400 s); also the unit of a difference between two dates |
| `km` | kilometre |
| `deg` | degree of angle, π/180 radians; radians are dimensionless (`1`) |

`min`, `h`, `d`, `km` and `deg` were added in `spec-0.4.0` for the formula dialect (SPEC.md 15):
durations for instant arithmetic and lookup bounds, distances, and angles for the trigonometric
functions and `haversine`. A day is
86400 seconds: instants have no leap seconds (SPEC.md 3.3).

`mm` and `m` are different units, not two spellings of one: a value in `mm` is written in millimetres. Choose the unit the source publishes in.

### 2.3 Ratios and counts

```units-ratio
percent permille bp 1 count
```

| Unit | Meaning |
|---|---|
| `percent` | Parts per hundred: `2.5` means 2.5 %. |
| `permille` | Parts per thousand: `25` means 2.5 %. |
| `bp` | Basis points, parts per ten thousand: `25` means 0.25 %. |
| `1` | A dimensionless quantity that is none of the others, such as a ratio of like quantities or a coefficient. |
| `count` | A number of things. |

### 2.4 Indices

An index is written `index:<period>=<value>`: the index equals `<value>` in `<period>`.

```
index-unit   = "index:" index-period "=" index-value     ; at most 64 characters
index-period = year [ "-" month [ "-" day ] ]           ; YYYY, YYYY-MM or YYYY-MM-DD
index-value  = number, greater than 0                   ; SPEC.md 3.1
```

The period is a real calendar year, month or day, in the forms of SPEC.md 3.2: years `0001` to `9999`, so `index:0000=100` is not a unit. The value is a canonical number greater than zero. An index unit is a literal: it can be written wherever a literal can, but not as a side of a rate. A string that starts `index:` and breaks any of these rules, or is longer than 64 characters, is `E_CANON_UNIT`. Examples: `index:2015=100` (UK CPI), `index:1984-01-03=1000` (an equity index based on one day).

## 3. Resolving a unit

The unit of one cell's value is found from the descriptor and the cell's arguments. A receipt carries both, the descriptor through `cell.fn_hash`.

Resolution is a client convenience. Verification (SPEC.md 10.1) never resolves units, and a receipt whose unit cannot be resolved verifies like any other.

`resolve(descriptor, cell)` checks, in this order, and reports the first failure:

1. the cell: structure, then canonical form (SPEC.md 4.4);
2. that the descriptor hashes to `cell.fn_hash` (`E_FN_HASH_MISMATCH`);
3. the descriptor: structure, then canonical form (SPEC.md 7), as in verification step 7.1;
4. substitution into the return unit, as below. For a rate, `of` is resolved before `per`.

Only the arguments the return unit refers to are examined. A referenced argument the cell does not bind is `E_ARG_MISSING`, and one bound with a type other than `string` is `E_ARG_TYPE`. Other arguments are not checked against the signature; verification step 7.2 does that.

- A literal resolves to itself.
- An argument reference resolves to that argument's value in the cell. The value must itself be a literal unit from section 2, otherwise `E_CANON_UNIT`.
- A rate resolves to `<of>/<per>`, each side resolved as above. Each side must resolve to a currency code, otherwise `E_CANON_UNIT`. `{"of": "USD", "per": "EUR"}` resolves to `USD/EUR`, meaning US dollars per euro.
- A referenced argument that is a slice marker cannot be resolved (`E_SLICE`).
- A function whose return type is not `number` has no unit; the result is null.

The resolved string is for display and comparison. It is not hashed, and it is not a unit that may be written in a signature.

## 4. Seed sources

The seed sources' quantities and their units:

| Source | Quantity | Unit |
|---|---|---|
| European Central Bank | reference rate | `{"of": {"arg": "quote"}, "per": "EUR"}`, withdrawn currencies included |
| ONS | CPI, CPIH | `index:2015=100` |
| ONS | inflation rate | `percent` |
| ONS | CPI item weights | `permille` |
| Open-Meteo | temperature | `degC` |
| Open-Meteo | precipitation, snowfall | `mm`, `cm` |
| Open-Meteo | wind speed | `km/h` or `m/s` |
| Open-Meteo | surface pressure | `hPa` |
| Open-Meteo | shortwave radiation | `W/m2` |
| Companies House | counts | `count` |
| Companies House | share capital | a currency code, or `{"arg": …}` |

Dates, such as incorporation dates, are values of type `date` and have no unit.

## 5. Changes

- `spec-0.4.0`: `min`, `h`, `d`, `km` and `deg` added. No other change; no hash changes, since a unit is
  part of a hash only in a descriptor that uses it.
- `spec-0.2.0`: first version, including `mm`, `cm`, `km/h`, `hPa`, `W/m2` and `permille` for the seed sources.
