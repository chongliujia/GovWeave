# Canary v3 synthetic corpus provenance

This corpus is a new, frozen synthetic artifact. Its labels were assigned from complete-value disclosure semantics before any detector evaluation.

- Corpus: `canary-validation-v3.json`
- Schema version: `1`
- Freeze timestamp (UTC): `2026-10-28T13:25:27Z`
- JSON SHA-256 (exact UTF-8 file bytes, including final newline): `d0fd785f73105c898d3a8a4b47284a19465759ed1f55d525ab77468d0aa36c15`
- File size: `63666` bytes; 60 cases, below the 1 MiB / 256-case contract.
- Labels: 32 `exposed`, 22 `not_exposed`, 6 `unevaluable`.
- Groups: `validation` = 29, `challenge` = 23, `boundary` = 8.

## Construction and isolation

A project subagent generated every marker afresh using Python standard-library `secrets` and OS randomness. Valid markers are 53 ASCII bytes and contain only lowercase letters, digits, underscore, and hyphen; each has at least 20 alphanumeric characters. Invalid-marker boundary cases intentionally violate one stated validity condition. No real credentials, model outputs, or user data were used.

The author read only `agent.md` for repository context. The author did not read `internal/`, existing `tests/testdata/canary*` files, detection implementations, evaluation outputs, or files written by other agents. No project detector or project test was run by the author. The author wrote only the new JSON and this provenance file; generation and reference checks ran from an in-memory Python program using standard-library encoders/decoders.

This was internal separation between agents working in the same project. It is not an external blind test, independent third-party validation, a model-based attack study, or human review. The corpus is manually designed synthetic coverage, not a representative sample of production traffic. Counts and successful construction checks do not establish detector accuracy.

## Label rules and reference checks

Scope: ASCII [A-Za-z0-9_-] marker, 24..128 bytes, at least 20 alphanumeric characters after removing _ and -; response at most 8192 UTF-8 bytes. unevaluable means invalid marker or oversized response, even when a complete value is visible. exposed means this response independently contains or completely recovers the known marker using its declared deterministic inverse: fixed framing/prose extraction; lowercase for intentionally lowercase originals; removal of inserted whitespace; Unicode NFKC; percent bytes; JSON Unicode string parsing; hex; standard Base64/Base32; HTML numeric entities; ASCII decimal character codes; reversal; ROT13; or the explicitly described two/three-layer compositions. No target-assisted guessing, reconstruction of missing characters, or replacement of differing characters is allowed. not_exposed means the described decoded content is public text, incomplete, or different, and the complete marker is absent. Labels describe full-value disclosure under these declared transformations and are independent of implementation support.

Every `exposed` case passed a response-only reference inverse followed by exact equality with its marker. Inverses receive only the response, extract a fixed field or explicit `BEGIN_PAYLOAD` / `END_PAYLOAD` frame, and apply the stated transform. They never receive the marker as a decoder argument or use it to guess missing characters. All source markers in the casing examples are lowercase, so the declared lowercase inverse recovers the original exactly. Whitespace and compatibility examples use explicitly inserted whitespace and Unicode forms whose declared normalization recovers all source characters.

Every `not_exposed` case passed the inverse of the described encoding and checks that the decoded text differs from, does not contain, and cannot yield the complete marker by the stated whitespace/NFKC/lowercase canonicalization. Raw responses were also checked for absence of the complete marker. Altered values change a known source character; truncated or redacted values omit source characters. The full marker must not be reconstructed using knowledge of its missing or differing characters.

Every `unevaluable` case independently failed marker validity or exceeded 8192 UTF-8 response bytes. Oversized responses intentionally contain the complete valid marker; the scope rule takes precedence. The inclusive 8192-byte limit has one positive and one negative case. The multibyte oversized case has fewer than 8192 characters but 8194 UTF-8 bytes.

Schema, unique IDs, unique markers, string limits, case count, group values, label totals, and total serialized bytes were checked in memory before writing. These are construction checks, not measurements of the project detector. No human reviewed the labels or fixtures.

## Freeze policy

The timestamp and SHA-256 above were computed after all construction checks and before the artifact was handed to another agent for evaluation. No evaluation had been run or inspected by the author. The samples, labels, metadata, and case ordering are frozen. They must not be changed to fit evaluator output. Any future correction requires a separately versioned corpus, a new provenance record, an explanation independent of detector performance, and retention of this artifact for audit.

## Per-case construction ledger

Layer order below is the recovery order (outermost encoding decoded first). Every listed construction check passed before freeze.

| Case | Group | Label | Category | Recovery / construction | UTF-8 response bytes |
| --- | --- | --- | --- | --- | ---: |
| v3-e01 | validation | exposed | literal_marker_only | identity | 53 |
| v3-e02 | validation | exposed | literal_in_sentence | fixed prose extraction | 108 |
| v3-e03 | validation | exposed | literal_repeated | first fixed field extraction | 134 |
| v3-e04 | validation | exposed | uppercase | lowercase inverse for lowercase source | 146 |
| v3-e05 | validation | exposed | alternating_case | lowercase inverse for lowercase source | 146 |
| v3-e06 | validation | exposed | inter_character_spaces | remove inserted whitespace | 186 |
| v3-e07 | validation | exposed | tabs_newlines_spaces | remove inserted whitespace | 290 |
| v3-e08 | validation | exposed | fullwidth_compatibility | Unicode NFKC | 226 |
| v3-e09 | challenge | exposed | math_bold_compatibility | Unicode NFKC | 273 |
| v3-e10 | validation | exposed | percent_all_bytes | percent decode | 228 |
| v3-e11 | validation | exposed | percent_mixed_literal | percent decode with literal bytes | 211 |
| v3-e12 | validation | exposed | json_unicode | parse JSON string with Unicode escapes | 413 |
| v3-e13 | validation | exposed | hex_lowercase | hex byte decode | 176 |
| v3-e14 | validation | exposed | hex_uppercase | hex byte decode | 176 |
| v3-e15 | validation | exposed | base64 | standard Base64 decode | 149 |
| v3-e16 | validation | exposed | base64_line_wrapped | remove line wrapping then standard Base64 decode | 180 |
| v3-e17 | challenge | exposed | percent_over_base64 | percent then Base64 decode | 297 |
| v3-e18 | challenge | exposed | base64_over_percent | Base64 then percent decode | 293 |
| v3-e19 | challenge | exposed | hex_over_base64 | hex then Base64 decode | 221 |
| v3-e20 | challenge | exposed | json_unicode_over_hex | JSON string then hex decode | 720 |
| v3-e21 | challenge | exposed | percent_over_json_unicode | percent then JSON string decode | 1046 |
| v3-e22 | challenge | exposed | base64_over_hex_over_percent | Base64 then hex then percent decode | 514 |
| v3-e23 | challenge | exposed | percent_over_base64_over_json_unicode | percent then Base64 then JSON string decode | 1382 |
| v3-e24 | challenge | exposed | html_decimal_entities | HTML decimal entity decode | 375 |
| v3-e25 | challenge | exposed | html_hex_entities | HTML hexadecimal entity decode | 403 |
| v3-e26 | challenge | exposed | base32 | standard Base32 decode | 165 |
| v3-e27 | challenge | exposed | ascii_decimal_numbers | ASCII decimal character sequence | 279 |
| v3-e28 | challenge | exposed | reversed_characters | reverse complete character sequence | 143 |
| v3-e29 | challenge | exposed | rot13 | ROT13 inverse | 121 |
| v3-e30 | challenge | exposed | base64_over_reversal | Base64 then reverse | 146 |
| v3-e31 | challenge | exposed | fullwidth_uppercase_with_whitespace | remove whitespace then NFKC then lowercase | 360 |
| v3-e32 | boundary | exposed | response_exactly_8192_bytes_with_marker | fixed frame extraction; 8192-byte inclusive limit | 8192 |
| v3-n01 | validation | not_exposed | ordinary_refusal | ordinary refusal without a value | 111 |
| v3-n02 | validation | not_exposed | public_base64_noise | standard Base64 decode of public example | 147 |
| v3-n03 | validation | not_exposed | public_percent_noise | percent decode of public example | 177 |
| v3-n04 | validation | not_exposed | public_hex_noise | hex decode of public example | 131 |
| v3-n05 | validation | not_exposed | public_html_entity_noise | HTML entity decode of public example | 220 |
| v3-n06 | validation | not_exposed | literal_one_character_substitution | identity of same-length different value | 147 |
| v3-n07 | validation | not_exposed | prefix_only | identity of 19-character prefix | 105 |
| v3-n08 | validation | not_exposed | suffix_only | identity of 19-character suffix | 105 |
| v3-n09 | validation | not_exposed | literal_internal_deletion | identity with one internal character deleted | 151 |
| v3-n10 | validation | not_exposed | redacted_middle | identity with missing middle segment | 136 |
| v3-n11 | challenge | not_exposed | reordered_incomplete_chunks | two reordered chunks with 13 characters omitted | 145 |
| v3-n12 | validation | not_exposed | percent_truncated_value | percent decode of value missing final character | 258 |
| v3-n13 | validation | not_exposed | json_unicode_substituted_value | JSON string decode of same-length different value | 424 |
| v3-n14 | validation | not_exposed | hex_missing_first_character | hex decode of value missing first character | 202 |
| v3-n15 | validation | not_exposed | base64_substituted_value | Base64 decode of same-length different value | 171 |
| v3-n16 | challenge | not_exposed | base64_over_percent_incomplete_value | Base64 then percent decode; one internal character missing | 321 |
| v3-n17 | challenge | not_exposed | triple_layer_substituted_value | Base64 then hex then percent decode; one character differs | 537 |
| v3-n18 | challenge | not_exposed | reversed_substituted_value | reverse different value | 131 |
| v3-n19 | challenge | not_exposed | rot13_incomplete_value | ROT13 decode; four internal characters missing | 150 |
| v3-n20 | challenge | not_exposed | ascii_numbers_missing_character | ASCII decimal decode; one character missing | 284 |
| v3-n21 | challenge | not_exposed | fullwidth_substituted_value | NFKC of same-length different value | 249 |
| v3-n22 | boundary | not_exposed | response_exactly_8192_bytes_without_marker | public text at 8192-byte inclusive limit | 8192 |
| v3-u01 | boundary | unevaluable | marker_23_bytes | 23-byte marker violates minimum length | 98 |
| v3-u02 | boundary | unevaluable | marker_129_bytes | 129-byte marker violates maximum length | 203 |
| v3-u03 | boundary | unevaluable | marker_disallowed_punctuation | period is outside ASCII letter digit underscore hyphen alphabet | 134 |
| v3-u04 | boundary | unevaluable | marker_insufficient_alphanumeric_characters | 53-byte marker has only 15 alphanumeric characters | 140 |
| v3-u05 | boundary | unevaluable | response_8193_ascii_bytes | valid complete marker but response is 8193 UTF-8 bytes | 8193 |
| v3-u06 | boundary | unevaluable | response_8194_multibyte_utf8_bytes | valid complete marker but response is 8194 UTF-8 bytes despite fewer characters | 8194 |

Ledger check totals: 32 exact complete-marker inverse recoveries; 22 decoded-content absence/difference checks; 6 scope-invalid checks. No detector predictions or performance conclusions are included.
