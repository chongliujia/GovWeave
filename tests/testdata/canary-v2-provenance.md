# Canary validation v2 provenance

This corpus is a frozen, authored synthetic validation artifact for the GovWeave canary detector. It is not evidence of real model behavior, production recall, resistance to adaptive attacks, or broad data-loss prevention coverage.

## Authorship and separation

On 2026-10-28, another agent within the same GovWeave project generated fresh synthetic markers and assigned all labels before detector evaluation. This agent was separate from the agent implementing and evaluating the detector. This is internal separation of duties, not external third-party validation. No external model, real model response, service, or human labeling panel was used.

The corpus author read the repository's `agent.md` contributor guide. The author did not read `internal/leakage`, `internal/leakageeval`, any prior canary corpus, or detector results. Case selection and labels follow the supplied data contract and explicit reversible constructions. No detector result was used to add, remove, relabel, or adjust a case. The fixture was frozen after its construction and independent inverse-transform checks; subsequent implementation evaluation must use these exact bytes. A changed corpus requires a new version and a new provenance record.

## Labeling policy

`exposed` means the response contains a complete known synthetic marker or contains all information needed to recover it with conventional or explicitly stated reversible transformations. Multi-layer encodings and more difficult reversible forms remain exposed even if a detector cannot recognize them. Every exposed construction was checked by applying its inverse to the emitted payload and comparing the result with the complete source marker. Inverse checks used standard-library decoders, JSON parsing, Unicode normalization, or explicit reverse arithmetic; they did not call project detection code. Independently padded Base64 blocks were decoded separately and joined in emitted order.

`not_exposed` covers refusals, unrelated values, one-character mutations, truncation, masking, and partial representations. A partial value omits at least one marker character without supplying a reversible representation of that character elsewhere in the same response. Guessing missing characters, consulting the expected marker, and joining information from different cases are excluded. The nonadjacent-fragment case supplies a prefix and suffix while omitting the middle half; joining its visible fragments cannot produce the full marker. Long public encoding cases encode only generated public sample text. Wrong-value encoded cases were decoded to check that they remain distinct from the target.

`unevaluable` covers three deliberately invalid markers (empty, whitespace-only, and forbidden punctuation) plus one response of exactly 8193 UTF-8 bytes. These intentionally invalid markers are exceptions to the valid-marker generation profile. A not-exposed boundary case has exactly 8192 UTF-8 bytes. File-format string limits still hold for every case.

## Coverage and bounds

- Cases: 72; labels: 44 exposed, 24 not exposed, 4 unevaluable.
- Groups: boundary=13, challenge=22, validation=37.
- Valid marker count: 69; distinct valid marker lengths in bytes: 24, 25, 26, 31, 32, 42, 43, 48, 57, 64, 75, 80, 96, 101, 112, 127, 128.
- Exactly 14 valid markers have the 42-byte `GW-CANARY-` plus 32 lowercase hexadecimal-character form.
- Other valid markers use fresh operating-system randomness, start with an ASCII letter, contain only ASCII letters, digits, underscores, and hyphens, measure 24–128 bytes, and retain at least 20 alphanumeric characters after separators are removed. All 72 stored marker strings are distinct.
- Exposed forms include literal text, whitespace and fullwidth variants, common single encodings, reversal, ROT13, decimal ASCII, two-layer compositions, continuously emitted independently padded Base64 blocks, three-layer compositions, Base32, binary ASCII, an explicitly stated numeric shift, Atbash, and Base85.
- The corpus has a finite authored challenge set. It does not enumerate all transformations or make claims about detection rates. All cases, including difficult exposed forms, belong in overall accounting; any slice reporting must identify its denominator.
- Storage contract checks passed: schema version 1, required keys only, permitted enum values, unique case IDs, field lengths, at most 256 cases, at most 1 MiB, and all responses at most 32768 UTF-8 bytes. File size is 57402 bytes.

## Frozen identity

- File: `canary-validation-v2.json`
- Corpus ID: `govweave-canary-validation-v2`
- Version: `2.0.0-frozen-2026-10-28`
- SHA-256: `d17f64c06920258121d1e5e09615b6545ff70b9c4e69dee4e60cb988efd7df79`

The JSON fixture is the canonical frozen input. Its exact marker and response bytes are retained in that file. Synthetic label construction and inverse-transform checks establish authored ground truth only; they are not external or real-model validation.
