# Sensitive-text v2 normalization validation provenance

- Client date: 2026-10-29 (Asia/Shanghai). Precise UTC freeze timestamps and hashes are in [corpus freeze](sensitive-v2-freeze.json) and [source freeze](sensitive-v2-source-freeze.json).
- New corpus: [sensitive-validation-v2.json](sensitive-validation-v2.json), 64 authored synthetic cases; SHA-256 `a81027500c2793291288b514a7f0357fc4ebcd17a070f34b451c55c4003c3a48`.
- Order: inspect v1 misses; author and freeze the new cases; implement v2 and test generic boundaries; freeze detector source; measure both generations against both corpora. The same developer authored the new set and implementation. This is not a blind holdout or independent external validation. No labels or detector source were changed after first measurement.
- Twelve credential, twelve email, twelve phone, twenty benign, four mixed and four boundary cases. One boundary input exceeds 8192 bytes and is excluded from quality denominators. The 40-obfuscated-email case is valid input; unknown from the finding cap counts as a miss for email.
- All strings are synthetic. No provided API key, customer record or live model response was used. Labels mean category presence in the authored scenario, not credential validity, personal ownership or a legal classification.
- The original v1 detector and 80-case corpus remain byte-for-byte unchanged. V2 is an explicit policy choice, not an automatic upgrade.

## First comparison

The command `make validate-sensitive` ran 100 timing repetitions and two warmups per case, one worker. Quality counts each case only once. Reports contain category metadata and sample IDs, not source text.

| Corpus | Detector | Credential TP / FP / FN | Email TP / FP / FN | Phone TP / FP / FN | Decision coverage |
| --- | --- | --- | --- | --- | --- |
| Original 80 | v1 | 15 / 0 / 4 | 14 / 0 / 6 | 13 / 0 / 6 | 77/78 |
| Original 80 | v2 | 16 / 0 / 3 | 16 / 0 / 4 | 15 / 0 / 4 | 77/78 |
| New 64 | v1 | 4 / 0 / 11 | 3 / 0 / 13 | 3 / 0 / 12 | 63/63 |
| New 64 | v2 | 13 / 0 / 2 | 13 / 0 / 3 | 13 / 0 / 2 | 62/63 |

On the original set, recall moves from 78.95% / 70.00% / 68.42% to 84.21% / 80.00% / 78.95%. New-set v2 recall is 86.67% / 81.25% / 86.67%. Neither set observed a false positive; these small, deliberately structured sets cannot estimate production precision. Unsupported arbitrary secrets, encoded/split values, international phone formats and non-ASCII email syntax still contribute misses. The new-set coverage drop reflects v2 finding more than 32 obfuscated emails and returning unknown; v1 misses them all while returning not_observed. Neither outcome is a successful detection for quality scoring.

| Corpus / detector | Local P50 µs | P95 µs | P99 µs | Generated private report |
| --- | ---: | ---: | ---: | --- |
| Original / v1 | 2.667 | 6.750 | 396.625 | `dist/sensitive-validation/eval-209421815/report.json` |
| Original / v2 | 2.834 | 9.375 | 371.125 | `dist/sensitive-validation/eval-3751461715/report.json` |
| New / v1 | 1.875 | 5.958 | 338.334 | `dist/sensitive-validation/eval-876291411/report.json` |
| New / v2 | 3.750 | 17.333 | 376.042 | `dist/sensitive-validation/eval-942924317/report.json` |

These sequential single-machine detector measurements include corpus boundary cases but exclude HTTP, queues, provider inference, policy evaluation and audit writes. Timing order and machine noise can change tail comparisons; no service latency or throughput guarantee follows. Byte-span correctness is checked separately in unit and fuzz tests; corpus quality remains category-presence scoring.
