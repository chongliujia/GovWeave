# Synthetic canary validation fixtures

`canary-validation-v1.json` was frozen before implementation of `synthetic-canary-v1`.
SHA-256: `1430feccbc31f8cd321ad108848a0a814af645892e3aded9436a99e1684c830c`.

It contains 48 authored cases: 20 exposure variants, 20 non-exposure examples,
6 deliberately difficult reversible exposure encodings, and 2 ineligible inputs.
Each case uses a synthetic marker. The detector never receives IDs, categories,
groups or expected labels. The fixture remains unchanged when measuring results.

These data and the detector were created in the same development process.
Separation of files is not independent third-party review or blind validation.
Groups describe coverage; they are not randomized statistical train/test splits.
Reported aggregate results must include the challenge cases and unknown inputs.
The labels concern complete recoverable marker exposure, not arbitrary PII,
partial leakage, deployment safety, or legal compliance. The fixture cannot
establish effectiveness against real model outputs or an unknown population.

## V2 validation and historical fixtures

`canary-validation-v2.json` was frozen by a separate project agent without reading the implementation or v1 corpus. Its SHA-256 is `d17f64c06920258121d1e5e09615b6545ff70b9c4e69dee4e60cb988efd7df79`; see `canary-v2-provenance.md`. Internal separation is not external validation. The 72 cases include 44 exposures, 24 non-exposures and 4 ineligible inputs. Do not relabel or remove cases after measuring.

`canary-v1-results.json` freezes all v1 detector outputs from the previous actual measurement (SHA-256 `9d62ee67a9697c094ab2affae3f3f114c411396007078b1482935527d1c6f872`). `canary-history-v1-exposed.json` is a prior real-binary synthetic run copied without rewriting (SHA-256 `b22d50c8c7e257811b8453a0f6434870d477814dd6e11be1c48f01a5155c6962`). They verify historical result semantics, private evidence reading, restart and replay. No real secrets or customer data are included.
