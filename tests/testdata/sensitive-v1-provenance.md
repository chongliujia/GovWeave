# Sensitive-text validation v1 provenance

- Frozen at: 2026-10-28T15:09:14.106476+00:00.
- Corpus SHA-256: f1f5cdd4cb2dcc782cb9b1479b2884ed4f5c55728f98a100eedf972c95963b71.
- Cases: 80 (16 credential, 16 email, 16 phone, 24 benign, 4 mixed, 2 valid limits, 2 invalid oversized inputs).
- Authoring: a separate development agent authored the examples from the category contract before reading or executing the new detector implementation. No external annotator or independent human review was involved.
- No user-provided API key, customer text, or real record was copied. Token values and contact examples were invented. Example email domains are reserved example domains; phone-like digits are synthetic illustrations, not verified subscribers.
- Labels mean intended credential/email/mobile candidate presence in these authored scenarios. They do not imply validity of credentials, personal-data legal status, consent, or a legal compliance decision.
- Unsupported positives intentionally include arbitrary secrets, split/encoded values, internationalized email forms, non-China phone forms and obfuscation. Keep misses visible rather than relabeling them as negatives.
- The two invalid oversized inputs must yield unknown; exclude them from valid-case category quality denominators. The valid 40-email case is not invalid input: a finding-budget unknown must count against coverage and as a false negative for its positive category.
- This corpus is frozen before the first measurement. Do not change its labels or bytes to improve reported numbers. Subsequent fixes should use new regression cases and report this same baseline separately.
- Timing is a local detector-call measurement only, excluding HTTP, provider/model calls, audit synchronization, policy persistence and application processing.

## First measurement identity

- Detector source SHA-256 (recorded immediately before execution): internal/sensitive/detector.go = 67533b31af969288af055e6aa7b46057e88f2d1e51ef688d6b01e4a36ca3134f.
- Detector version: sensitive-text-v1.
- Command: go run ./cmd/sensitive-eval (100 timing repetitions, 2 warmups, seed 20261028, one worker).
- First local report: dist/sensitive-validation/eval-4220675485/report.json. It is a private generated artifact, not checked-in source data.
- Category recall: credential 15/19, email 14/20, phone 13/19. There were zero false positives in this authored corpus; this does not estimate production precision.
- All category decisions share one valid-input abstention (the finding-limit example), giving 77/78 decision coverage. Both oversized inputs yielded unknown and are excluded from quality denominators.
- Source and corpus bytes were not tuned after these results.
