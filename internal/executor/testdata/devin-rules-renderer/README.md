# Pinned Devin rules renderer receipts

Fixture documentation for contributors, consumed by
`TestPinnedRendererCorpusReceipts` in `internal/executor/devin_rules_test.go`.
For user-facing instruction selection, see [instruction bundles](../../../../docs/reference/common-profile-format.md#instruction-bundles).

These included `.body` and `.stdout` fixture pairs were captured from Devin
CLI 3000.10.21 (`611c1cba`) on Linux x86_64. The measured source corpus had
SHA-256 `d1dc25a71e84fffdd18ee4480bfd303ae8cab96426ed0981590cfcbbaaa01126`.
The fixture pairs in this directory are the self-contained test inputs; no
external corpus file is needed.

The target frames `rules show` content between two separator lines, each
containing 60 U+2500 characters, and prints the absolute path as a quoted value. Across these 16 receipts, rendered
content equals `strings.TrimSpace(body) + "\n"`; interior CRLF and embedded
separator lines remain intact. Tests independently compare the projected file
bytes before using this lossy display transformation. These are Linux parser
observations; they are not Linux runtime support evidence. The separate
`TestNativeProductionInstructionRulesReceipts` test performs native macOS
confirmation in the candidate CI gate. Do not replace captured output with
handwritten expected text and describe it as a target observation.
