# Observed-fact records

Anything learned by inspecting a vendor ROM, firmware package, or binary lives
here as a **fact record**, not as code. Examples: an operator UA string, a
feature tag spelling, an APN shape, a carrier timer value.

Rules:

1. **Never** copy code, decompiled expressions, private symbols, or opaque
   constants into the implementation from a vendor artifact.
2. Every record names its provenance: package/partition/file, how it was read,
   date, exact observed value, and confidence.
3. A fact may become a *configuration default* only if a public 3GPP/GSMA/IETF
   source or the operator's own published settings corroborate it.
4. Facts are not test oracles for protocol behaviour. Protocol tests must cite
   a public normative clause (see `docs/specs.md`).
5. If a fact is uncertain, mark it uncertain and do not ship it as a default.

Use [`example-record.md`](example-record.md) as the template. Delete the example
content when creating a real record.
