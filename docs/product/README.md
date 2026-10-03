# Deceipt Product Expansion — Planning Index

**Status:** PLANNED · **Date:** 2026-10-03

This directory extends the current BLE-first PoC with receipt capture and user-facing organization features without weakening the existing receipt trust model.

## Planned capabilities

| Capability | Document | Core rule |
|---|---|---|
| Email receipt ingestion | [email-receipt-ingestion-v1.md](./email-receipt-ingestion-v1.md) | Email is an ingestion source, not cryptographic merchant trust. |
| Laya / System-One classification | [system-one-classification-v1.md](./system-one-classification-v1.md) | ML enriches receipts; it never invents or authoritatively changes monetary facts. |
| Spending insights | [insights-v1.md](./insights-v1.md) | Insights are computed from stored normalized receipt data and explicit enrichment, not generated ad hoc by a model. |

## Shared product model

Deceipt should support multiple ways for a receipt to enter the app:

1. **Native Deceipt receipt** — received through a Deceipt transport such as BLE and independently verified using the existing merchant-signature/trust contract.
2. **Email-imported receipt** — forwarded/delivered to a Deceipt-managed address and parsed by the backend.
3. **Future import sources** — file share, photo/OCR, retailer APIs, bank/card matching, etc.

These sources should converge on a common application-level receipt record while preserving source-specific evidence and trust.

A source label must never be collapsed into a trust label. In particular:

- `source=deceipt_transport` does not itself mean trusted; the existing signature verification outcome remains authoritative.
- `source=email` is **not merchant-verified**, even when SPF/DKIM/DMARC pass.
- Laya/System-One output is **enrichment metadata**, never verification evidence.

## Application-level receipt layers

The product should conceptually keep four layers distinct:

```text
Raw evidence
    ↓
Normalized receipt facts
    ↓
Enrichment / organization
    ↓
Insights projections
```

### 1. Raw evidence
What Deceipt actually received: signed receipt bytes, email MIME message, attachment bytes, or another future source artifact.

### 2. Normalized receipt facts
Merchant display name, date, currency, totals, line items, taxes, tips, discounts, payment summary, and identifiers, each with provenance.

### 3. Enrichment
Categories, canonical merchant grouping, tags, personal/business label, recurring-purchase candidates, and other System-One outputs.

### 4. Insights
Deterministic aggregates derived from normalized facts plus accepted enrichment.

This separation is intentional. A classifier failure must not lose a receipt, and changing a category must not modify the underlying receipt evidence.

## Cross-feature invariants

1. Never label an email-imported receipt as cryptographically verified merely because its email authentication passed.
2. Never let an ML model silently alter a receipt total, tax, tip, currency, timestamp, or merchant signature status.
3. Preserve raw source evidence long enough to re-run parsers and investigate extraction errors according to the eventual retention policy.
4. Make receipt import idempotent.
5. User edits override model enrichment until the user explicitly clears the override.
6. Insights use deterministic arithmetic over stored values.
7. Refunds and voids follow receipt semantics rather than being treated as ordinary positive spend.
8. Mixed currencies are not silently summed without an explicit FX policy and rate provenance.
9. Every parser/model output is versioned so old imports can be reprocessed safely.
10. Failure of email parsing, Laya inference, or insight projection must fail locally rather than corrupting the canonical receipt.

## Suggested implementation order

1. Define the application-level imported-receipt/provenance model.
2. Build inbound email aliasing + raw-message capture.
3. Add staged parsing and a review path for ambiguous imports.
4. Add the `SystemOneClassifier` contract and Laya adapter.
5. Persist categories/tags and user overrides.
6. Add deterministic insight projections.
7. Build the Insights UI.
8. Add reprocessing, correction feedback, and parser/model quality metrics.

No application code is changed by these planning documents.
