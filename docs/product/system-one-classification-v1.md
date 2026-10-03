# Laya / System-One Receipt Classification v1

**Status:** PLANNED · **Date:** 2026-10-03  
**Goal:** Add a fast System-One model layer, initially Laya-compatible, for organizing receipts without making ML authoritative over receipt evidence or money.

## 1. Role of System-One

System-One should answer cheap, narrow questions quickly.

Good initial tasks:

- receipt category;
- line-item category;
- canonical merchant grouping suggestion;
- tags;
- personal vs. business suggestion;
- recurring/subscription candidate;
- transaction/receipt-type routing;
- whether a receipt likely needs a stronger parser or user review;
- insight labels such as `dining_out`, `groceries`, `fuel`, `parking`.

Bad tasks for System-One authority:

- deciding whether a merchant signature is valid;
- changing total/subtotal/tax/tip;
- inventing missing line items;
- choosing a currency without evidence;
- deciding that an email sender is cryptographically trusted;
- silently correcting contradictory receipt facts.

Those stay deterministic, evidence-backed, or user-confirmed.

## 2. Integration boundary

Do not couple product code directly to one Laya runtime.

Define a narrow service interface:

```ts
interface SystemOneClassifier {
  classifyReceipt(input: ReceiptClassificationInput): Promise<ReceiptClassificationResult>;
  classifyLines(input: LineClassificationInput): Promise<LineClassificationResult[]>;
}
```

Each result should carry:

```ts
type ModelDecision<T> = {
  value: T;
  confidence: number;
  modelId: string;
  modelVersion: string;
  taxonomyVersion: string;
  decidedAt: string;
};
```

This lets Deceipt use:

- Laya locally during development;
- a backend-hosted Laya service;
- a future on-device System-One implementation;
- deterministic fallback rules;
- another small model without changing receipt storage semantics.

## 3. Processing order

Recommended order:

```text
Receipt persisted
   ↓
Deterministic normalization / known merchant rules
   ↓
System-One classification
   ↓
Confidence policy
   ↓
Persist enrichment
   ↓
Update insight projections
```

System-One runs **after receipt capture** and asynchronously. A model outage must not block the user's receipt from being saved.

## 4. Inputs

Prefer structured, minimized inputs instead of raw source artifacts.

Example:

```json
{
  "merchant_display_name": "Example Market",
  "merchant_domain": "example.com",
  "currency": "CAD",
  "total_minor": 4287,
  "line_descriptions": [
    "Whole Milk 2L",
    "Bananas",
    "Paper Towels"
  ],
  "source_kind": "email"
}
```

Avoid sending:

- full raw MIME bodies when unnecessary;
- payment tokens/card details;
- addresses unless needed for a specific task;
- signed receipt bytes;
- unrelated user history.

For merchant categorization, a normalized merchant name + representative line descriptions is usually sufficient.

## 5. Initial taxonomy

The category system should be stable and versioned. Suggested v1 hierarchy:

```text
food
  groceries
  restaurant
  cafe
  delivery

transport
  fuel
  transit
  parking
  rideshare
  vehicle_maintenance

shopping
  clothing
  electronics
  household
  general_retail

entertainment
  games
  movies
  events
  hobbies

housing
  rent
  home_improvement

utilities
  phone
  internet
  electricity
  other_utilities

health
  pharmacy
  medical
  fitness

travel
  lodging
  flights
  local_transport

education
business
gifts
fees
other
uncategorized
```

Do not overfit the first taxonomy. Store a `taxonomy_version` so categories can migrate later.

## 6. Confidence policy

Confidence is a product control, not decoration.

Suggested policy:

| Confidence | Behavior |
|---|---|
| high | Apply automatically. |
| medium | Apply as a suggestion and make correction easy; optionally mark subtle UI uncertainty. |
| low | Leave `uncategorized` or send to a stronger classifier/review path. |

Exact numeric thresholds should be calibrated with a labeled validation set rather than guessed in the app.

## 7. Overrides and learning

A user correction is stronger evidence than a model guess.

Persist:

```text
model_suggestion
user_override
effective_value
```

Rules:

1. user override always wins;
2. background reclassification never overwrites an active user override;
3. changing taxonomy/model version may generate a new suggestion without replacing the override;
4. corrections should be available as opt-in/appropriately governed training or evaluation data;
5. recurring merchant corrections can become deterministic per-user rules.

Example:

```text
Laya: Costco → shopping/general_retail
User: Costco → food/groceries
Future Costco receipts for this user: deterministic groceries override
```

## 8. Merchant canonicalization

System-One can suggest that variants refer to the same merchant:

```text
"MCDONALD'S #1842"
"McDonalds 1842"
"MCDONALDS"
       ↓
canonical display group: "McDonald's"
```

But preserve the original merchant string as evidence. Canonicalization is an organizational layer, not a rewrite of the source receipt.

## 9. Line-item classification

Line-level categories enable better insights than receipt-level labels.

Example:

```text
Costco receipt
- groceries          → food/groceries
- TV                 → shopping/electronics
- gasoline           → transport/fuel
```

For mixed-category receipts, Insights should prefer line-level categorized amounts when reliable; otherwise fall back to the receipt-level category.

A line classifier must never change the stored line amount.

## 10. Recurring-spend detection

Use two stages:

1. System-One classifies whether the merchant/item looks like a plausible recurring service.
2. Deterministic history checks cadence and amount patterns.

Do not call a purchase a subscription solely from one model output.

Useful output:

```ts
{
  candidate: true,
  semanticType: "subscription",
  confidence: 0.88
}
```

Then a deterministic process checks, for example, repeated merchant group + similar amount + roughly periodic dates.

## 11. Versioning and reprocessing

Store:

- `model_id`;
- `model_version`;
- `taxonomy_version`;
- `classifier_prompt_or_schema_version`;
- classification timestamp;
- confidence;
- whether value is model, rule, or user-owned.

Reprocessing should be an explicit job that writes new enrichment versions. It must not mutate raw evidence.

## 12. Quality metrics

Build an AxiomGym-like evaluation mindset for Deceipt classification.

Maintain a labeled set covering:

- common merchants;
- ambiguous merchants;
- mixed-category receipts;
- sparse email receipts;
- line items with abbreviations;
- refunds;
- restaurant vs grocery edge cases;
- business/personal ambiguity;
- recurring vs one-off charges.

Measure:

- receipt category accuracy;
- line-item accuracy;
- calibration by confidence bucket;
- user correction rate;
- abstention rate;
- latency;
- failure rate;
- accuracy by source kind and parser quality.

For System-One, **abstaining well is preferable to confidently organizing a receipt incorrectly**.

## 13. v1 acceptance criteria

1. Receipt persistence succeeds when System-One is unavailable.
2. Laya is reachable through a replaceable `SystemOneClassifier` contract.
3. Classification outputs are versioned and confidence-bearing.
4. User overrides cannot be overwritten by automatic reclassification.
5. System-One never changes canonical monetary facts or verification state.
6. At least receipt-level and merchant-level classification are supported.
7. Line-item classification can be added without changing the canonical receipt schema.
8. Insights can consume the effective category while still identifying whether it came from rule, model, or user.
