# Spending Insights v1

**Status:** PLANNED · **Date:** 2026-10-03  
**Goal:** Give users a useful, trustworthy view of spending habits across native Deceipt receipts and email-imported receipts.

## 1. Product principle

The Insights page is a deterministic analytics surface over stored receipt facts.

System-One may provide categories, tags, merchant grouping, and candidate labels, but it must **not generate spending totals on demand**.

```text
Receipt facts + effective enrichment
              ↓
       analytics projection
              ↓
          Insights UI
```

This makes every displayed number explainable back to receipts.

## 2. Initial page structure

### Header / period control

Support:

- This week
- This month
- Last 3 months
- This year
- Custom range

The active period drives every card/chart below.

### Summary cards

Initial cards:

- **Total spend**
- **Receipt count**
- **Average receipt**
- **Change vs previous comparable period**

Optional later cards:

- median receipt;
- total refunds;
- uncategorized spend;
- verified vs imported receipt coverage.

### Spend over time

Time-series chart with granularity chosen from period:

- daily for short ranges;
- weekly for multi-month;
- monthly for year-scale.

A tap on a point/bar should drill into the receipts behind that value.

### Category breakdown

Show spend by effective category.

Preferred calculation:

1. line-level categories when categorized line amounts cover the receipt reliably;
2. otherwise receipt-level category;
3. otherwise `uncategorized`.

This prevents a mixed Costco/Walmart-style receipt from being forced entirely into one category when line data is available.

### Merchant breakdown

Show:

- top merchants by spend;
- purchase count;
- average spend at merchant;
- change vs previous period.

Canonical merchant grouping comes from explicit mapping/System-One enrichment, while original merchant evidence stays untouched.

### Recurring spend

Show candidates only after semantic classification is corroborated by deterministic historical cadence.

Examples:

- subscriptions;
- memberships;
- monthly services.

Each candidate should link to the receipts that caused the detection.

### Notable changes

Examples:

- category increased materially vs previous period;
- new recurring merchant;
- unusually large receipt relative to user's own history;
- spending concentration changed.

These are descriptive observations, not financial advice.

## 3. Filters

The page should allow filtering by:

- category;
- merchant;
- receipt source: native Deceipt / email import;
- verification state;
- personal/business label;
- currency;
- receipt status;
- tags.

Filters must update totals and charts from the same projection/query rules.

## 4. Arithmetic semantics

### Sales
Count as positive spend.

### Refunds
Subtract from spend in the applicable period according to the stored refund receipt/event date. Preserve the link to the original receipt when known.

### Voids
Do not count a voided sale as spend once the void relationship is known.

### Tips, tax, fees
Included in total spend because they contribute to the paid total. Dedicated breakdowns may expose them separately.

### Discounts
Do not double-subtract if already reflected in the canonical total.

### Partial/incomplete imports
A receipt missing a reliable currency or total should not contribute to total-spend aggregates. It can still contribute to receipt-count/review metrics where appropriate.

## 5. Currency policy

Do **not** silently sum CAD + USD + EUR into one number.

v1 options:

- default to the user's dominant/home currency only when receipts are already in that currency;
- show separate totals by currency when multiple currencies occur.

Future FX conversion must store:

- source rate;
- rate timestamp/date;
- base/quote currency;
- conversion policy;
- original amount.

Converted values are derived analytics, never a rewrite of the receipt.

## 6. Insight projection

Avoid scanning and reclassifying every receipt on every page load.

Maintain a derived projection/materialized analytics layer keyed by user and time bucket.

Conceptual inputs:

```text
receipt_id
effective_date
kind: sale/refund/void
currency
total_minor
merchant_group_id
effective_receipt_category
line allocations by category
source_kind
verification_state
personal_business
tags
```

The projection should be rebuildable from canonical receipts + enrichment.

Triggers that invalidate/recompute affected buckets:

- receipt imported;
- receipt deleted;
- refund/void linked;
- category changed;
- merchant grouping changed;
- user override changed;
- parser reprocessing changes canonical eligible facts.

## 7. Explainability

Every number should be drillable to its source receipts.

Examples:

- Tap **Groceries — $312.40** → receipts/lines contributing to $312.40.
- Tap **+18% vs last month** → current and previous date ranges + contributing receipts.
- Tap recurring candidate → historical receipt sequence.

No opaque "AI says you spent..." totals.

## 8. Classification coverage

Insights should expose data quality without making the page noisy.

Useful metadata:

```text
92% of spend categorized
8% uncategorized
3 receipts need review
```

This gives the user a reason to correct uncertain imports and improves trust in category charts.

## 9. Suggested v1 screen

```text
┌─────────────────────────────────────┐
│ Insights                   [Month ▾]│
│                                     │
│ $1,284.22 spent     +6.2% vs prior  │
│ 37 receipts         $34.71 average  │
│                                     │
│ Spend over time                     │
│ [          chart                  ] │
│                                     │
│ Categories                          │
│ Groceries      $382   30%           │
│ Dining         $244   19%           │
│ Transport      $181   14%           │
│ ...                                 │
│                                     │
│ Top merchants                       │
│ 1. Costco       $211                │
│ 2. ...                              │
│                                     │
│ Recurring                            │
│ 3 candidates                        │
│                                     │
│ 94% categorized · 2 need review     │
└─────────────────────────────────────┘
```

Exact visual design remains a later UI task; this document defines the behavior and data contract.

## 10. Privacy

Insights are sensitive because they reveal spending habits.

Plan for:

- account-scoped authorization on every analytics query;
- no cross-user aggregation that exposes individual behavior;
- no raw receipt details in ordinary analytics logs;
- explicit deletion propagation from receipts to projections;
- model inputs minimized to the task;
- future export/delete controls;
- clear distinction between local/on-device enrichment and backend processing if both exist.

## 11. Performance

Desired behavior:

- initial summary loads from precomputed/indexed projection;
- charts do not require model inference;
- category edits update affected projections incrementally;
- large histories can be rebuilt in background jobs;
- stale projection state is versioned and detectable.

The page can show the last consistent projection rather than blocking on Laya.

## 12. v1 acceptance criteria

1. The page supports month and custom-range spend totals.
2. Every total is computed from stored receipt amounts using integer-minor-unit arithmetic.
3. Refunds and voids do not inflate spending.
4. Mixed currencies are never silently summed.
5. Category and merchant breakdowns link back to contributing receipts.
6. Email imports and native receipts can both participate while retaining source/trust filters.
7. System-One downtime does not prevent existing insights from loading.
8. User category corrections propagate to the projection.
9. Uncategorized/needs-review coverage is visible.
10. No insight total depends on a free-form model-generated arithmetic answer.
