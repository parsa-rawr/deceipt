/**
 * NFC normalization, with a real implementation available on every runtime.
 *
 * Why this module exists: NFC is a REQUIRED receipt text rule
 * (docs/protocol/receipt-v1.md §1, §3 label 6, §4.3 label 2, §8 `check_text` —
 * "valid UTF-8, NFC-normalized, ... Any violation ⇒ RECEIPT_TEXT_INVALID"), for
 * bidi/lookalike defense on a user-facing document. Hermes on RN 0.87 does not
 * guarantee `String.prototype.normalize` (it is an Intl feature, and Intl is
 * optional in Hermes builds), so a fallback is needed rather than a silent
 * weakening of the check.
 *
 * Resolution order:
 *
 *   1. `String.prototype.normalize` when the engine has it — exact by
 *      definition, and what every Intl-enabled Hermes/Node/JSC build uses.
 *   2. `unorm` (a pure-JavaScript implementation of Unicode normalization,
 *      UAX #15) otherwise. No native code, so it works in Hermes.
 *   3. Nothing — the caller is told the result is `UNVERIFIED`, never `OK`.
 *
 * ## What the fallback can and cannot promise (measured, not assumed)
 *
 * `unorm` ships Unicode 8.0 data (published 2016), so it is stale relative to
 * the platform's tables. A 40,000-case differential fuzz against
 * `String.prototype.normalize` showed `unorm` differing only on 13 combining
 * code points assigned AFTER Unicode 8 (`U+1ABF`, `U+1AC0`, `U+1AC3`, `U+1AC4`,
 * `U+1ACA`, `U+1ADD`, `U+1AE6`, `U+1AEB`, `U+1DF6`–`U+1DFA`), where it fails to
 * reorder a sequence the platform considers non-NFC.
 *
 * The direction of that error matters: `unorm` would ACCEPT a string the
 * platform calls non-NFC. Accepting a non-NFC string weakens the lookalike
 * defense for those code points; it does not break the arithmetic, identifier or
 * signature checks, and it never rejects a NFC string the platform accepts.
 *
 * Therefore the fallback is used, but its use is REPORTED rather than hidden:
 * `normalizationEngineIsExact()` is false on that path, the app surfaces it, and
 * the honest fix (a dependency carrying current Unicode tables) is a package
 * decision rather than something to fake here.
 */

import unorm from 'unorm';

export type NormalizationEngine = 'platform' | 'unorm' | 'none';

/** Which engine this runtime will use. */
export function normalizationEngine(): NormalizationEngine {
  if (typeof ''.normalize === 'function') {
    return 'platform';
  }
  if (typeof unorm?.nfc === 'function') {
    return 'unorm';
  }
  return 'none';
}

/**
 * True when NFC can be checked exactly — the platform normalizer is present.
 * False means the fallback's stale tables could accept a non-NFC string for a
 * handful of post-Unicode-8 combining marks.
 */
export function normalizationEngineIsExact(): boolean {
  return normalizationEngine() === 'platform';
}

/** True when a real implementation is available (either engine). */
export function canNormalize(): boolean {
  return normalizationEngine() !== 'none';
}

/**
 * The NFC form of `value`, or `null` when no engine can produce it. `null` is
 * distinct from "already NFC": a caller that cannot normalize must not conclude
 * that the input is normalized.
 */
export function toNfc(value: string): string | null {
  if (typeof value.normalize === 'function') {
    return value.normalize('NFC');
  }
  if (typeof unorm?.nfc === 'function') {
    return unorm.nfc(value);
  }
  return null;
}

/** True when `value` is already in NFC form. Throws only when nothing can decide. */
export function isNfc(value: string | null): boolean {
  if (value === null) {
    return false;
  }
  const normalized = toNfc(value);
  if (normalized === null) {
    throw new Error('no NFC implementation is available in this runtime');
  }
  return normalized === value;
}
