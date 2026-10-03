/**
 * NFC normalization, with a real implementation available on every runtime.
 *
 * Why this module exists: NFC is a REQUIRED receipt text rule
 * (docs/protocol/receipt-v1.md §1, §3 label 6, §4.3 label 2, §8 `check_text` —
 * "valid UTF-8, NFC-normalized, ... Any violation ⇒ RECEIPT_TEXT_INVALID"), for
 * bidi/lookalike defense on a user-facing document.
 *
 * What is actually true about the engine, stated precisely: `String.prototype.normalize`
 * is an Intl feature and is NOT GUARANTEED to exist on Hermes — Intl is optional in
 * Hermes builds. It is not universally absent: a physical RN 0.87 / Hermes Android
 * build was observed reporting `platform`, i.e. it HAS the method. So this module
 * does not depend on the pessimistic case and does not assume the optimistic one:
 * it uses the engine when the engine has it, uses the OS normalizer when it does
 * not, and fails closed when neither exists. The engine actually in use is
 * reported (`normalizationEngine`) rather than assumed, and can be read on device.
 *
 * Resolution order:
 *
 *   1. `String.prototype.normalize` when the engine has it — exact, synchronous,
 *      and what every Intl-enabled Hermes/Node/JSC build uses.
 *   2. The OS normalizer exposed through the bridge: Android
 *      `java.text.Normalizer.normalize(s, Form.NFC)` and iOS
 *      `precomposedStringWithCanonicalMapping`. Both are ICU-backed, so they
 *      carry CURRENT Unicode tables maintained by the vendor. This is the path
 *      a Hermes build without Intl takes.
 *   3. Nothing — the receipt is REJECTED with `RECEIPT_TEXT_INVALID`.
 *
 * ## Why no third-party normalizer
 *
 * A pure-JavaScript implementation would have to ship its own Unicode tables,
 * and the ones available are stale: `unorm` carries Unicode 8.0 (2016) data, so
 * it accepts some post-8.0 combining sequences the platform calls non-NFC. A
 * blacklist of those code points derived from fuzzing would not be coverage
 * proof, and shipping an accepted-non-NFC path would weaken the lookalike defense
 * that receipt-v1.md §8 requires. The OS normalizer is exact, is already
 * maintained, and needs no new package.
 *
 * ## Synchronous parsing, asynchronous normalizer
 *
 * `check_text` runs inside receipt parsing, which is synchronous, while the
 * bridge is asynchronous. Rather than making the whole parse async (invasive) or
 * hiding a global pending list (easy to get wrong), `parseReceiptPayload`
 * COLLECTS the non-ASCII values it could not check into `deferredNfcChecks`, and
 * `verifyReceipt` confirms exactly those values before any receipt can be
 * accepted. On an engine with `String.prototype.normalize` the list is always
 * empty and no async work happens at all.
 */

export type NormalizationEngine = 'platform' | 'native' | 'none';

/**
 * The bridge's NFC normalizer, registered by the app shell exactly like the
 * CSPRNG source. Returns the NFC form of the input text, or throws.
 *
 * It is asynchronous because it crosses the bridge, while receipt parsing is
 * synchronous; `receipt.ts` therefore COLLECTS non-ASCII values it cannot check
 * and `verification.ts` confirms them before any receipt can be accepted. See
 * the module docblock for why no third-party approximator is used.
 */
export interface NativeNfcSource {
  normalizeNfc(text: string): Promise<string>;
}

let nativeNfcSource: NativeNfcSource | null = null;

/** Register the platform normalizer. Called once at app startup. */
export function setNativeNfcSource(source: NativeNfcSource | null): void {
  nativeNfcSource = source;
}

/**
 * Which engine will decide NFC. `platform` is the engine's own
 * `String.prototype.normalize`; `native` is the OS normalizer behind the bridge
 * (Android `java.text.Normalizer`, iOS `precomposedStringWithCanonicalMapping`).
 * Both are ICU-backed and exact; `none` means the receipt must be rejected.
 */
export function normalizationEngine(): NormalizationEngine {
  if (typeof ''.normalize === 'function') {
    return 'platform';
  }
  if (nativeNfcSource !== null) {
    return 'native';
  }
  return 'none';
}

/**
 * True when NFC can be decided EXACTLY in this runtime. There is no approximate
 * engine: either an ICU-backed normalizer is available or the receipt is
 * rejected, so this is false only when NFC is unverifiable.
 */
export function normalizationEngineIsExact(): boolean {
  return normalizationEngine() !== 'none';
}

/** True when a real implementation is available. */
export function canNormalize(): boolean {
  return normalizationEngine() !== 'none';
}

/** True when the synchronous engine can decide NFC without the bridge. */
export function hasSynchronousNfc(): boolean {
  return typeof ''.normalize === 'function';
}

/**
 * The NFC form of `value` when the SYNCHRONOUS engine can produce it, or `null`
 * when the caller must defer to `normalizeNfcAsync`. `null` never means "already
 * NFC": a caller receiving it must not conclude the value is normalized.
 */
export function toNfc(value: string): string | null {
  if (typeof value.normalize === 'function') {
    return value.normalize('NFC');
  }
  return null;
}

/**
 * The NFC form of `value` through the platform normalizer behind the bridge.
 * Throws when no exact implementation exists, so a caller can never silently
 * accept an unnormalized value.
 */
export async function normalizeNfcAsync(value: string): Promise<string> {
  const synchronous = toNfc(value);
  if (synchronous !== null) {
    return synchronous;
  }
  if (nativeNfcSource === null) {
    throw new Error('this runtime has no exact NFC implementation');
  }
  return nativeNfcSource.normalizeNfc(value);
}

/** True when the value is already NFC, using whichever exact engine exists. */
export async function isNfcAsync(value: string): Promise<boolean> {
  return (await normalizeNfcAsync(value)) === value;
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
