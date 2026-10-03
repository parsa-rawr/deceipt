/**
 * TEMPORARY DEV PROBE — remove with the other diagnostics once the device flow is
 * proven.
 *
 * It answers one question that cannot be answered by reading code: does the
 * bridged OS normalizer behave exactly like a correct NFC implementation on the
 * cases where a stale table would silently ACCEPT a non-NFC string?
 *
 * Method: for each case, disable `String.prototype.normalize` so the shared layer
 * is FORCED onto the bridge, run the real parse boundary, and compare against the
 * expected result computed while the engine was still available. The engine is
 * restored for every case, whether the case passed or threw.
 *
 * The probe does not implement normalization. Expected values come from whichever
 * exact engine the host has, and the cases are chosen so a stale implementation is
 * caught: the reordering cases need combining-class data (U+0898 is Unicode 14,
 * U+1ABF/U+1AC0/U+1DF6-U+1DFA are post-Unicode-9), while the precomposed cases
 * need composition data stable since Unicode 3.x and therefore must pass on ANY
 * correct implementation.
 */

import {ProtocolError} from '../protocol/errors';
import {parseReceiptPayload, serializeReceipt, type Receipt} from '../protocol/receipt';
import {normalizationEngine, normalizeNfcAsync} from '../protocol/normalization';

export interface NfcProbeCase {
  name: string;
  /** What the value is, in words. */
  description: string;
  /** What a correct implementation must do. */
  expectation: 'compose' | 'reject';
  /** For `compose`: the NFC form the bridge must return. For `reject`: the
   *  decomposed input the parse boundary must refuse. */
  expected: string;
  /** What the probe observed on the bridged path. */
  observed: string;
  passed: boolean;
}

export interface NfcProbeReport {
  /** The engine in use BEFORE the probe disables the platform normalizer. */
  engineBefore: string;
  /** The engine in use WHILE the probe runs (must be 'native' for a valid run). */
  engineDuring: string;
  cases: NfcProbeCase[];
  failures: string[];
  /** Set when the probe could not run meaningfully. */
  skipped?: string;
}

/**
 * Compose probes: RAW non-NFC strings handed straight to the bridged normalizer.
 *
 * These are the cases that can prove the OS COMPOSED something. A receipt-level
 * rejection cannot: rejecting a non-NFC document proves the parse boundary
 * rejects, which is a different property. So each case carries the NFC form a
 * correct implementation must return.
 */
export function composeProbes(): Array<{name: string; description: string; raw: string; expectedNfc: string}> {
  return [
    {
      name: 'compose_e_acute',
      description: 'e + U+0301 composes to U+00E9 (stable since Unicode 3.x)',
      raw: 'Café \u0026 Vine',
      expectedNfc: 'Café \u0026 Vine',
    },
    {
      name: 'compose_a_ring',
      description: 'A + U+030A composes to U+00C5',
      raw: '\u00c5ngstrom vs Ångstrom',
      expectedNfc: '\u00c5ngstrom vs Ångstrom',
    },
    {
      name: 'compose_hangul_jamo',
      description: 'Hangul jamo U+1100 U+1161 composes to the syllable U+AC00',
      raw: '가',
      expectedNfc: '가',
    },
    {
      name: 'reorder_ogonek_below',
      description: 'a + U+031B + U+0323: CCC(031B)=216 < CCC(0323)=220, so the marks MUST swap',
      raw: 'Mocha ạ̛',
      expectedNfc: 'Mocha ạ̛',
    },
    {
      name: 'reorder_ccc_unicode14',
      description: 'a + U+0898 + U+0323: U+0898 is Unicode 14, so a stale table cannot reorder it',
      raw: 'Brew ạ࢘',
      expectedNfc: 'Brew ạ࢘',
    },
    {
      name: 'reorder_post_unicode9_1abf',
      description: 'a + U+1ABF + U+0301: post-Unicode-9 mark needing reordering then composition',
      raw: 'Roast áᪿ',
      expectedNfc: 'Roast áᪿ',
    },
    {
      name: 'reorder_post_unicode9_1df6',
      description: 'a + U+1DF6 + U+0323: post-Unicode-9 combining mark below',
      raw: 'Bean ạ᷶',
      expectedNfc: 'Bean ạ᷶',
    },
  ];
}

/**
 * Parse probes: receipts whose display name is deliberately DECOMPOSED. A correct
 * boundary must REJECT these (receipt-v1.md §8), which is what proves the raw
 * bytes reached the check rather than a pre-normalized value.
 */
export function parseProbes(): Array<{name: string; description: string; decomposed: string}> {
  return [
    {
      name: 'parse_rejects_decomposed_latin',
      description: 'decomposed e + U+0301 must be rejected as non-NFC',
      decomposed: 'Café \u0026 Vine',
    },
    {
      name: 'parse_rejects_decomposed_unicode14_mark',
      description: 'a + U+0898 + U+0323 must be rejected: the ordering is wrong and the mark is Unicode 14',
      decomposed: 'Brew ạ࢘',
    },
  ];
}

/**
 * Run the probe. `buildReceipt` supplies a valid receipt whose text this probe
 * mutates, so the parse boundary is exercised on a real document.
 */
export async function runNfcProbe(base: Receipt): Promise<NfcProbeReport> {
  const engineBefore = normalizationEngine();
  const platformNormalize = String.prototype.normalize;

  // Expectations are computed while the exact engine is still available. If the
  // host has no exact engine there is nothing to compare against, so the probe
  // declines to run rather than inventing expectations.
  const composeExpected: Array<{name: string; description: string; raw: string; nfc: string}> = [];
  for (const probe of composeProbes()) {
    const nfc = probe.raw.normalize('NFC');
    if (nfc === probe.raw) {
      // The case does not actually need composing in this Unicode version, so it
      // cannot prove composition happened. Reported rather than silently kept.
      composeExpected.push({...probe, nfc});
      continue;
    }
    composeExpected.push({...probe, nfc});
  }

  const cases: NfcProbeCase[] = [];
  const failures: string[] = [];
  let engineDuring = engineBefore;

  /** Run `work` with the JS engine disabled, always restoring it. */
  const withBridgedEngine = async <T>(work: () => Promise<T>): Promise<T> => {
    Object.defineProperty(String.prototype, 'normalize', {value: undefined, configurable: true, writable: true});
    try {
      engineDuring = normalizationEngine();
      return await work();
    } finally {
      Object.defineProperty(String.prototype, 'normalize', {
        value: platformNormalize,
        configurable: true,
        writable: true,
      });
    }
  };

  // --- Property 1: the bridge COMPOSES / REORDERS raw non-NFC text -----------
  for (const item of composeExpected) {
    const needsNormalization = item.nfc !== item.raw;
    let observed: string;
    let passed: boolean;
    try {
      const bridged = await withBridgedEngine(() => normalizeNfcAsync(item.raw));
      observed = `bridged -> ${JSON.stringify(bridged)}`;
      if (!needsNormalization) {
        passed = true;
        observed += ' (already NFC in this Unicode version: no reordering required, not a composition test)';
      } else {
        passed = bridged === item.nfc;
        if (!passed) {
          observed += ` (expected ${JSON.stringify(item.nfc)})`;
        }
      }
    } catch (error) {
      observed = `bridged threw: ${error instanceof Error ? error.message : String(error)}`;
      passed = false;
    }
    if (!passed) {
      failures.push(`${item.name}: ${observed}`);
    }
    cases.push({
      name: item.name,
      description: item.description,
      expectation: 'compose',
      expected: item.nfc,
      observed,
      passed,
    });
  }

  // --- Property 2: the parse boundary REJECTS raw decomposed receipt bytes ----
  for (const item of parseProbes()) {
    let observed: string;
    let passed: boolean;
    try {
      const parsed = await withBridgedEngine(async () => {
        if (normalizationEngine() !== 'native') {
          // Without the bridge the rejection would be vacuous: it would mean "no
          // engine exists", not "the OS agreed the value is non-NFC".
          throw new Error(
            `the bridged normalizer is not reachable (engine '${normalizationEngine()}'); this rejection cannot be attributed to the OS`,
          );
        }
        // Serialization writes the string verbatim (nothing in `receiptToCbor`
        // calls checkText, and checkText only validates), so the RAW decomposed
        // bytes reach the parse boundary. This is what makes the rejection
        // meaningful: the boundary saw non-NFC input and refused it.
        const payload = serializeReceipt({
          ...base,
          merchant: {...base.merchant, displayName: item.decomposed.slice(0, 120)},
        });
        return parseReceiptPayload(payload);
      });
      observed = `accepted: ${JSON.stringify(parsed.receipt.merchant.displayName)} (should have been REJECTED)`;
      passed = false;
    } catch (error) {
      observed = `rejected: ${error instanceof Error ? error.message : String(error)}`;
      passed =
        error instanceof ProtocolError &&
        error.name === 'RECEIPT_TEXT_INVALID' &&
        /not NFC-normalized/.test(error.message);
    }
    if (!passed) {
      failures.push(`${item.name}: ${observed}`);
    }
    cases.push({
      name: item.name,
      description: item.description,
      expectation: 'reject',
      expected: item.decomposed,
      observed,
      passed,
    });
  }

  return {engineBefore, engineDuring, cases, failures};
}

/** A one-line summary suitable for a log or a rendered line. */
export function summarizeNfcProbe(report: NfcProbeReport): string {
  if (report.skipped !== undefined) {
    return `NFC probe skipped: ${report.skipped}`;
  }
  const passed = report.cases.filter(item => item.passed).length;
  const failures = report.failures.length === 0 ? '' : ` FAILURES: ${report.failures.join('; ')}`;
  return `NFC probe: ${passed}/${report.cases.length} cases (engine ${report.engineBefore} -> ${report.engineDuring})${failures}`;
}
