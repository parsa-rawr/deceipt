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

import {parseReceiptPayload, serializeReceipt, type Receipt} from '../protocol/receipt';
import {normalizationEngine} from '../protocol/normalization';

export interface NfcProbeCase {
  name: string;
  /** What the value is, in words. */
  description: string;
  /** Whether a correct implementation must ACCEPT (already NFC) or REJECT. */
  expectation: 'accept' | 'reject';
  /** The NFC form computed before normalization was disabled. */
  expectedNfc: string;
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
 * The probe cases, as readable strings rather than magic escapes, each carrying
 * the reason it is interesting.
 */
export function probeCases(): Array<{name: string; description: string; value: string}> {
  return [
    {
      name: 'compose_e_acute',
      description: 'e + U+0301 -> U+00E9 (stable since Unicode 3.x: any correct engine must pass)',
      value: 'Cafe\u0301 \u0026 Vine',
    },
    {
      name: 'reorder_ogonek_below',
      description: 'a + U+031B + U+0323: CCC(031B)=216 < CCC(0323)=220, so the marks must swap',
      value: 'Mocha a\u031B\u0323',
    },
    {
      name: 'reorder_ccc_unicode14',
      description: 'a + U+0898 + U+0323: U+0898 is Unicode 14, so a stale table cannot reorder it',
      value: 'Brew a\u0898\u0323',
    },
    {
      name: 'reorder_post_unicode9_1abf',
      description: 'a + U+1ABF + U+0301: U+1ABF is post-Unicode-9; needs reordering and composition',
      value: 'Roast a\u1ABF\u0301',
    },
    {
      name: 'reorder_post_unicode9_1df6',
      description: 'a + U+1DF6 + U+0323: post-Unicode-9 combining mark below',
      value: 'Bean a\u1DF6\u0323',
    },
    {
      name: 'already_nfc_nonASCII',
      description: 'precomposed U+00E9: already NFC, must be accepted unchanged',
      value: 'Caf\u00e9 \u0026 Vine',
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

  // Expectations must be computed while the exact engine is still available.
  const expected: Array<{name: string; description: string; value: string; nfc: string}> = [];
  for (const probeCase of probeCases()) {
    let nfc: string;
    try {
      nfc = probeCase.value.normalize('NFC');
    } catch {
      return {
        engineBefore,
        engineDuring: engineBefore,
        cases: [],
        failures: [],
        skipped: 'this host has no exact NFC engine to compute expectations from',
      };
    }
    expected.push({...probeCase, nfc});
  }

  const cases: NfcProbeCase[] = [];
  const failures: string[] = [];
  let engineDuring = engineBefore;

  for (const item of expected) {
    const isAlreadyNfc = item.nfc === item.value;
    // Force the bridged path for THIS case only.
    Object.defineProperty(String.prototype, 'normalize', {value: undefined, configurable: true, writable: true});
    let observed: string;
    let passed: boolean;
    try {
      engineDuring = normalizationEngine();
      if (engineDuring !== 'native') {
        // Without a bridged engine every "reject" case would pass VACUOUSLY —
        // the parse fails because no engine exists, not because the OS says the
        // value is non-NFC. That would be a probe lying to itself, so it is
        // reported as a hard failure instead of a pass.
        throw new Error(
          `the bridged normalizer is not reachable (engine '${engineDuring}'); the probe cannot distinguish a correct rejection from a missing engine`,
        );
      }
      const payload = serializeReceipt({
        ...base,
        merchant: {...base.merchant, displayName: item.value.slice(0, 120)},
      });
      const parsed = await parseReceiptPayload(payload);
      const accepted = parsed.receipt.merchant.displayName;
      observed = `accepted: ${JSON.stringify(accepted)}`;
      passed = isAlreadyNfc && accepted === item.value;
      if (!isAlreadyNfc) {
        observed += ' (should have been REJECTED as non-NFC)';
      }
    } catch (error) {
      observed = `rejected: ${error instanceof Error ? error.message : String(error)}`;
      passed = !isAlreadyNfc;
    } finally {
      Object.defineProperty(String.prototype, 'normalize', {
        value: platformNormalize,
        configurable: true,
        writable: true,
      });
    }
    if (!passed) {
      failures.push(`${item.name}: ${observed}`);
    }
    cases.push({
      name: item.name,
      description: item.description,
      expectation: isAlreadyNfc ? 'accept' : 'reject',
      expectedNfc: item.nfc,
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
