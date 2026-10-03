/**
 * Standalone smoke for the TEMPORARY NFC probe.
 *
 * It runs the probe against a host engine so the probe's own logic is known-good
 * before the physical run: the cases must classify correctly (precomposed values
 * accepted, genuinely reordering values rejected) and the engine must be restored
 * afterwards. This is not the device evidence — that comes from the physical
 * bundle — it only proves the probe is not lying to itself.
 */

import {runNfcProbe, summarizeNfcProbe, composeProbes, parseProbes} from '../src/dev/nfcProbe';
import {buildDemoReceipt} from '../src/demo/demoReceipt';
import {normalizationEngine, setNativeNfcSource} from '../src/protocol/normalization';
import {buildMockPair} from './harness';

const NOW = 1767225600;

describe('NFC probe smoke (TEMPORARY)', () => {
  afterEach(() => {
    setNativeNfcSource(null);
  });

  it('proves COMPOSITION by comparing the bridge output to the expected NFC form', async () => {
    const pair = await buildMockPair();
    const base = await buildDemoReceipt({
      merchantId: pair.provision.merchantId,
      credentialBytes: pair.provision.credentialBytes,
    });
    // The host's own normalizer stands in for the OS normalizer behind the
    // bridge. It must be CAPTURED, not looked up on String.prototype: the probe
    // disables that method per case, and a stand-in that consults it would fail
    // for the probe's reason rather than its own — which is exactly what a real
    // OS normalizer never does.
    const platformNormalize = String.prototype.normalize;
    setNativeNfcSource({normalizeNfc: async (text: string) => platformNormalize.call(text, 'NFC')});
    const report = await runNfcProbe(base);
    expect(report.skipped).toBeUndefined();
    expect(report.cases.length).toBe(composeProbes().length + parseProbes().length);
    expect(report.failures).toEqual([]);
    // The compose cases must have actually exercised composition or reordering,
    // not passed because the input was already NFC.
    const composeCases = report.cases.filter(item => item.expectation === 'compose');
    const exercised = composeCases.filter(item => item.expected !== item.observed);
    expect(composeCases.length).toBeGreaterThanOrEqual(6);
    expect(exercised.length).toBeGreaterThanOrEqual(4);
    // The parse cases must reject with the specific non-NFC failure.
    const rejectCases = report.cases.filter(item => item.expectation === 'reject');
    expect(rejectCases.length).toBeGreaterThanOrEqual(2);
    expect(rejectCases.every(item => /not NFC-normalized/.test(item.observed))).toBe(true);
    expect(summarizeNfcProbe(report)).toContain(`${report.cases.length}/${report.cases.length} cases`);
  });

  it('detects a permissive normalizer instead of passing it', async () => {
    const pair = await buildMockPair();
    const base = await buildDemoReceipt({
      merchantId: pair.provision.merchantId,
      credentialBytes: pair.provision.credentialBytes,
    });
    // A normalizer that claims every value is already NFC: the probe must FAIL the
    // reordering cases, which is precisely the stale-table failure mode.
    setNativeNfcSource({normalizeNfc: async (text: string) => text});
    const report = await runNfcProbe(base);
    expect(report.failures.length).toBeGreaterThan(0);
    expect(report.cases.some(item => !item.passed)).toBe(true);
  });

  it('restores the platform normalizer after every case', async () => {
    const pair = await buildMockPair();
    const base = await buildDemoReceipt({
      merchantId: pair.provision.merchantId,
      credentialBytes: pair.provision.credentialBytes,
    });
    const platformNormalize = String.prototype.normalize;
    setNativeNfcSource({normalizeNfc: async (text: string) => platformNormalize.call(text, 'NFC')});
    expect(typeof ''.normalize).toBe('function');
    await runNfcProbe(base);
    // The probe must not leave the engine disabled.
    expect(typeof ''.normalize).toBe('function');
    expect('e\u0301'.normalize('NFC')).toBe('\u00e9');
    expect(normalizationEngine()).toBe('platform');
  });

  void NOW;
});
