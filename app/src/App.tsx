/**
 * The app shell: mode selection, the two mode screens, and the binding of the
 * shared logic to a concrete storage port and the pinned anchor set.
 *
 * The shell owns exactly three decisions and no protocol logic:
 *  1. which mode the operator chose;
 *  2. which `DeceiptNative` adapter to use (a real one registered by A4/A5, or
 *    the in-process mock when no native module is present);
 *  3. which `KeyValueStore` backs the receipt history.
 *
 * The store is an in-memory implementation today. That is honest about a real
 * gap rather than hiding it: receipt history does NOT yet survive a full process
 * restart, because persisting it needs an on-device key-value backend
 * (`@react-native-async-storage/async-storage` or equivalent), which is a new
 * native dependency and therefore A0's decision, not mine. The in-memory port
 * satisfies the `KeyValueStore` interface, so swapping it is a one-line change
 * here and nothing else in the app moves.
 */

import React, {useMemo, useState} from 'react';
import {SafeAreaProvider} from 'react-native-safe-area-context';
import {NativeModules, ScrollView, StatusBar, Text, View, useColorScheme} from 'react-native';
import type {DeceiptNative} from './native/DeceiptNative';
import {InMemoryDeceiptNative} from './native/mock/InMemoryDeceiptNative';
import {adaptNativeModule, probeNativeModule, type ProbeResult} from './native/adapterShim';
import {base64Decode} from './protocol/bytes';
import {normalizationEngine, normalizationEngineIsExact} from './protocol/normalization';
import {canGenerateSecureRandom, setNativeRandomSource} from './protocol/crypto';
import {MemoryKeyValueStore, ReceiptStore} from './storage/receiptStore';
import {TRUST_ANCHORS} from './config/trustAnchors';
import {MerchantScreen} from './ui/MerchantScreen';
import {CustomerScreen} from './ui/CustomerScreen';
import {ActionButton, Card, colors, styles} from './ui/primitives';

type Mode = 'menu' | 'merchant' | 'customer';

/** The demo's fixed verification instant, matching the frozen credential window. */
const DEMO_NOW_UNIX = 1767225540;

export interface AppProps {
  /** Overrides for tests and for a host that injects a prepared adapter. */
  native?: DeceiptNative;
  store?: ReceiptStore;
  now?: () => number;
}

export default function App(props: AppProps): React.JSX.Element {
  const isDarkMode = useColorScheme() === 'dark';
  return (
    <SafeAreaProvider>
      <StatusBar barStyle={isDarkMode ? 'light-content' : 'dark-content'} />
      <AppContent {...props} />
    </SafeAreaProvider>
  );
}

export function AppContent({native, store, now}: AppProps): React.JSX.Element {
  const [mode, setMode] = useState<Mode>('menu');
  const binding = useMemo(() => (native === undefined ? resolveNativeAdapter() : bindSuppliedAdapter(native)), [native]);
  const resolvedNative = binding.adapter;
  // Point the protocol layer at the adapter's CSPRNG before any screen can mint
  // an identifier or a nonce. Hermes has no `globalThis.crypto`, so on device
  // this is the only secure source there is.
  useMemo(() => {
    setNativeRandomSource(
      binding.probe.compatible
        ? {
            randomBytes: async (count: number) => base64Decode(await binding.adapter.randomBytes(count)),
          }
        : null,
    );
    return undefined;
  }, [binding]);
  const resolvedStore = useMemo(() => store ?? new ReceiptStore(new MemoryKeyValueStore()), [store]);
  const clock = useMemo(() => now ?? (() => DEMO_NOW_UNIX), [now]);

  return (
    <View style={styles.screen} testID="app-root">
      {mode !== 'menu' ? (
        <ActionButton
          label="← Back"
          onPress={() => setMode('menu')}
          testID="back-to-menu"
          accessibilityLabel="back-to-menu"
          variant="secondary"
        />
      ) : null}
      {mode === 'menu' ? (
        <ScrollView contentContainerStyle={styles.screen}>
          <Text style={styles.title}>Deceipt</Text>
          <Text style={styles.subtitle}>
            Proof-of-concept receipt transfer. One app, two modes: the merchant signs and serves, the customer verifies.
          </Text>
          <Card testID="adapter-card">
            <Text style={styles.sectionTitle}>Adapter</Text>
            <Text style={styles.value}>{describeAdapter(resolvedNative)}</Text>
            <Text style={styles.label} testID="nfc-engine">
              NFC engine: {normalizationEngine()}
              {normalizationEngineIsExact() ? '' : ' (fallback tables predate Unicode 9; a few newer combining marks may not be reordered)'}
            </Text>
            <Text style={styles.label} testID="randomness-source">
              randomness: {canGenerateSecureRandom() ? (binding.isNative ? 'native CSPRNG' : 'WebCrypto (mock build)') : 'unavailable'}
            </Text>
            {binding.probe.compatible ? (
              <Text style={styles.label} testID="adapter-compatible">
                contract check: ok ({binding.probe.present.length} methods, events via {binding.probe.eventMode})
              </Text>
            ) : (
              <>
                <Text style={styles.error} testID="adapter-incompatible">
                  This native module does not match the app's contract, so Bluetooth modes are disabled.
                </Text>
                {binding.probe.problems.map(problem => (
                  <Text key={problem} style={styles.error}>
                    {problem}
                  </Text>
                ))}
              </>
            )}
            <Text style={styles.notice}>
              The shared protocol, state machine and verification run identically whichever adapter is present.
            </Text>
          </Card>
          <ActionButton label="Merchant mode" onPress={() => setMode('merchant')} testID="mode-merchant" accessibilityLabel="mode-merchant" />
          <ActionButton
            label="Customer mode"
            onPress={() => setMode('customer')}
            testID="mode-customer"
            accessibilityLabel="mode-customer"
            variant="secondary"
          />
        </ScrollView>
      ) : null}
      {mode === 'merchant' && binding.probe.compatible ? <MerchantScreen native={resolvedNative} now={clock} /> : null}
      {mode === 'merchant' && !binding.probe.compatible ? (
        <Text style={styles.error} testID="merchant-blocked">
          Merchant mode needs a native module matching the app's contract. See the adapter report on the menu.
        </Text>
      ) : null}
      {mode === 'customer' && binding.probe.compatible ? (
        <CustomerScreen native={resolvedNative} store={resolvedStore} anchors={TRUST_ANCHORS} now={clock} />
      ) : null}
      {mode === 'customer' && !binding.probe.compatible ? (
        <Text style={styles.error} testID="customer-blocked">
          Customer mode needs a native module matching the app's contract. See the adapter report on the menu.
        </Text>
      ) : null}
    </View>
  );
}

export interface AdapterBinding {
  adapter: DeceiptNative;
  probe: ProbeResult;
  /** `true` when the module is native (rather than the in-process mock). */
  isNative: boolean;
}

/**
 * Resolve the adapter and PROBE it before use.
 *
 * The probe matters because the shared test suite runs against the mock: a
 * native module whose `subscribe` has the wrong arity passes every Jest test and
 * redboxes on the first tap. Probing at resolution time turns that into a
 * reported, visible state — the app says which method does not match instead of
 * crashing when the user chooses a mode.
 *
 * Event delivery is adapted if needed: A4 implements `subscribe(listener)`
 * natively; the emitter pattern is absorbed by `adaptNativeModule` so the native
 * side needs no callback ABI.
 */
function resolveNativeAdapter(): AdapterBinding {
  const registered: unknown = (NativeModules as Record<string, unknown>).DeceiptNative;
  const probe = probeNativeModule(registered);
  if (registered !== undefined && registered !== null && probe.present.length > 0) {
    return {
      adapter: probe.compatible ? adaptNativeModule(registered) : new InMemoryDeceiptNative(),
      probe,
      isNative: true,
    };
  }
  const mock = new InMemoryDeceiptNative();
  return {adapter: mock, probe: probeNativeModule(mock), isNative: false};
}

/** Probe an adapter supplied by a host (tests, an embedded build). */
function bindSuppliedAdapter(adapter: DeceiptNative): AdapterBinding {
  return {adapter, probe: probeNativeModule(adapter), isNative: !(adapter instanceof InMemoryDeceiptNative)};
}

function describeAdapter(adapter: DeceiptNative): string {
  return adapter instanceof InMemoryDeceiptNative
    ? 'Mock adapter (no usable native module — this build cannot use Bluetooth)'
    : 'Native adapter (Bluetooth available)';
}

export const APP_DEMO_NOW_UNIX = DEMO_NOW_UNIX;
export {colors};
