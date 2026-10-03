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
  const resolvedNative = useMemo(() => native ?? resolveNativeAdapter(), [native]);
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
      {mode === 'merchant' ? <MerchantScreen native={resolvedNative} now={clock} /> : null}
      {mode === 'customer' ? (
        <CustomerScreen native={resolvedNative} store={resolvedStore} anchors={TRUST_ANCHORS} now={clock} />
      ) : null}
    </View>
  );
}

/**
 * Pick the adapter. A4/A5 register a hand-written native module under
 * `DeceiptNative`; when it is absent (a JS-only build, Jest, or a platform that
 * has not been built yet) the in-process mock stands in so the app still runs.
 * The choice is reported in the UI rather than made silently.
 */
function resolveNativeAdapter(): DeceiptNative {
  const registered: unknown = (NativeModules as Record<string, unknown>).DeceiptNative;
  if (isDeceiptNative(registered)) {
    return registered;
  }
  return new InMemoryDeceiptNative();
}

function isDeceiptNative(candidate: unknown): candidate is DeceiptNative {
  if (typeof candidate !== 'object' || candidate === null) {
    return false;
  }
  const record = candidate as Record<string, unknown>;
  const required = ['capabilities', 'startCustomerSession', 'startMerchantSession', 'subscribe'];
  return required.every(name => typeof record[name] === 'function');
}

function describeAdapter(adapter: DeceiptNative): string {
  return adapter instanceof InMemoryDeceiptNative
    ? 'Mock adapter (no native module registered — this build cannot use Bluetooth)'
    : 'Native adapter (Bluetooth available)';
}

export const APP_DEMO_NOW_UNIX = DEMO_NOW_UNIX;
export {colors};
