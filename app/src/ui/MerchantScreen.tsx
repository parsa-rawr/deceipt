/**
 * Merchant mode.
 *
 * The flow is the A2 §7 demo path built on `checkout/merchantFlow.ts`:
 * build a synthetic receipt, sign it once over exact canonical bytes, derive the
 * binding bytes, mint the QR, advertise, and serve the transfer.
 *
 * Two things this screen exists to make driveable without a camera:
 *  * the QR payload is shown as selectable TEXT, so an operator (or an agent
 *    driving the phone) can read it and type it into the customer phone;
 *  * every state change and every typed error is visible as text.
 */

import React, {useCallback, useEffect, useState} from 'react';
import {ScrollView, Text, View} from 'react-native';
import type {
  DeceiptEvent,
  DeceiptNative,
  MerchantKeyStatus,
  SessionSnapshot,
} from '../native/DeceiptNative';
import {DeceiptBridgeError} from '../native/bridgeError';
import {ProtocolError, type ProtocolErrorName} from '../protocol/errors';
import {prepareMerchantOffer, startMerchantServing, assertMerchantReady, type PreparedMerchantOffer} from '../checkout/merchantFlow';
import {buildDemoReceipt} from '../demo/demoReceipt';
import {ensureDemoMerchant} from '../demo/merchantProvision';
import {Card, Field, ActionButton, StatusPill, colors, formatMoney, styles} from './primitives';

export interface MerchantScreenProps {
  native: DeceiptNative;
  /** Injected clock so tests and the demo can pin the verification instant. */
  now: () => number;
}

type MerchantPhase = 'idle' | 'preparing' | 'advertising' | 'transferring' | 'complete' | 'failed';

export function MerchantScreen({native, now}: MerchantScreenProps): React.JSX.Element {
  const [phase, setPhase] = useState<MerchantPhase>('idle');
  const [keyStatus, setKeyStatus] = useState<MerchantKeyStatus | null>(null);
  const [provisionNote, setProvisionNote] = useState<string | null>(null);
  const [provisioning, setProvisioning] = useState(false);
  const [prepared, setPrepared] = useState<PreparedMerchantOffer | null>(null);
  const [sessionHandle, setSessionHandle] = useState<string | null>(null);
  const [snapshot, setSnapshot] = useState<SessionSnapshot | null>(null);
  const [log, setLog] = useState<string[]>([]);
  const [failure, setFailure] = useState<{name: ProtocolErrorName | null; message: string} | null>(null);
  const [sessionType, setSessionType] = useState<string>('none');

  /**
   * Dev-only bootstrap. Called before the first prepare so the demo can render a
   * code on a fresh install; it is a no-op on an adapter that forbids test
   * provisioning, and the reason is surfaced rather than swallowed.
   */
  const onProvision = useCallback(async () => {
    setProvisioning(true);
    setProvisionNote(null);
    try {
      const outcome = await ensureDemoMerchant(native);
      if (outcome.ok) {
        setKeyStatus(outcome.status ?? (await native.merchantKeyStatus()));
        setProvisionNote(
          outcome.alreadyProvisioned
            ? 'already provisioned'
            : 'test merchant key and credential imported (dev build only)',
        );
      } else {
        setProvisionNote(outcome.reason ?? 'provisioning unavailable');
      }
    } catch (error) {
      setProvisionNote(describe(error));
    } finally {
      setProvisioning(false);
    }
  }, [native]);

  const append = useCallback((line: string) => {
    setLog(current => (current[current.length - 1] === line ? current : [...current, line].slice(-40)));
  }, []);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const status = await native.merchantKeyStatus();
        if (!cancelled) {
          setKeyStatus(status);
        }
      } catch (error) {
        if (!cancelled) {
          append(`key status unavailable: ${describe(error)}`);
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [native, append]);

  useEffect(() => {
    const unsubscribe = native.subscribe((events: DeceiptEvent[]) => {
      for (const event of events) {
        append(event.type);
        if (event.type === 'session_keys_derived') {
          setSessionType('SessionKeysOnly (no transfer yet)');
        } else if (event.type === 'session_unverified_peer') {
          setSessionType('SessionUnverifiedPeer (unpinned issuer)');
        } else if (event.type === 'session_authenticated') {
          setSessionType('SessionAuthenticated');
        } else if (event.type === 'offer_accepted') {
          setPhase('transferring');
        } else if (event.type === 'transfer_complete') {
          setPhase('complete');
        } else if (event.type === 'receipt_ack_sent') {
          append(`receipt acknowledged: outcome ${event.outcomeCode}`);
        } else if (event.type === 'error') {
          setFailure({name: event.error.name, message: describeBridge(event.error.name, event.error.detail)});
          setPhase('failed');
        }
      }
    });
    return unsubscribe;
  }, [native, append]);

  const onPrepare = useCallback(async () => {
    setFailure(null);
    setPhase('preparing');
    try {
      const status = await assertMerchantReady(native);
      setKeyStatus(status);
      const merchantIdHex = status.merchantIdHex ?? '';
      const credentialB64 = status.credentialB64 ?? '';
      if (merchantIdHex.length !== 32 || credentialB64.length === 0) {
        throw new ProtocolError('CAPABILITY_UNAVAILABLE', 'the provisioned key has no merchant id or credential');
      }
      const receipt = buildDemoReceipt({
        merchantId: hexToBytes(merchantIdHex),
        credentialBytes: base64ToBytes(credentialB64),
      });
      const next = await prepareMerchantOffer(native, receipt, now());
      setPrepared(next);
      append(`prepared binding for ${next.receiptIdHex.slice(0, 8)}…`);
    } catch (error) {
      setFailure({name: errorName(error), message: describe(error)});
      setPhase('failed');
    }
  }, [native, now, append]);

  const onAdvertise = useCallback(async () => {
    if (prepared === null) {
      return;
    }
    setFailure(null);
    try {
      const serving = await startMerchantServing(native, prepared);
      setSessionHandle(serving.sessionHandle);
      setSnapshot(serving.snapshot);
      setPhase('advertising');
      append('advertising the Deceipt service UUID');
    } catch (error) {
      setFailure({name: errorName(error), message: describe(error)});
      setPhase('failed');
    }
  }, [native, prepared, append]);

  const onStop = useCallback(async () => {
    if (sessionHandle !== null) {
      try {
        await native.stopSession(sessionHandle);
      } catch {
        // Teardown is best effort; the screen still returns to idle.
      }
    }
    setSessionHandle(null);
    setSnapshot(null);
    setPhase('idle');
    append('session stopped');
  }, [native, sessionHandle, append]);

  return (
    <ScrollView contentContainerStyle={styles.screen} testID="merchant-screen">
      <Text style={styles.title}>Merchant</Text>
      <Text style={styles.subtitle}>
        Signs one synthetic receipt over exact canonical bytes, then serves it. Nothing in the QR is a receipt.
      </Text>

      <Card testID="merchant-key-card">
        <Text style={styles.sectionTitle}>Signing key</Text>
        {keyStatus === null ? (
          <Text style={styles.label}>checking…</Text>
        ) : keyStatus.provisioned ? (
          <>
            <View style={styles.row}>
              <Text style={styles.label}>device key id</Text>
              <Text style={styles.mono} testID="merchant-device-key-id">
                {(keyStatus.identity?.deviceKeyIdHex ?? '').slice(0, 8)}…
              </Text>
            </View>
            <Field label="storage" value={keyStatus.identity?.storage ?? 'unknown'} />
          </>
        ) : (
          <>
            <Text style={styles.error} testID="merchant-key-missing">
              No signing key is provisioned on this build, so merchant mode cannot sign a receipt.
            </Text>
            <ActionButton
              label="Import test merchant key"
              onPress={() => void onProvision()}
              testID="provision-test-merchant"
              accessibilityLabel="provision-test-merchant"
              variant="secondary"
              disabled={provisioning}
            />
          </>
        )}
        {provisionNote !== null ? (
          <Text style={styles.label} testID="provision-note">
            {provisionNote}
          </Text>
        ) : null}
      </Card>

      <Card>
        <Text style={styles.sectionTitle}>Session</Text>
        <StatusPill
          text={phase}
          color={
            phase === 'failed'
              ? colors.rejected
              : phase === 'complete'
                ? colors.trusted
                : phase === 'idle'
                  ? colors.neutral
                  : colors.accent
          }
          testID="merchant-phase"
        />
        <Field label="session type" value={sessionType} />
        {snapshot !== null ? <Field label="state" value={snapshot.state} /> : null}
        {failure !== null ? (
          <Text style={styles.error} testID="merchant-error">
            {failure.name ?? 'ERROR'}: {failure.message}
          </Text>
        ) : null}
      </Card>

      {prepared !== null ? (
        <Card testID="merchant-qr-card">
          <Text style={styles.sectionTitle}>Checkout code</Text>
          <Text style={styles.label}>
            Read this out or copy it into the customer phone. It carries the session id, the binding token and the offer
            hash — never the receipt, the amount or the merchant name.
          </Text>
          <Text style={styles.notice}>
            Shown as text, not as a QR image: rendering one would need a new native dependency, and the customer screen
            takes the code by paste. Say the word if you want the image instead.
          </Text>
          <View style={styles.qr}>
            <Text selectable testID="qr-payload-text" style={styles.qrText}>
              {prepared.qr.qrPayload}
            </Text>
          </View>
          <Field label="receipt total" value={formatMoney(prepared.receipt.totals.totalMinor, prepared.receipt.currency)} />
          <Field label="expires" value={String(prepared.qr.expiresAtUnix)} />
        </Card>
      ) : null}

      <ActionButton label="Prepare checkout" onPress={onPrepare} testID="prepare-checkout" accessibilityLabel="prepare-checkout" />
      <ActionButton
        label="Start advertising"
        onPress={onAdvertise}
        testID="start-advertising"
        accessibilityLabel="start-advertising"
        variant="secondary"
        disabled={prepared === null || phase === 'advertising'}
      />
      <ActionButton
        label="Stop session"
        onPress={onStop}
        testID="stop-session"
        accessibilityLabel="stop-session"
        variant="destructive"
        disabled={sessionHandle === null}
      />

      <Card testID="merchant-log-card">
        <Text style={styles.sectionTitle}>Events</Text>
        {log.length === 0 ? (
          <Text style={styles.label}>nothing yet</Text>
        ) : (
          log.map((line, index) => (
            <Text key={`${line}-${index}`} style={styles.label}>
              {line}
            </Text>
          ))
        )}
      </Card>
    </ScrollView>
  );
}

function describe(error: unknown): string {
  if (error instanceof ProtocolError) {
    return error.message;
  }
  if (error instanceof DeceiptBridgeError) {
    return `${error.bridge.name}: ${error.bridge.detail ?? 'bridge failure'}`;
  }
  return error instanceof Error ? error.message : 'unknown failure';
}

function errorName(error: unknown): ProtocolErrorName | null {
  if (error instanceof ProtocolError) {
    return error.name;
  }
  if (error instanceof DeceiptBridgeError) {
    return error.bridge.name;
  }
  return null;
}

function describeBridge(name: string, detail?: string): string {
  return detail === undefined ? name : `${name}: ${detail}`;
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(Math.floor(hex.length / 2));
  for (let index = 0; index < out.length; index += 1) {
    out[index] = parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return out;
}

function base64ToBytes(input: string): Uint8Array {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const padded = input.length % 4 === 0 ? input : input + '='.repeat(4 - (input.length % 4));
  const out: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (const character of padded) {
    if (character === '=') {
      break;
    }
    buffer = (buffer << 6) | alphabet.indexOf(character);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push((buffer >> bits) & 0xff);
    }
  }
  return new Uint8Array(out);
}
