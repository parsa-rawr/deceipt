/**
 * Customer mode.
 *
 * The QR payload is typed or pasted into a TextInput — deliberately, not by
 * camera: the PoC is driven by an operator (or an agent through accessibility),
 * and requiring a camera would make the two-phone demo undriveable. The scan is
 * still the only selection act, and it is the same string the merchant screen
 * shows.
 *
 * Everything the customer must be able to judge is text: the offered merchant
 * and total, the verification outcome in plain language, and the §5.3
 * sub-states individually.
 */

import React, {useCallback, useEffect, useMemo, useState} from 'react';
import {ScrollView, Text, TextInput, View} from 'react-native';
import type {DeceiptEvent, DeceiptNative, OfferMetadata, PermissionReport, TrustAnchor} from '../native/DeceiptNative';
import {DeceiptBridgeError} from '../native/bridgeError';
import {ProtocolError, type ProtocolErrorName} from '../protocol/errors';
import {verifyReceipt, REVOCATION_UNSUPPORTED_REASON, toStoredVerification, type VerificationSubStates} from '../protocol/verification';
import {base64Decode, base64Encode, hexEncode} from '../protocol/bytes';
import {CheckoutController} from '../checkout/controller';
import {
  failureMessageFor,
  recoveryActionFor,
  type CheckoutModel,
  type SavedReceiptView,
} from '../checkout/machine';
import {ReceiptStore} from '../storage/receiptStore';
import {
  ActionButton,
  Card,
  Field,
  StatusPill,
  SubStateTable,
  colors,
  formatMoney,
  formatWhen,
  styles,
  verificationStatusCopy,
} from './primitives';

export interface CustomerScreenProps {
  native: DeceiptNative;
  store: ReceiptStore;
  anchors: TrustAnchor[];
  now: () => number;
  /** Injected by tests; defaults to a fresh controller over the same ports. */
  controllerFactory?: (options: {
    native: DeceiptNative;
    store: ReceiptStore;
    anchors: TrustAnchor[];
    now: () => number;
    onChange: (model: CheckoutModel) => void;
  }) => Pick<CheckoutController, 'start' | 'dispose' | 'onQRScanned' | 'onAcceptOffer' | 'onDeclineOffer' | 'onCancel' | 'reset' | 'onOpenScanner'>;
}

export function CustomerScreen({native, store, anchors, now, controllerFactory}: CustomerScreenProps): React.JSX.Element {
  const [model, setModel] = useState<CheckoutModel | null>(null);
  const [qrText, setQrText] = useState('');
  const [permissions, setPermissions] = useState<PermissionReport | null>(null);
  const [history, setHistory] = useState<SavedReceiptView[]>([]);
  const [log, setLog] = useState<string[]>([]);

  const append = useCallback((line: string) => {
    setLog(current => (current[current.length - 1] === line ? current : [...current, line].slice(-40)));
  }, []);

  const controller = useMemo(() => {
    const factory =
      controllerFactory ??
      ((options: {
        native: DeceiptNative;
        store: ReceiptStore;
        anchors: TrustAnchor[];
        now: () => number;
        onChange: (next: CheckoutModel) => void;
      }) => new CheckoutController(options));
    return factory({native, store, anchors, now, onChange: setModel});
  }, [native, store, anchors, now, controllerFactory]);

  useEffect(() => {
    controller.start();
    void (async () => {
      try {
        setPermissions(await native.permissionState());
      } catch (error) {
        append(`permissions unavailable: ${describe(error)}`);
      }
      await refreshHistory();
    })();
    return () => {
      void controller.dispose();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [controller]);

  useEffect(() => {
    const unsubscribe = native.subscribe((events: DeceiptEvent[]) => {
      for (const event of events) {
        append(event.type);
      }
    });
    return unsubscribe;
  }, [native, append]);

  const refreshHistory = useCallback(async () => {
    try {
      const rows = await store.list();
      setHistory(
        rows.map(row => ({
          receiptIdHex: row.receiptIdHex,
          merchantDisplayName: row.merchantDisplayName,
          totalMinor: row.totalMinor,
          currency: row.currency,
          issuedAt: row.issuedAt,
          outcome: row.verification.outcome,
          trustLabel: row.trustLabel,
          alreadyImported: false,
        })),
      );
    } catch (error) {
      append(`history unavailable: ${describe(error)}`);
    }
  }, [store, append]);

  // The history is refreshed when the model reports a stored outcome.
  useEffect(() => {
    if (model?.state === 'saved') {
      void refreshHistory();
    }
  }, [model?.state, refreshHistory]);

  const onScan = useCallback(async () => {
    await controller.onQRScanned(qrText.trim());
  }, [controller, qrText]);

  const onRequestPermissions = useCallback(async () => {
    try {
      const next = await native.requestPermissions(['bluetooth', 'camera']);
      setPermissions(next);
      append(`bluetooth: ${next.bluetooth}, camera: ${next.camera}`);
    } catch (error) {
      append(`permission request failed: ${describe(error)}`);
    }
  }, [native, append]);

  const onRetry = useCallback(() => {
    controller.reset();
    setModel(current => current);
    append('reset for retry');
  }, [controller, append]);

  const state = model?.state ?? 'ready';
  const saved = model?.saved ?? null;
  const offer = model?.offer ?? null;
  const failure = model?.failure ?? null;

  return (
    <ScrollView contentContainerStyle={styles.screen} testID="customer-screen">
      <Text style={styles.title}>Customer</Text>
      <Text style={styles.subtitle}>
        Paste the checkout code the merchant shows. The receipt arrives over Bluetooth; the code names the transaction.
      </Text>

      {permissions !== null ? (
        <Card testID="permission-card">
          <Text style={styles.sectionTitle}>Permissions</Text>
          <Field label="bluetooth" value={`${permissions.bluetooth} (${permissions.bluetoothState})`} />
          <Field label="camera" value={permissions.camera} />
          {permissions.bluetooth !== 'granted' || permissions.bluetoothState !== 'on' ? (
            <Text style={styles.error} testID="permission-warning">
              {permissions.bluetoothState !== 'on'
                ? 'Bluetooth is off. Turn it on to receive a receipt.'
                : 'Deceipt needs Bluetooth to receive your receipt.'}
            </Text>
          ) : null}
          <ActionButton
            label="Grant permissions"
            onPress={onRequestPermissions}
            testID="request-permissions"
            accessibilityLabel="request-permissions"
            variant="secondary"
          />
        </Card>
      ) : null}

      <Card>
        <Text style={styles.sectionTitle}>Checkout code</Text>
        <TextInput
          testID="qr-payload-input"
          accessibilityLabel="qr-payload-input"
          style={styles.input}
          multiline
          autoCapitalize="none"
          autoCorrect={false}
          placeholder="deceipt1:…"
          placeholderTextColor={colors.textMuted}
          value={qrText}
          onChangeText={setQrText}
        />
        <ActionButton label="Use this code" onPress={onScan} testID="scan-qr" accessibilityLabel="scan-qr" disabled={qrText.trim().length === 0} />
      </Card>

      <Card>
        <Text style={styles.sectionTitle}>Status</Text>
        <StatusPill
          text={state}
          color={
            state === 'saved'
              ? colors.trusted
              : state === 'recoverable_failure'
                ? colors.rejected
                : state === 'verifying'
                  ? colors.unknown
                  : colors.accent
          }
          testID="checkout-state"
        />
        {model?.receiptUntrusted === true ? (
          <Text style={styles.notice} testID="receipt-untrusted">
            The receipt arrived and decrypted. It is not trusted yet — its signature and its merchant are still being
            checked.
          </Text>
        ) : null}
        {model !== null && model.progress !== null ? (
          <Field label="frames" value={`${model.progress.highestContiguousSequence + 1} / ${model.progress.frameCount}`} />
        ) : null}
        {model !== null ? <Field label="discovered terminals" value={String(model.candidates.length)} /> : null}
        {failure !== null ? (
          <>
            <Text style={styles.error} testID="checkout-error">
              {failure.message}
            </Text>
            <Field label="typed error" value={failure.error?.name ?? 'USER_CANCELLED'} />
            <Field label="recovery" value={recoveryActionFor(failure.error?.name ?? null)} />
          </>
        ) : null}
      </Card>

      {offer !== null ? (
        <Card testID="offer-card">
          <Text style={styles.sectionTitle}>Offered transaction</Text>
          <Text style={styles.notice}>
            These are the merchant's claims. They are shown before verification and are not trusted yet.
          </Text>
          <Field label="merchant reference" value={offer.merchantReference} />
          <Field label="total" value={formatMoney(offer.totalAmountMinor, offer.currency)} />
          <Field label="issued" value={formatWhen(offer.issuedAt)} />
          <Field label="session type" value={model?.peer === null || model?.peer === undefined ? 'none' : model.peer.kind} />
          <ActionButton
            label="Accept this transaction"
            onPress={() => void controller.onAcceptOffer()}
            testID="accept-offer"
            accessibilityLabel="accept-offer"
            disabled={model?.peer === null || model?.peer === undefined}
          />
          <ActionButton
            label="Decline"
            onPress={() => void controller.onDeclineOffer()}
            testID="decline-offer"
            accessibilityLabel="decline-offer"
            variant="secondary"
          />
        </Card>
      ) : null}

      {saved !== null ? (
        <Card testID="receipt-result">
          <Text style={styles.sectionTitle}>Receipt</Text>
          <StatusPill
            text={verificationStatusCopy(saved.outcome).label}
            color={verificationStatusCopy(saved.outcome).color}
            testID="receipt-verification-pill"
          />
          <Text style={[styles.value, {color: verificationStatusCopy(saved.outcome).color}]} testID="receipt-status-text">
            {verificationStatusCopy(saved.outcome).text}
          </Text>
          <Field label="merchant" value={saved.merchantDisplayName} />
          <Field label="total" value={formatMoney(saved.totalMinor, saved.currency)} />
          <Field label="issued" value={formatWhen(saved.issuedAt)} />
          {saved.alreadyImported ? <Text style={styles.notice}>This receipt was already saved; no duplicate was added.</Text> : null}
        </Card>
      ) : null}

      {model !== null && model.state === 'recoverable_failure' ? (
        <>
          <ActionButton label="Try again" onPress={onRetry} testID="retry" accessibilityLabel="retry" />
          <ActionButton
            label="Cancel"
            onPress={() => void controller.onCancel()}
            testID="cancel"
            accessibilityLabel="cancel"
            variant="destructive"
          />
        </>
      ) : null}

      <Card testID="history-card">
        <Text style={styles.sectionTitle}>Saved receipts</Text>
        {history.length === 0 ? (
          <Text style={styles.label} testID="history-empty">
            none yet
          </Text>
        ) : (
          history.map((row, index) => (
            <View key={row.receiptIdHex} testID={`history-row-${index}`} style={styles.section}>
              <View style={styles.row}>
                <Text style={styles.value}>{row.merchantDisplayName}</Text>
                <Text style={styles.value}>{formatMoney(row.totalMinor, row.currency)}</Text>
              </View>
              <View style={styles.row}>
                <Text style={styles.label}>{formatWhen(row.issuedAt)}</Text>
                <Text style={[styles.label, {color: verificationStatusCopy(row.outcome).color}]}>
                  {verificationStatusCopy(row.outcome).label}
                </Text>
              </View>
            </View>
          ))
        )}
      </Card>

      <Card testID="customer-log-card">
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

/**
 * A self-contained verifier for a receipt already in hand. Exists so a tester
 * can re-check a stored receipt against the pinned anchors without re-running a
 * transfer; it uses the same `verifyReceipt` the controller does.
 */
export async function verifyStoredReceipt(
  coseSign1B64: string,
  anchors: TrustAnchor[],
  nowUnix: number,
): Promise<{outcome: string; subStates: VerificationSubStates; errorName: ProtocolErrorName | null}> {
  const result = await verifyReceipt({
    coseSign1Bytes: base64Decode(coseSign1B64),
    anchors,
    nowUnix,
  });
  const stored = toStoredVerification(result, nowUnix);
  return {outcome: stored.outcome, subStates: stored.subStates, errorName: stored.errorName as ProtocolErrorName | null};
}

export function describeError(error: unknown): string {
  return describe(error);
}

function describe(error: unknown): string {
  if (error instanceof ProtocolError) {
    return `${error.name}: ${error.message}`;
  }
  if (error instanceof DeceiptBridgeError) {
    return `${error.bridge.name}: ${error.bridge.detail ?? 'bridge failure'}`;
  }
  return error instanceof Error ? error.message : 'unknown failure';
}

/** Re-exported for the app shell so it does not import protocol modules. */
export {failureMessageFor, REVOCATION_UNSUPPORTED_REASON, base64Encode, hexEncode, SubStateTable};
