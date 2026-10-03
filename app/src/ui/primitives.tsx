/**
 * Shared UI: presentation primitives, the design tokens and the plain-language
 * copy rules of docs/flows/transaction-binding-and-checkout-v1.md §8.
 *
 * The copy rules are enforced here rather than by review:
 *  * a verification outcome is rendered through `verificationStatusCopy`, whose
 *    three branches are visually distinct and never conflate "delivered" with
 *    "verified";
 *  * crypto internals (key ids, signature bytes, nonces, transcript hashes,
 *    session ids, the SBT) have no rendering path at all.
 */

import React from 'react';
import {StyleSheet, Text, TouchableOpacity, View} from 'react-native';
import type {VerificationSubStates} from '../protocol/verification';
import type {PolicyOutcome} from '../protocol/errors';

export const colors = {
  background: '#0b1020',
  surface: '#151b30',
  surfaceAlt: '#1d2540',
  border: '#2b3454',
  text: '#eef2ff',
  textMuted: '#9aa6c8',
  accent: '#5b8def',
  trusted: '#3fb950',
  unknown: '#d29922',
  rejected: '#f85149',
  neutral: '#8b949e',
} as const;

export const styles = StyleSheet.create({
  screen: {flex: 1, backgroundColor: colors.background, padding: 16},
  title: {color: colors.text, fontSize: 22, fontWeight: '700', marginBottom: 4},
  subtitle: {color: colors.textMuted, fontSize: 13, marginBottom: 12},
  section: {marginBottom: 14},
  sectionTitle: {color: colors.text, fontSize: 15, fontWeight: '600', marginBottom: 6},
  card: {
    backgroundColor: colors.surface,
    borderColor: colors.border,
    borderWidth: 1,
    borderRadius: 10,
    padding: 12,
    marginBottom: 10,
  },
  row: {flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between'},
  label: {color: colors.textMuted, fontSize: 12},
  value: {color: colors.text, fontSize: 14},
  mono: {color: colors.text, fontFamily: 'monospace', fontSize: 12},
  button: {
    backgroundColor: colors.accent,
    borderRadius: 8,
    paddingVertical: 12,
    paddingHorizontal: 16,
    marginBottom: 8,
  },
  buttonSecondary: {
    backgroundColor: colors.surfaceAlt,
    borderColor: colors.border,
    borderWidth: 1,
  },
  buttonDestructive: {backgroundColor: colors.rejected},
  buttonText: {color: colors.text, fontSize: 15, fontWeight: '600', textAlign: 'center'},
  input: {
    backgroundColor: colors.surfaceAlt,
    borderColor: colors.border,
    borderWidth: 1,
    borderRadius: 8,
    color: colors.text,
    padding: 10,
    fontSize: 13,
    minHeight: 44,
  },
  pill: {
    borderRadius: 999,
    paddingVertical: 4,
    paddingHorizontal: 10,
    alignSelf: 'flex-start',
  },
  pillText: {fontSize: 12, fontWeight: '700'},
  qr: {
    backgroundColor: '#ffffff',
    padding: 12,
    borderRadius: 8,
    marginBottom: 8,
  },
  qrText: {color: '#000000', fontFamily: 'monospace', fontSize: 11},
  notice: {color: colors.textMuted, fontSize: 12, fontStyle: 'italic'},
  error: {color: colors.rejected, fontSize: 13},
});

export function Card({children, testID}: {children: React.ReactNode; testID?: string}): React.JSX.Element {
  return (
    <View style={styles.card} testID={testID}>
      {children}
    </View>
  );
}

export function Field({label, value}: {label: string; value: string}): React.JSX.Element {
  return (
    <View style={styles.row}>
      <Text style={styles.label}>{label}</Text>
      <Text style={styles.value}>{value}</Text>
    </View>
  );
}

export function ActionButton({
  label,
  onPress,
  testID,
  accessibilityLabel,
  variant = 'primary',
  disabled = false,
}: {
  label: string;
  onPress: () => void;
  testID: string;
  accessibilityLabel?: string;
  variant?: 'primary' | 'secondary' | 'destructive';
  disabled?: boolean;
}): React.JSX.Element {
  const variantStyle =
    variant === 'secondary' ? styles.buttonSecondary : variant === 'destructive' ? styles.buttonDestructive : undefined;
  return (
    <TouchableOpacity
      accessibilityRole="button"
      accessibilityLabel={accessibilityLabel ?? label}
      accessibilityState={{disabled}}
      testID={testID}
      disabled={disabled}
      onPress={onPress}
      style={[styles.button, variantStyle, disabled ? styles.buttonSecondary : undefined]}>
      <Text style={styles.buttonText}>{label}</Text>
    </TouchableOpacity>
  );
}

/**
 * The plain-language verification status of A2 §8. The three outcomes map to
 * three visibly different affordances, and `unknown_key` never borrows the
 * trusted presentation.
 */
export function verificationStatusCopy(outcome: PolicyOutcome): {text: string; color: string; label: string} {
  switch (outcome) {
    case 'TRUSTED':
      return {text: 'Verified — issued by a recognized Deceipt merchant', color: colors.trusted, label: 'verified'};
    case 'UNVERIFIED_UNKNOWN_ISSUER':
      return {text: 'Not verified — signing key is not recognized', color: colors.unknown, label: 'unverified'};
    case 'ALREADY_IMPORTED_IDENTICAL':
      return {text: 'Already saved — this receipt is identical to one you have', color: colors.neutral, label: 'already-saved'};
    case 'PENDING':
      return {text: 'Checking…', color: colors.textMuted, label: 'pending'};
    default:
      return {text: 'Rejected — the receipt did not match its signature or its merchant', color: colors.rejected, label: 'rejected'};
  }
}

export function StatusPill({text, color, testID}: {text: string; color: string; testID: string}): React.JSX.Element {
  return (
    <View style={[styles.pill, {backgroundColor: colors.surfaceAlt, borderColor: color, borderWidth: 1}]} testID={testID}>
      <Text style={[styles.pillText, {color}]}>{text}</Text>
    </View>
  );
}

/**
 * The §5.3 sub-states, rendered one per row. They are never collapsed: the
 * receipt can be rejected with a valid signature, or unknown-key with every
 * other check passing, and the UI has to be able to say so.
 */
export function SubStateTable({subStates, testID}: {subStates: VerificationSubStates; testID: string}): React.JSX.Element {
  const rows: Array<[string, boolean, string]> = [
    ['Signature valid', subStates.signatureValid, colors.trusted],
    ['Signing key authorized', subStates.keyAuthorized, colors.trusted],
    ['Credential temporally acceptable', subStates.credentialTemporallyAcceptable, colors.trusted],
    ['Revocation known', subStates.revocationKnown, colors.neutral],
    ['Semantically valid', subStates.semanticallyValid, colors.trusted],
    ['Unique locally', subStates.uniqueLocally, colors.trusted],
  ];
  return (
    <View testID={testID}>
      {rows.map(([label, value, trueColor]) => (
        <View style={styles.row} key={label}>
          <Text style={styles.label}>{label}</Text>
          <Text style={[styles.value, {color: value ? trueColor : colors.rejected}]}>
            {value ? 'yes' : 'no'}
          </Text>
        </View>
      ))}
      <Text style={styles.notice}>
        Revocation is not evaluated in this proof of concept: no revocation distribution exists, so a key revoked in
        production is indistinguishable here.
      </Text>
    </View>
  );
}

export function formatMoney(amountMinor: number, currency: string): string {
  const exponent = CURRENCY_EXPONENTS[currency];
  if (exponent === undefined) {
    return `${currency} ${amountMinor} minor units`;
  }
  const negative = amountMinor < 0;
  const magnitude = Math.abs(amountMinor);
  const divisor = 10 ** exponent;
  const whole = Math.floor(magnitude / divisor);
  const fraction = magnitude % divisor;
  const fractionText = exponent === 0 ? '' : `.${String(fraction).padStart(exponent, '0')}`;
  return `${negative ? '-' : ''}${currency} ${whole}${fractionText}`;
}

/**
 * Minor-unit exponents for the v1 table's currencies. Kept local to the UI so
 * the display layer does not import the protocol constants for a formatting
 * concern; the authoritative table is `protocol/schema/bounds-v1.json`.
 */
const CURRENCY_EXPONENTS: Readonly<Record<string, number>> = {
  CAD: 2, USD: 2, EUR: 2, GBP: 2, AUD: 2, NZD: 2, CHF: 2, MXN: 2, BRL: 2,
  SGD: 2, HKD: 2, SEK: 2, NOK: 2, DKK: 2, PLN: 2, CZK: 2, TRY: 2, ZAR: 2,
  INR: 2, CNY: 2, HUF: 2, JPY: 0, KRW: 0, VND: 0, CLP: 0, ISK: 0,
  KWD: 3, BHD: 3, OMR: 3, JOD: 3, TND: 3, IQD: 3, LYD: 3,
};

export function formatWhen(unixSeconds: number): string {
  if (unixSeconds <= 0) {
    return 'unknown';
  }
  return new Date(unixSeconds * 1000).toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC');
}
