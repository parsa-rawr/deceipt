/**
 * Camera QR scanning for the checkout code.
 *
 * A2's frozen flow is a camera scan at the terminal, and the user authorized the
 * camera on both phones, so this is the primary selection act. The text field
 * stays as a documented fallback for a missing camera, a denied permission or an
 * automated driver — never as the only path.
 *
 * The decoder is `react-native-camera-kit`'s native barcode scanner (Android ML
 * Kit / iOS AVFoundation): a maintained library with zero runtime dependencies
 * beyond react and react-native. Nothing about the scanned string is interpreted
 * here; the payload is handed to the same `startCustomerSession` selection the
 * text field uses, so the parse/validation path is identical either way.
 */

import React, {useCallback, useRef} from 'react';
import {StyleSheet, Text, View} from 'react-native';
import {Camera, CameraType} from 'react-native-camera-kit';
import {ActionButton, colors, styles} from './primitives';

export interface QrScannerProps {
  /** The exact scanned string. Called once per distinct value. */
  onScan: (payload: string) => void;
  /** Invoked when the operator dismisses the scanner. */
  onCancel: () => void;
  /** Set when the camera permission is known to be unavailable. */
  permissionDenied?: boolean;
}

export function QrScanner({onScan, onCancel, permissionDenied = false}: QrScannerProps): React.JSX.Element {
  // A camera fires `onReadCode` repeatedly for the same code; the first read of
  // a given value is the selection act, and the rest are noise.
  const lastValue = useRef<string | null>(null);

  const handleRead = useCallback(
    (event: {nativeEvent: {codeStringValue?: string}}) => {
      const value = event.nativeEvent.codeStringValue;
      if (typeof value !== 'string' || value.length === 0) {
        return;
      }
      if (lastValue.current === value) {
        return;
      }
      lastValue.current = value;
      onScan(value);
    },
    [onScan],
  );

  if (permissionDenied) {
    return (
      <View style={styles.card} testID="scanner-permission-denied">
        <Text style={styles.error}>Scanning needs camera access. Grant it in Settings, then try again.</Text>
        <ActionButton label="Enter the code manually" onPress={onCancel} testID="scanner-to-manual" accessibilityLabel="scanner-to-manual" variant="secondary" />
      </View>
    );
  }

  return (
    <View style={local.container} testID="qr-scanner">
      <Camera
        style={local.camera}
        cameraType={CameraType.Back}
        scanBarcode
        showFrame
        onReadCode={handleRead}
        // Android reports a camera failure through onError rather than throwing.
        onError={() => undefined}
      />
      <View style={local.overlay}>
        <Text style={local.hint} testID="scanner-hint">
          Point the camera at the checkout code on the terminal.
        </Text>
        <ActionButton
          label="Enter the code manually instead"
          onPress={onCancel}
          testID="scanner-to-manual"
          accessibilityLabel="scanner-to-manual"
          variant="secondary"
        />
      </View>
    </View>
  );
}

const local = StyleSheet.create({
  container: {height: 320, marginBottom: 12, borderRadius: 10, overflow: 'hidden', backgroundColor: '#000000'},
  camera: {flex: 1},
  overlay: {position: 'absolute', left: 0, right: 0, bottom: 0, padding: 10, backgroundColor: 'rgba(11,16,32,0.85)'},
  hint: {color: colors.text, fontSize: 13, marginBottom: 8, textAlign: 'center'},
});
