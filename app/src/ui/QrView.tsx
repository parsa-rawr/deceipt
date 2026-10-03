/**
 * A scannable QR code, rendered with plain React Native views.
 *
 * Why not react-native-svg: it is a native dependency, and a QR is a grid of
 * black and white squares — `qrcode-generator` (pure JS, zero runtime
 * dependencies) produces the module matrix and this renders it. No native code,
 * no new platform build.
 *
 * The encoder is given the exact payload string; nothing about the payload is
 * interpreted or rewritten here (A2 §3.3 fixes `deceipt1:` + base64url CBOR).
 */

import React, {useMemo} from 'react';
import {StyleSheet, View} from 'react-native';
import qrcode from 'qrcode-generator';

export interface QrViewProps {
  /** The exact string to encode. */
  value: string;
  /** Rendered size in logical pixels. */
  size: number;
  /** Error-correction level; 'M' is the usual trade-off for a screen scan. */
  level?: 'L' | 'M' | 'Q' | 'H';
  testID?: string;
  accessibilityLabel?: string;
}

const QUIET_ZONE_MODULES = 4;

export function QrView({value, size, level = 'M', testID, accessibilityLabel}: QrViewProps): React.JSX.Element {
  const matrix = useMemo(() => buildMatrix(value, level), [value, level]);
  const total = matrix.length + QUIET_ZONE_MODULES * 2;
  const moduleSize = size / total;
  const rows: React.JSX.Element[] = [];
  for (let row = 0; row < total; row += 1) {
    const cells: React.JSX.Element[] = [];
    for (let column = 0; column < total; column += 1) {
      const isQuietZone =
        row < QUIET_ZONE_MODULES ||
        column < QUIET_ZONE_MODULES ||
        row >= total - QUIET_ZONE_MODULES ||
        column >= total - QUIET_ZONE_MODULES;
      const dark = !isQuietZone && matrix[row - QUIET_ZONE_MODULES][column - QUIET_ZONE_MODULES];
      cells.push(
        <View
          key={column}
          style={{
            width: moduleSize,
            height: moduleSize,
            backgroundColor: dark ? '#000000' : '#ffffff',
          }}
        />,
      );
    }
    rows.push(
      <View key={row} style={styles.row}>
        {cells}
      </View>,
    );
  }
  return (
    <View
      testID={testID}
      accessibilityRole="image"
      accessibilityLabel={accessibilityLabel ?? 'QR code for the checkout'}
      style={[styles.canvas, {width: size, height: size}]}>
      {rows}
    </View>
  );
}

/** The QR module matrix. Throws when the payload cannot be encoded. */
function buildMatrix(value: string, level: 'L' | 'M' | 'Q' | 'H'): boolean[][] {
  // Type 0 = auto-select the smallest version that fits.
  const qr = qrcode(0, level);
  qr.addData(value);
  qr.make();
  const count = qr.getModuleCount();
  const matrix: boolean[][] = [];
  for (let row = 0; row < count; row += 1) {
    const cells: boolean[] = [];
    for (let column = 0; column < count; column += 1) {
      cells.push(qr.isDark(row, column));
    }
    matrix.push(cells);
  }
  return matrix;
}

const styles = StyleSheet.create({
  canvas: {backgroundColor: '#ffffff', borderRadius: 8},
  row: {flexDirection: 'row'},
});
