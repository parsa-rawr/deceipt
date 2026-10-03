/**
 * Jest stand-in for `react-native-camera-kit`.
 *
 * The real package cannot load under Jest: it ships a compiled spec that React
 * Native's babel codegen plugin rejects ("Could not find component config for
 * native component"), and a native view cannot render in Node regardless.
 *
 * This is a BOUNDARY stub, not a mock echo. It exists so a test can deliver a
 * scan event to the real `QrScanner` and assert the CONSUMER-VISIBLE
 * consequence — that a scanned payload reaches the same selection path as a typed
 * one. Nothing here re-implements library behaviour.
 */

import React from 'react';
import {View} from 'react-native';

export const CameraType = {Back: 'back', Front: 'front'} as const;

/** Props surface the app uses; the rest of the library is not needed. */
export interface MockCameraProps {
  style?: unknown;
  cameraType?: string;
  scanBarcode?: boolean;
  showFrame?: boolean;
  onReadCode?: (event: {nativeEvent: {codeStringValue: string}}) => void;
  onError?: (event: {nativeEvent: {errorMessage: string}}) => void;
  testID?: string;
}

export function Camera(props: MockCameraProps): React.JSX.Element {
  return <View testID={props.testID ?? 'mock-camera'} />;
}
