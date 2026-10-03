//
//  DeceiptCapabilities.swift
//  Deceipt iOS native adapter (A4) — app target
//
//  Capability and permission reporting for the shared UI. A capability that is
//  false MUST surface an explicit capability failure, never silently degrade.
//
//  Core Bluetooth (official docs, 2026-10-03):
//    * CBCentralManager / CBPeripheralManager are available on all iOS devices
//      that support Bluetooth LE; the framework is available from iOS 5, and
//      `NSBluetoothAlwaysUsageDescription` is required for apps linked on or
//      after iOS 13 (Apple: "Core Bluetooth").
//    * Apple documents that Core Bluetooth background modes are NOT supported
//      for iPad apps running on macOS; iOS 26+ adds Live Activity background
//      scanning privileges. The PoC does not rely on background BLE.
//
//  Supported floor: iOS 15.1 (RN 0.87 min_ios_version_supported). Every iPhone
//  that runs iOS 15.1 has both central and peripheral BLE, so bleCentral /
//  blePeripheral / bleAdvertising are true; only the radio can prove it at
//  runtime, and that is what `bluetoothState` reports.
//

import Foundation
import CoreBluetooth
import AVFoundation

@objc(DeceiptCapabilities)
public final class DeceiptCapabilities: NSObject {
    public static let adapterBuild = "a4-ios-0.1.0"

    /// `true` only in explicitly flagged test/dev builds (never production).
    /// A build-time `DECEIPT_TEST_PROVISIONING` flag enables it unconditionally;
    /// otherwise an explicit launch environment variable opts in, so a normal
    /// Release build stays production-safe unless a test harness sets it.
    public static var testProvisioningEnabled: Bool {
        #if DECEIPT_TEST_PROVISIONING
        return true
        #else
        return ProcessInfo.processInfo.environment["DECEIPT_TEST_PROVISIONING"] == "1"
        #endif
    }

    @objc public func report() -> [String: Any] {
        [
            "platform": "ios",
            "bleCentral": true,
            "blePeripheral": true,
            "bleAdvertising": true,
            "protocolVersion": NSNumber(value: DeceiptProto.protocolVersion),
            "suiteIds": [NSNumber(value: DeceiptProto.suiteId)],
            "ed25519": true,
            "ed25519Keystore": true,
            // Honest: Keychain-software, NOT Secure-Enclave-backed.
            "ed25519HardwareBacked": false,
            "keyPersistence": true,
            "cameraQrScan": true,
            "testProvisioningEnabled": DeceiptCapabilities.testProvisioningEnabled,
            "adapterBuild": DeceiptCapabilities.adapterBuild,
        ]
    }

    // MARK: Permissions

    private func bluetoothPermission() -> String {
        if #available(iOS 13.0, *) {
            switch CBManager.authorization {
            case .allowedAlways: return "granted"
            case .denied: return "denied"
            case .restricted: return "restricted"
            case .notDetermined: return "undetermined"
            @unknown default: return "undetermined"
            }
        }
        return "undetermined"
    }

    private func cameraPermission() -> String {
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized: return "granted"
        case .denied: return "denied"
        case .restricted: return "restricted"
        case .notDetermined: return "undetermined"
        @unknown default: return "undetermined"
        }
    }

    /// Maps a CBManager state to the bridge's `BluetoothState`.
    public static func mapState(_ state: CBManagerState) -> String {
        switch state {
        case .poweredOn: return "on"
        case .poweredOff: return "off"
        case .unauthorized: return "unauthorized"
        case .unsupported: return "unsupported"
        default: return "unknown"
        }
    }

    @objc public func permissionReport(bluetoothState: String) -> [String: Any] {
        [
            "bluetooth": bluetoothPermission(),
            "camera": cameraPermission(),
            "bluetoothState": bluetoothState,
        ]
    }
}
