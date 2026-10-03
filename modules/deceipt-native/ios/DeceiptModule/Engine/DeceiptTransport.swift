//
//  DeceiptTransport.swift
//  Deceipt iOS native adapter (A4)
//
//  The BLE seam. The engine owns the protocol; a transport owns the radio.
//  CoreBluetooth implementations live in the app target (they need a radio and
//  an iOS run loop); `LoopbackTransport` is the radio-free seam the engine
//  tests drive. RSSI never appears here: it is exposed only as a diagnostics
//  field on candidate events (DESIGN.md §2.5).
//

import Foundation

/// Role at the radio layer: merchant advertises (GATT server), customer scans
/// (GATT client).
public enum DeceiptRole: String {
    case merchant
    case customer
}

public struct PeerCandidate {
    public var peripheralId: String
    public var serviceUuid: String
    public var protocolVersion: Int?
    public var deterministicLabel: String
    public var rssi: Int?
}

public protocol DeceiptTransport: AnyObject {
    var role: DeceiptRole { get }
    /// ATT MTU currently negotiated (reported, never assumed).
    var attMtu: Int { get }

    // Inbound (fragments are raw LPdu fragments on the named characteristic).
    var onCommandFragment: ((Data) -> Void)? { get set }
    var onEventFragment: ((Data) -> Void)? { get set }
    var onDataFrame: ((Data) -> Void)? { get set }
    var onConnected: ((Int) -> Void)? { get set }
    var onDisconnected: ((String) -> Void)? { get set }
    var onAdvertisingStarted: (() -> Void)? { get set }
    var onAdvertisingStopped: ((String) -> Void)? { get set }
    var onScanStarted: (() -> Void)? { get set }
    var onScanStopped: ((String) -> Void)? { get set }
    var onPeerCandidate: ((PeerCandidate) -> Void)? { get set }
    var onPeerCandidateLost: ((String) -> Void)? { get set }
    var onBluetoothState: ((String) -> Void)? { get set }

    // Merchant: advertise the service and stand up the GATT server.
    func startAdvertising()
    func stopAdvertising()
    /// Merchant: send an LPdu fragment on EVENT (indicate).
    func sendEvent(_ fragment: Data) -> Bool
    /// Merchant: send a DataFrame on DATA (notify). `true` == accepted into the
    /// radio's bounded queue (false == backpressure, retry later).
    func sendData(_ frame: Data) -> Bool

    // Customer: scan, connect to the one selected peripheral, write COMMAND.
    func startScan()
    func stopScan()
    func connect(peripheralId: String)
    /// Customer: send an LPdu fragment on COMMAND (write with response).
    func sendCommand(_ fragment: Data) -> Bool
    func disconnect()

    /// Number of ATT payload bytes available for an LPdu fragment.
    var fragmentPayloadMax: Int { get }
}

public extension DeceiptTransport {
    /// LPdu fragment payload max: `att_payload_max − 4` header bytes.
    var fragmentPayloadMax: Int {
        max(1, min(DeceiptBounds.attPayloadMax(attMtu) - DeceiptBounds.lpduHeaderBytes, DeceiptBounds.maxLpduFragBytes))
    }
}

/// In-process radio for engine tests. Two transports are linked so each one's
/// sends arrive at the other's handlers, on a serial queue, respecting the
/// advertised ATT payload.
public final class LoopbackTransport: DeceiptTransport {
    public let role: DeceiptRole
    public var attMtu: Int

    public var onCommandFragment: ((Data) -> Void)?
    public var onEventFragment: ((Data) -> Void)?
    public var onDataFrame: ((Data) -> Void)?
    public var onConnected: ((Int) -> Void)?
    public var onDisconnected: ((String) -> Void)?
    public var onAdvertisingStarted: (() -> Void)?
    public var onAdvertisingStopped: ((String) -> Void)?
    public var onScanStarted: (() -> Void)?
    public var onScanStopped: ((String) -> Void)?
    public var onPeerCandidate: ((PeerCandidate) -> Void)?
    public var onPeerCandidateLost: ((String) -> Void)?
    public var onBluetoothState: ((String) -> Void)?

    public private(set) var peer: LoopbackTransport?
    private let queue = DispatchQueue(label: "deceipt.loopback")
    /// Test hooks: drop/substitute a frame or fragment.
    public var dropDataFrames = false
    public var tamperDataFrame: ((Data) -> Data)?

    public init(role: DeceiptRole, attMtu: Int = 185) {
        self.role = role
        self.attMtu = attMtu
    }

    public func link(_ other: LoopbackTransport) {
        peer = other
        other.peer = self
    }

    public func startAdvertising() {
        onAdvertisingStarted?()
        // Advertise a candidate to the linked central.
        queue.async { [weak self] in
            guard let self, let central = self.peer else { return }
            central.onPeerCandidate?(PeerCandidate(
                peripheralId: "loopback-peripheral",
                serviceUuid: DeceiptGatt.serviceUuid,
                protocolVersion: Int(DeceiptProto.protocolVersion),
                deterministicLabel: "loopback",
                rssi: nil
            ))
        }
    }

    public func stopAdvertising() { onAdvertisingStopped?("stopped") }

    public func startScan() {
        onScanStarted?()
        queue.async { [weak self] in
            guard let self else { return }
            // A linked advertiser reports itself.
            self.peer?.onAdvertisingStarted?()
            self.onPeerCandidate?(PeerCandidate(
                peripheralId: "loopback-peripheral",
                serviceUuid: DeceiptGatt.serviceUuid,
                protocolVersion: Int(DeceiptProto.protocolVersion),
                deterministicLabel: "loopback",
                rssi: nil
            ))
        }
    }

    public func stopScan() { onScanStopped?("user_cancelled") }

    public func connect(peripheralId: String) {
        queue.async { [weak self] in
            guard let self else { return }
            self.onConnected?(self.attMtu)
            self.peer?.onConnected?(self.attMtu)
        }
    }

    public func disconnect() {
        queue.async { [weak self] in
            self?.onDisconnected?("link_lost")
            self?.peer?.onDisconnected?("link_lost")
        }
    }

    public func sendEvent(_ fragment: Data) -> Bool {
        queue.async { [weak self] in self?.peer?.onEventFragment?(fragment) }
        return true
    }

    public func sendCommand(_ fragment: Data) -> Bool {
        queue.async { [weak self] in self?.peer?.onCommandFragment?(fragment) }
        return true
    }

    public func sendData(_ frame: Data) -> Bool {
        if dropDataFrames { return false }
        let out = tamperDataFrame?(frame) ?? frame
        queue.async { [weak self] in self?.peer?.onDataFrame?(out) }
        return true
    }
}
