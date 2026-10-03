//
//  DeceiptBleTransport.swift
//  Deceipt iOS native adapter (A4) — app target
//
//  Core Bluetooth implementation of the `DeceiptTransport` seam.
//
//    * Merchant = GATT SERVER + advertiser (`CBPeripheralManager`).
//    * Customer = GATT CLIENT + scanner (`CBCentralManager`).
//
//  The advertisement carries the service UUID and nothing else. No OS pairing
//  is used; security comes from the handshake and the receipt signature, never
//  from the link (wire.md §1). RSSI is surfaced ONLY via `PeerCandidate.rssi`
//  as a diagnostics value and never as a selection or trust input.
//
//  Outbound traffic is drained through a bounded queue so a stalled radio
//  applies backpressure instead of unbounded memory growth (invariant 7).
//

import Foundation
import CoreBluetooth

@objc(DeceiptBleTransport)
public final class DeceiptBleTransport: NSObject, DeceiptTransport {
    public let role: DeceiptRole
    public private(set) var attMtu: Int

    // Handlers (set by the engine).
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

    private let serviceUUID = CBUUID(string: DeceiptGatt.serviceUuid)
    private let commandUUID = CBUUID(string: DeceiptGatt.commandUuid)
    private let eventUUID = CBUUID(string: DeceiptGatt.eventUuid)
    private let dataUUID = CBUUID(string: DeceiptGatt.dataUuid)

    // Central state
    private var central: CBCentralManager?
    private var discovered: [UUID: CBPeripheral] = [:]
    private var peripheral: CBPeripheral?
    private var commandChar: CBCharacteristic?
    private var eventChar: CBCharacteristic?
    private var dataChar: CBCharacteristic?

    // Peripheral state
    private var peripheralManager: CBPeripheralManager?
    private var commandMutable: CBMutableCharacteristic?
    private var eventMutable: CBMutableCharacteristic?
    private var dataMutable: CBMutableCharacteristic?
    private var advertised = false

    // Bounded outbound queue (fragments and frames share one drain path).
    private struct Outbound {
        var characteristic: CBUUID
        var data: Data
    }
    private var outbound: [Outbound] = []
    private let outboundCap = 64
    /// Customer writes are `.withResponse` and strictly one-in-flight: the next
    /// fragment is only written after `didWriteValueFor` confirms the previous,
    /// so a slow link applies backpressure instead of overrunning the ATT queue.
    private var writeInFlight = false

    private let queue = DispatchQueue(label: "com.deceipt.ble")

    public init(role: DeceiptRole, attMtu: Int = 185) {
        self.role = role
        self.attMtu = attMtu
        super.init()
    }

    // MARK: DeceiptTransport

    public var fragmentPayloadMax: Int {
        let att = min(max(attMtu - 3, 0), DeceiptBounds.maxAttPayload)
        return max(1, min(att - DeceiptBounds.lpduHeaderBytes, DeceiptBounds.maxLpduFragBytes))
    }

    public func startAdvertising() {
        queue.async { [weak self] in
            guard let self else { return }
            if self.peripheralManager == nil {
                self.peripheralManager = CBPeripheralManager(delegate: self, queue: self.queue)
            }
        }
    }

    public func stopAdvertising() {
        queue.async { [weak self] in
            self?.peripheralManager?.stopAdvertising()
            self?.advertised = false
            self?.onAdvertisingStopped?("stopped")
        }
    }

    public func startScan() {
        queue.async { [weak self] in
            guard let self else { return }
            if self.central == nil {
                self.central = CBCentralManager(delegate: self, queue: self.queue)
            } else if self.central?.state == .poweredOn {
                self.central?.scanForPeripherals(withServices: [self.serviceUUID], options: nil)
                self.onScanStarted?()
            }
        }
    }

    public func stopScan() {
        queue.async { [weak self] in
            self?.central?.stopScan()
            self?.onScanStopped?("user_cancelled")
        }
    }

    public func connect(peripheralId: String) {
        queue.async { [weak self] in
            guard let self, let uuid = UUID(uuidString: peripheralId), let p = self.discovered[uuid] else {
                self?.onDisconnected?("connect_failed")
                return
            }
            self.peripheral = p
            p.delegate = self
            self.central?.connect(p, options: nil)
        }
    }

    public func disconnect() {
        queue.async { [weak self] in
            guard let self else { return }
            if let p = self.peripheral {
                self.central?.cancelPeripheralConnection(p)
                self.peripheral = nil
            }
            self.peripheralManager?.removeAllServices()
        }
    }

    public func sendEvent(_ fragment: Data) -> Bool { enqueue(characteristic: eventUUID, data: fragment) }
    public func sendCommand(_ fragment: Data) -> Bool { enqueue(characteristic: commandUUID, data: fragment) }
    public func sendData(_ frame: Data) -> Bool { enqueue(characteristic: dataUUID, data: frame) }

    private func enqueue(characteristic: CBUUID, data: Data) -> Bool {
        var accepted = true
        queue.sync {
            if outbound.count >= outboundCap { accepted = false; return }
            outbound.append(Outbound(characteristic: characteristic, data: data))
        }
        if accepted { drain() }
        return accepted
    }

    private func drain() {
        queue.async { [weak self] in
            guard let self else { return }
            if self.role == .merchant {
                var progressed = true
                while progressed, let next = self.outbound.first {
                    progressed = self.writePeripheral(next)
                    if progressed { self.outbound.removeFirst() }
                }
            } else {
                // Central writes are queued by CoreBluetooth; flush what we can.
                while let next = self.outbound.first {
                    if !self.writeCentral(next) { break }
                    self.outbound.removeFirst()
                }
            }
        }
    }

    private func writePeripheral(_ o: Outbound) -> Bool {
        guard let pm = peripheralManager else { return false }
        let char: CBMutableCharacteristic?
        switch o.characteristic {
        case eventUUID: char = eventMutable
        case dataUUID: char = dataMutable
        default: return false
        }
        guard let c = char else { return false }
        return pm.updateValue(o.data, for: c, onSubscribedCentrals: nil)
    }

    private func writeCentral(_ o: Outbound) -> Bool {
        guard let p = peripheral, let c = commandChar else { return false }
        if writeInFlight { return false }
        writeInFlight = true
        p.writeValue(o.data, for: c, type: .withResponse)
        return true
    }
}

// MARK: - Central (customer)

extension DeceiptBleTransport: CBCentralManagerDelegate {
    public func centralManagerDidUpdateState(_ central: CBCentralManager) {
        onBluetoothState?(DeceiptCapabilities.mapState(central.state))
        if central.state == .poweredOn, role == .customer {
            central.scanForPeripherals(withServices: [serviceUUID], options: nil)
            onScanStarted?()
        }
    }

    public func centralManager(_ central: CBCentralManager, didDiscover peripheral: CBPeripheral,
                               advertisementData: [String: Any], rssi RSSI: NSNumber) {
        discovered[peripheral.identifier] = peripheral
        let adServiceUUIDs = (advertisementData[CBAdvertisementDataServiceUUIDsKey] as? [CBUUID]) ?? []
        guard adServiceUUIDs.contains(serviceUUID) || peripheral.services != nil else {
            // We only request our service UUID, so this is already filtered; keep
            // the diagnostics-only RSSI out of any ordering decision.
            return
        }
        onPeerCandidate?(PeerCandidate(
            peripheralId: peripheral.identifier.uuidString,
            serviceUuid: DeceiptGatt.serviceUuid,
            protocolVersion: nil, // advertisement carries no protocol version (wire.md §1)
            deterministicLabel: String(peripheral.identifier.uuidString.prefix(8)),
            rssi: RSSI.intValue
        ))
    }

    public func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        writeInFlight = false
        peripheral.delegate = self
        peripheral.discoverServices([serviceUUID])
    }

    public func centralManager(_ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral, error: Error?) {
        onDisconnected?("connect_failed")
    }

    public func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral, error: Error?) {
        writeInFlight = false
        onDisconnected?("link_lost")
    }
}

// MARK: - Peripheral (customer side of the link)

extension DeceiptBleTransport: CBPeripheralDelegate {
    public func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        guard error == nil, let services = peripheral.services else { return }
        for s in services where s.uuid == serviceUUID {
            peripheral.discoverCharacteristics([commandUUID, eventUUID, dataUUID], for: s)
        }
    }

    public func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: Error?) {
        guard error == nil, let chars = service.characteristics else { return }
        for c in chars {
            switch c.uuid {
            case commandUUID: commandChar = c
            case eventUUID: eventChar = c; peripheral.setNotifyValue(true, for: c)
            case dataUUID: dataChar = c; peripheral.setNotifyValue(true, for: c)
            default: break
            }
        }
        // Reported MTU from the peripheral's write-with-response capacity.
        let mtu = peripheral.maximumWriteValueLength(for: .withResponse) + 3
        attMtu = min(max(mtu, 23), DeceiptBounds.maxAttPayload + 3)
        onConnected?(attMtu)
    }

    public func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: Error?) {
        guard error == nil, let value = characteristic.value else { return }
        if characteristic.uuid == dataUUID { onDataFrame?(value) }
        else if characteristic.uuid == eventUUID { onEventFragment?(value) }
    }

    /// Backpressure: CoreBluetooth signals the central may write again.
    public func peripheralIsReady(toSendWriteWithoutResponse peripheral: CBPeripheral) {
        drain()
    }

    /// A `.withResponse` write completed: release the one-in-flight slot.
    public func peripheral(_ peripheral: CBPeripheral, didWriteValueFor characteristic: CBCharacteristic, error: Error?) {
        writeInFlight = false
        drain()
    }
}

// MARK: - Peripheral (merchant)

extension DeceiptBleTransport: CBPeripheralManagerDelegate {
    public func peripheralManagerDidUpdateState(_ peripheral: CBPeripheralManager) {
        onBluetoothState?(DeceiptCapabilities.mapState(peripheral.state))
        guard peripheral.state == .poweredOn else { return }
        // Stand up the GATT server once powered on.
        let command = CBMutableCharacteristic(type: commandUUID, properties: [.write],
                                              value: nil, permissions: [.writeable])
        let event = CBMutableCharacteristic(type: eventUUID, properties: [.indicate],
                                            value: nil, permissions: [.readable])
        let data = CBMutableCharacteristic(type: dataUUID, properties: [.notify],
                                           value: nil, permissions: [.readable])
        commandMutable = command; eventMutable = event; dataMutable = data
        let service = CBMutableService(type: serviceUUID, primary: true)
        service.characteristics = [command, event, data]
        peripheral.add(service)
    }

    public func peripheralManager(_ peripheral: CBPeripheralManager, didAdd service: CBService, error: Error?) {
        guard error == nil else { return }
        peripheral.startAdvertising([CBAdvertisementDataServiceUUIDsKey: [serviceUUID]])
    }

    public func peripheralManagerDidStartAdvertising(_ peripheral: CBPeripheralManager, error: Error?) {
        if error == nil {
            advertised = true
            onAdvertisingStarted?()
        }
    }

    public func peripheralManager(_ peripheral: CBPeripheralManager, didReceiveWrite requests: [CBATTRequest]) {
        for request in requests {
            if let value = request.value {
                onCommandFragment?(value)
            }
            peripheral.respond(to: request, withResult: .success)
        }
    }

    public func peripheralManager(_ peripheral: CBPeripheralManager, central: CBCentral, didSubscribeTo characteristic: CBCharacteristic) {
        // No-op beyond tracking: the service is open and security comes from the
        // handshake. Kept explicit so a subscription is never treated as trust.
    }

    public func peripheralManagerIsReady(toUpdateSubscribers peripheral: CBPeripheralManager) {
        drain()
    }
}
