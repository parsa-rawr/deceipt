//
//  CborTests.swift
//  Deceipt iOS adapter tests (A4)
//
//  Canonical CBOR is radio-independent and MUST pass.
//

import XCTest
@testable import DeceiptModule

final class CborTests: XCTestCase {
    func testEncodeMinimalIntegers() throws {
        XCTAssertEqual(DeceiptBytes.hex(try CborEncoder.encode(.uint(0))), "00")
        XCTAssertEqual(DeceiptBytes.hex(try CborEncoder.encode(.uint(23))), "17")
        XCTAssertEqual(DeceiptBytes.hex(try CborEncoder.encode(.uint(24))), "1818")
        XCTAssertEqual(DeceiptBytes.hex(try CborEncoder.encode(.uint(255))), "18ff")
        XCTAssertEqual(DeceiptBytes.hex(try CborEncoder.encode(.uint(256))), "190100")
        XCTAssertEqual(DeceiptBytes.hex(try CborEncoder.encode(.int(-8))), "27")
    }

    func testRejectNonMinimalArg() throws {
        // 0x18 0x00 encodes 0 non-minimally.
        XCTAssertThrowsError(try CborDecoder.decode(Data([0x18, 0x00]))) { err in
            XCTAssertEqual((err as? DeceiptFailure)?.bridge.name, "CBOR_NONCANONICAL")
        }
    }

    func testRejectIndefiniteLength() {
        XCTAssertThrowsError(try CborDecoder.decode(Data([0x9f, 0xff]))) { err in
            XCTAssertEqual((err as? DeceiptFailure)?.bridge.name, "CBOR_UNSUPPORTED_TYPE")
        }
    }

    func testRejectFloatAndTag() {
        XCTAssertThrowsError(try CborDecoder.decode(Data([0xf9, 0x3c, 0x00]))) { err in
            XCTAssertEqual((err as? DeceiptFailure)?.bridge.name, "CBOR_UNSUPPORTED_TYPE")
        }
        XCTAssertThrowsError(try CborDecoder.decode(Data([0xc0, 0x00]))) { err in
            XCTAssertEqual((err as? DeceiptFailure)?.bridge.name, "CBOR_UNSUPPORTED_TYPE")
        }
    }

    func testRejectUnsortedMapKeys() {
        // {2:0, 1:0} is non-canonical.
        let d = Data([0xa2, 0x02, 0x00, 0x01, 0x00])
        XCTAssertThrowsError(try CborDecoder.decode(d)) { err in
            XCTAssertEqual((err as? DeceiptFailure)?.bridge.name, "CBOR_NONCANONICAL")
        }
    }

    func testRejectDuplicateMapKeys() {
        // {1:0, 1:1}
        let d = Data([0xa2, 0x01, 0x00, 0x01, 0x01])
        XCTAssertThrowsError(try CborDecoder.decode(d)) { err in
            XCTAssertEqual((err as? DeceiptFailure)?.bridge.name, "CBOR_DUPLICATE_KEY")
        }
    }

    func testBindingsRoundTripWithFixtureData() throws {
        // binding_tuple (87 bytes) from handshake-valid.json is canonical CBOR;
        // decode then re-encode must reproduce it byte-for-byte.
        let v = try VectorFixtures.json("protocol/vectors/handshake-valid.json")
        let tuple = try VectorFixtures.hex(v, "binding_tuple_hex")
        let decoded = try CborDecoder.decode(tuple)
        XCTAssertHexEqual(try CborEncoder.encode(decoded), tuple, "binding_tuple canonical round-trip")
        // tuple[1] = session_id, tuple[2] = transfer_id (handshake.md §3.1).
        let arr = try XCTUnwrap(decoded.asArray)
        XCTAssertEqual(arr.count, 5)
        XCTAssertEqual(arr[0].asUInt, 1)
        XCTAssertEqual(arr[1].asData?.count, 16)
        XCTAssertEqual(arr[2].asData?.count, 16)
        XCTAssertEqual(arr[3].asData?.count, 16)
        XCTAssertEqual(arr[4].asData?.count, 32)
        // Byte offsets from the fixture: session_id 00112233445566778899aabbccddeeff,
        // transfer_id ffeeddccbbaa99887766554433221100.
        XCTAssertEqual(DeceiptBytes.hex(try XCTUnwrap(arr[1].asData)), "00112233445566778899aabbccddeeff")
        XCTAssertEqual(DeceiptBytes.hex(try XCTUnwrap(arr[2].asData)), "ffeeddccbbaa99887766554433221100")
    }

    func testCborDepthBound() {
        // 13 nested arrays exceeds max_depth 12.
        var d = Data()
        for _ in 0..<13 { d.append(0x81) }
        d.append(0x00)
        XCTAssertThrowsError(try CborDecoder.decode(d)) { err in
            XCTAssertEqual((err as? DeceiptFailure)?.bridge.name, "CBOR_DEPTH_EXCEEDED")
        }
    }
}
