//
//  VectorFixtures.swift
//  Deceipt iOS adapter tests (A4)
//
//  Loads the frozen protocol vectors from the repository. The repo root is
//  derived from this source file's compile-time path so `swift test` works
//  from any working directory without copying the vectors into the module.
//

import Foundation
import XCTest
@testable import DeceiptModule

enum VectorFixtures {
    /// .../modules/deceipt-native/ios/Tests/VectorFixtures.swift -> repo root.
    static let repoRoot: URL = {
        var url = URL(fileURLWithPath: #filePath)
        // Tests/VectorFixtures.swift -> Tests -> ios -> deceipt-native -> modules -> root
        for _ in 0..<5 { url.deleteLastPathComponent() }
        return url
    }()

    static func json(_ relative: String) throws -> [String: Any] {
        let url = repoRoot.appendingPathComponent(relative)
        let data = try Data(contentsOf: url)
        guard let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw NSError(domain: "VectorFixtures", code: 1, userInfo: [NSLocalizedDescriptionKey: "not a JSON object: \(relative)"])
        }
        return obj
    }

    static func hex(_ obj: [String: Any], _ key: String) throws -> Data {
        guard let s = obj[key] as? String, let d = DeceiptBytes.fromHex(s) else {
            throw NSError(domain: "VectorFixtures", code: 2, userInfo: [NSLocalizedDescriptionKey: "missing/invalid hex \(key)"])
        }
        return d
    }
}

func XCTAssertHexEqual(_ actual: Data, _ expected: Data, _ message: String = "", file: StaticString = #filePath, line: UInt = #line) {
    XCTAssertEqual(DeceiptBytes.hex(actual), DeceiptBytes.hex(expected), message, file: file, line: line)
}
