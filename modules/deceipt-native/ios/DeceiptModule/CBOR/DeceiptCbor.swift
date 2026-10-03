//
//  DeceiptCbor.swift
//  Deceipt iOS native adapter (A4)
//
//  RFC 8949 §4.2.1 core-deterministic CBOR, restricted to the v1 profile
//  (receipt-v1.md §1): integer keys 0..255, ascending encoded order, no
//  floats, no tags, no indefinite lengths, definite-only, minimal-length
//  arguments, NFC/control-checked text on the semantic layer.
//
//  Parser bounds (depth/items/array/map/text/bytes) are enforced *during*
//  decoding, before any allocation sized by a peer-declared length
//  (receipt-v1.md §8, invariant 7).
//

import Foundation

public enum CborKind {
    case unsigned(UInt64)
    case negative(Int64)   // value is the actual negative integer
    case byteString(Data)
    case textString(String)
    case array([CborValue])
    case map([(CborValue, CborValue)])
    case bool(Bool)
}

public final class CborValue {
    public let kind: CborKind

    public init(_ kind: CborKind) { self.kind = kind }

    public static func uint(_ v: UInt64) -> CborValue { CborValue(.unsigned(v)) }
    public static func int(_ v: Int64) -> CborValue { v < 0 ? CborValue(.negative(v)) : CborValue(.unsigned(UInt64(v))) }
    public static func bytes(_ d: Data) -> CborValue { CborValue(.byteString(d)) }
    public static func text(_ s: String) -> CborValue { CborValue(.textString(s)) }
    public static func array(_ a: [CborValue]) -> CborValue { CborValue(.array(a)) }
    public static func map(_ m: [(CborValue, CborValue)]) -> CborValue { CborValue(.map(m)) }
    public static func bool(_ b: Bool) -> CborValue { CborValue(.bool(b)) }

    // MARK: Accessors

    public var asUInt: UInt64? { if case .unsigned(let v) = kind { return v }; return nil }
    public var asInt: Int64? {
        switch kind {
        case .unsigned(let v): return v <= UInt64(Int64.max) ? Int64(v) : nil
        case .negative(let v): return v
        default: return nil
        }
    }
    public var asData: Data? { if case .byteString(let d) = kind { return d }; return nil }
    public var asText: String? { if case .textString(let s) = kind { return s }; return nil }
    public var asBool: Bool? { if case .bool(let b) = kind { return b }; return nil }
    public var asArray: [CborValue]? { if case .array(let a) = kind { return a }; return nil }
    public var asMap: [(CborValue, CborValue)]? { if case .map(let m) = kind { return m }; return nil }

    /// Integer-label map lookup (v1 uses integer labels only).
    public func field(_ label: Int64) -> CborValue? {
        guard case .map(let m) = kind else { return nil }
        for (k, v) in m where k.asInt == label { return v }
        return nil
    }

    public func mapKeysAsInts() -> [Int64]? {
        guard case .map(let m) = kind else { return nil }
        return m.map { $0.0.asInt ?? Int64.min }
    }
}

// MARK: - Encoder

public enum CborEncodeError: Error {
    case unsupportedValue
    case sizeExceeded
    case depthExceeded
    case nonMinimalKey
    case duplicateKey
}

public enum CborEncoder {
    /// Canonical encode. Map keys MUST be integers; they are sorted by encoded
    /// bytes (== numeric order for 0..255) and duplicates rejected.
    public static func encode(_ value: CborValue) throws -> Data {
        var out = Data()
        try write(value, into: &out, depth: 0)
        return out
    }

    private static func write(_ value: CborValue, into out: inout Data, depth: Int) throws {
        guard depth <= DeceiptBounds.cborMaxDepth else { throw CborEncodeError.depthExceeded }
        switch value.kind {
        case .unsigned(let v):
            writeMajor(0, v, into: &out)
        case .negative(let v):
            // major 0 argument = -1 - v ; v is the actual negative value.
            let arg = UInt64(-1 - v)
            writeMajor(1, arg, into: &out)
        case .byteString(let d):
            guard d.count <= DeceiptBounds.cborMaxBytes else { throw CborEncodeError.sizeExceeded }
            writeMajor(2, UInt64(d.count), into: &out)
            out.append(d)
        case .textString(let s):
            let bytes = Data(s.utf8)
            guard bytes.count <= DeceiptBounds.cborMaxTextBytes else { throw CborEncodeError.sizeExceeded }
            writeMajor(3, UInt64(bytes.count), into: &out)
            out.append(bytes)
        case .array(let a):
            guard a.count <= DeceiptBounds.cborMaxArray else { throw CborEncodeError.sizeExceeded }
            writeMajor(4, UInt64(a.count), into: &out)
            for item in a { try write(item, into: &out, depth: depth + 1) }
        case .map(let m):
            guard m.count <= DeceiptBounds.cborMaxMap else { throw CborEncodeError.sizeExceeded }
            // Sort by encoded key bytes (canonical order).
            var encoded: [(Data, CborValue, CborValue)] = []
            encoded.reserveCapacity(m.count)
            for (k, v) in m {
                guard k.asInt != nil else { throw CborEncodeError.nonMinimalKey }
                var kb = Data()
                try write(k, into: &kb, depth: depth + 1)
                encoded.append((kb, k, v))
            }
            encoded.sort { lhs, rhs in
                if lhs.0.count != rhs.0.count { return lhs.0.count < rhs.0.count }
                return lhs.0.lexicographicallyPrecedes(rhs.0)
            }
            for i in 1..<max(encoded.count, 1) where encoded.count > 1 {
                if encoded[i].0 == encoded[i - 1].0 { throw CborEncodeError.duplicateKey }
            }
            writeMajor(5, UInt64(m.count), into: &out)
            for (kb, _, v) in encoded {
                out.append(kb)
                try write(v, into: &out, depth: depth + 1)
            }
        case .bool(let b):
            out.append(b ? 0xf5 : 0xf4)
        }
    }

    private static func writeMajor(_ major: UInt8, _ arg: UInt64, into out: inout Data) {
        let base = major << 5
        if arg < 24 {
            out.append(base | UInt8(arg))
        } else if arg <= 0xff {
            out.append(base | 24)
            out.append(UInt8(arg))
        } else if arg <= 0xffff {
            out.append(base | 25)
            out.append(contentsOf: DeceiptBytes.u16BE(UInt16(arg)))
        } else if arg <= 0xffff_ffff {
            out.append(base | 26)
            out.append(contentsOf: DeceiptBytes.u32BE(UInt32(arg)))
        } else {
            out.append(base | 27)
            out.append(contentsOf: DeceiptBytes.u64BE(arg))
        }
    }
}

// MARK: - Decoder

public struct CborDecoder {
    private let data: Data
    private var pos: Int = 0
    private var depth = 0
    private var itemCount = 0

    public init(_ data: Data) { self.data = data }

    public static func decode(_ data: Data) throws -> CborValue {
        var d = CborDecoder(data)
        let v = try d.decodeValue()
        guard d.pos == data.count else { throw DeceiptFailure("CBOR_MALFORMED", phase: BridgePhase.internal, detail: "trailing bytes") }
        return v
    }

    private mutating func byte() throws -> UInt8 {
        guard pos < data.count else { throw DeceiptFailure("CBOR_MALFORMED", phase: BridgePhase.internal) }
        let b = data[data.startIndex + pos]
        pos += 1
        return b
    }

    private mutating func take(_ n: Int) throws -> Data {
        guard n >= 0, pos + n <= data.count else { throw DeceiptFailure("CBOR_MALFORMED", phase: BridgePhase.internal) }
        let d = data.subdata(in: (data.startIndex + pos)..<(data.startIndex + pos + n))
        pos += n
        return d
    }

    /// Reads a major-type argument enforcing minimal-length encoding.
    private mutating func readArg(_ info: UInt8) throws -> UInt64 {
        switch info {
        case 0..<24: return UInt64(info)
        case 24:
            let v = try byte()
            guard v >= 24 else { throw DeceiptFailure("CBOR_NONCANONICAL", phase: BridgePhase.internal, detail: "non-minimal arg") }
            return UInt64(v)
        case 25:
            let d = try take(2)
            let v = (UInt64(d[d.startIndex]) << 8) | UInt64(d[d.startIndex + 1])
            guard v > 0xff else { throw DeceiptFailure("CBOR_NONCANONICAL", phase: BridgePhase.internal, detail: "non-minimal arg") }
            return v
        case 26:
            let d = try take(4)
            let v = DeceiptBytes.readU32BE(d, 0).map(UInt64.init) ?? 0
            guard v > 0xffff else { throw DeceiptFailure("CBOR_NONCANONICAL", phase: BridgePhase.internal, detail: "non-minimal arg") }
            return v
        case 27:
            let d = try take(8)
            let v = DeceiptBytes.readU64BE(d, 0) ?? 0
            guard v > 0xffff_ffff else { throw DeceiptFailure("CBOR_NONCANONICAL", phase: BridgePhase.internal, detail: "non-minimal arg") }
            return v
        case 31:
            throw DeceiptFailure("CBOR_UNSUPPORTED_TYPE", phase: BridgePhase.internal, detail: "indefinite length")
        default:
            throw DeceiptFailure("CBOR_MALFORMED", phase: BridgePhase.internal, detail: "reserved info")
        }
    }

    private mutating func bumpItem() throws {
        itemCount += 1
        guard itemCount <= DeceiptBounds.cborMaxItems else { throw DeceiptFailure("CBOR_SIZE_EXCEEDED", phase: BridgePhase.internal) }
    }

    public mutating func decodeValue() throws -> CborValue {
        try bumpItem()
        let initial = try byte()
        let major = initial >> 5
        let info = initial & 0x1f
        switch major {
        case 0:
            return .uint(try readArg(info))
        case 1:
            let arg = try readArg(info)
            guard arg <= UInt64(Int64.max) else { throw DeceiptFailure("CBOR_MALFORMED", phase: BridgePhase.internal) }
            return CborValue(.negative(-1 - Int64(arg)))
        case 2:
            let n = try readArg(info)
            guard n <= UInt64(DeceiptBounds.cborMaxBytes) else { throw DeceiptFailure("CBOR_SIZE_EXCEEDED", phase: BridgePhase.internal) }
            return CborValue(.byteString(try take(Int(n))))
        case 3:
            let n = try readArg(info)
            guard n <= UInt64(DeceiptBounds.cborMaxTextBytes) else { throw DeceiptFailure("CBOR_SIZE_EXCEEDED", phase: BridgePhase.internal) }
            let raw = try take(Int(n))
            guard let s = String(data: raw, encoding: .utf8) else { throw DeceiptFailure("CBOR_MALFORMED", phase: BridgePhase.internal, detail: "bad utf8") }
            return CborValue(.textString(s))
        case 4:
            let n = try readArg(info)
            // Bound-check BEFORE allocating.
            guard n <= UInt64(DeceiptBounds.cborMaxArray) else { throw DeceiptFailure("CBOR_SIZE_EXCEEDED", phase: BridgePhase.internal) }
            depth += 1
            guard depth <= DeceiptBounds.cborMaxDepth else { throw DeceiptFailure("CBOR_DEPTH_EXCEEDED", phase: BridgePhase.internal) }
            var arr: [CborValue] = []
            arr.reserveCapacity(Int(n))
            for _ in 0..<n { arr.append(try decodeValue()) }
            depth -= 1
            return CborValue(.array(arr))
        case 5:
            let n = try readArg(info)
            guard n <= UInt64(DeceiptBounds.cborMaxMap) else { throw DeceiptFailure("CBOR_SIZE_EXCEEDED", phase: BridgePhase.internal) }
            depth += 1
            guard depth <= DeceiptBounds.cborMaxDepth else { throw DeceiptFailure("CBOR_DEPTH_EXCEEDED", phase: BridgePhase.internal) }
            var pairs: [(CborValue, CborValue)] = []
            pairs.reserveCapacity(Int(n))
            var prevKeyBytes: Data? = nil
            for _ in 0..<n {
                let start = pos
                let k = try decodeValue()
                var kb = data.subdata(in: (data.startIndex + start)..<(data.startIndex + pos))
                if let prev = prevKeyBytes {
                    // Canonical: ascending encoded-key order, no duplicates.
                    if kb == prev { throw DeceiptFailure("CBOR_DUPLICATE_KEY", phase: BridgePhase.internal) }
                    if !canonicalLess(prev, kb) { throw DeceiptFailure("CBOR_NONCANONICAL", phase: BridgePhase.internal, detail: "map key order") }
                }
                prevKeyBytes = kb
                kb.removeAll()
                let v = try decodeValue()
                pairs.append((k, v))
            }
            depth -= 1
            return CborValue(.map(pairs))
        case 6:
            throw DeceiptFailure("CBOR_UNSUPPORTED_TYPE", phase: BridgePhase.internal, detail: "tag")
        case 7:
            switch info {
            case 20: return .bool(false)
            case 21: return .bool(true)
            case 22, 23: throw DeceiptFailure("CBOR_UNSUPPORTED_TYPE", phase: BridgePhase.internal, detail: "null/undefined")
            case 25, 26, 27: throw DeceiptFailure("CBOR_UNSUPPORTED_TYPE", phase: BridgePhase.internal, detail: "float")
            default: throw DeceiptFailure("CBOR_UNSUPPORTED_TYPE", phase: BridgePhase.internal, detail: "simple value")
            }
        default:
            throw DeceiptFailure("CBOR_MALFORMED", phase: BridgePhase.internal)
        }
    }

    /// RFC 8949 §4.2.1 length-first, then bytewise canonical ordering.
    private func canonicalLess(_ a: Data, _ b: Data) -> Bool {
        if a.count != b.count { return a.count < b.count }
        return a.lexicographicallyPrecedes(b)
    }
}
