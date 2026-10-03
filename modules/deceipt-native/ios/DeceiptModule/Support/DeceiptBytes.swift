//
//  DeceiptBytes.swift
//  Deceipt iOS native adapter (A4)
//
//  Byte, hex and base64 helpers. The bridge contract requires RFC 4648 §4
//  base64 (padding included) and lowercase hex for `Id16Hex`.
//
//  No key material is ever logged from this file.
//

import Foundation

public enum DeceiptBytes {
    /// Lowercase hex, no separators.
    public static func hex(_ data: Data) -> String {
        var out = String()
        out.reserveCapacity(data.count * 2)
        for b in data {
            out.append(String(format: "%02x", b))
        }
        return out
    }

    /// Strict lowercase/uppercase hex decode. Returns nil on malformed input
    /// (odd length or non-hex characters) rather than truncating.
    public static func fromHex(_ s: String) -> Data? {
        let chars = Array(s.utf8)
        guard chars.count % 2 == 0 else { return nil }
        var out = Data(capacity: chars.count / 2)
        func nibble(_ c: UInt8) -> UInt8? {
            switch c {
            case 0x30...0x39: return c - 0x30
            case 0x61...0x66: return c - 0x61 + 10
            case 0x41...0x46: return c - 0x41 + 10
            default: return nil
            }
        }
        var i = 0
        while i < chars.count {
            guard let hi = nibble(chars[i]), let lo = nibble(chars[i + 1]) else { return nil }
            out.append((hi << 4) | lo)
            i += 2
        }
        return out
    }

    /// RFC 4648 §4 base64 with padding.
    public static func base64(_ data: Data) -> String {
        data.base64EncodedString()
    }

    /// Strict base64 decode. Rejects malformed input (RN transport requires
    /// decoders to reject rather than silently truncate).
    public static func fromBase64(_ s: String) -> Data? {
        guard let d = Data(base64Encoded: s, options: []) else { return nil }
        // Round-trip guard: rejects non-canonical encodings that Foundation
        // would otherwise accept leniently.
        guard base64(d) == s else { return nil }
        return d
    }

    /// Base64URL, no padding — used only for the `deceipt1:` QR payload.
    public static func base64URLNoPad(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    public static func fromBase64URLNoPad(_ s: String) -> Data? {
        var t = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        let pad = (4 - t.count % 4) % 4
        t += String(repeating: "=", count: pad)
        return Data(base64Encoded: t, options: [])
    }

    public static func constantTimeEqual(_ a: Data, _ b: Data) -> Bool {
        if a.count != b.count { return false }
        var diff: UInt8 = 0
        for i in 0..<a.count {
            diff |= a[a.startIndex + i] ^ b[b.startIndex + i]
        }
        return diff == 0
    }

    /// Best-effort zeroization of a mutable byte buffer (handshake.md §8:
    /// zeroization is best-effort in a managed runtime).
    public static func zeroize(_ data: inout Data) {
        if data.isEmpty { return }
        data.withUnsafeMutableBytes { raw in
            if let base = raw.baseAddress {
                memset_s(base, raw.count, 0, raw.count)
            }
        }
        data.removeAll(keepingCapacity: false)
    }

    public static func u16BE(_ v: UInt16) -> Data {
        Data([UInt8((v >> 8) & 0xff), UInt8(v & 0xff)])
    }

    public static func u32BE(_ v: UInt32) -> Data {
        Data([
            UInt8((v >> 24) & 0xff), UInt8((v >> 16) & 0xff),
            UInt8((v >> 8) & 0xff), UInt8(v & 0xff),
        ])
    }

    public static func u64BE(_ v: UInt64) -> Data {
        var out = Data(capacity: 8)
        for shift in stride(from: 56, through: 0, by: -8) {
            out.append(UInt8((v >> UInt64(shift)) & 0xff))
        }
        return out
    }

    public static func readU16BE(_ d: Data, _ off: Int) -> UInt16? {
        guard off + 2 <= d.count else { return nil }
        let i = d.startIndex + off
        return (UInt16(d[i]) << 8) | UInt16(d[i + 1])
    }

    public static func readU32BE(_ d: Data, _ off: Int) -> UInt32? {
        guard off + 4 <= d.count else { return nil }
        let i = d.startIndex + off
        return (UInt32(d[i]) << 24) | (UInt32(d[i + 1]) << 16) | (UInt32(d[i + 2]) << 8) | UInt32(d[i + 3])
    }

    public static func readU64BE(_ d: Data, _ off: Int) -> UInt64? {
        guard off + 8 <= d.count else { return nil }
        var v: UInt64 = 0
        for k in 0..<8 { v = (v << 8) | UInt64(d[d.startIndex + off + k]) }
        return v
    }

    public static func slice(_ d: Data, _ off: Int, _ len: Int) -> Data? {
        guard off >= 0, len >= 0, off + len <= d.count else { return nil }
        return d.subdata(in: (d.startIndex + off)..<(d.startIndex + off + len))
    }
}
