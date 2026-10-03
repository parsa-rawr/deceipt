// swift-tools-version:5.9
//
// SwiftPM package for the Deceipt iOS native adapter core.
//
// The module's protocol/crypto engine is platform-portable Foundation +
// CryptoKit. CoreBluetooth/Keychain/UIKit stay in the Xcode app target
// (app/ios/DeceiptApp/Native/) because they cannot be exercised by `swift
// test` on a Mac without a radio and a simulator entitlement.
//
// `swift test` runs the radio-independent conformance vectors (Ed25519,
// transcript, key schedule, AEAD framing, CBOR) straight from
// protocol/vectors — those MUST pass without a device.
//
import PackageDescription

let package = Package(
    name: "DeceiptModule",
    platforms: [
        .iOS(.v15),
        .macOS(.v12),
    ],
    products: [
        .library(name: "DeceiptModule", targets: ["DeceiptModule"]),
    ],
    targets: [
        .target(
            name: "DeceiptModule",
            path: "DeceiptModule"
        ),
        .testTarget(
            name: "DeceiptModuleTests",
            dependencies: ["DeceiptModule"],
            path: "Tests"
        ),
    ]
)
