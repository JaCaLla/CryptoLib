// swift-tools-version: 6.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "CryptoLib",
    platforms: [.macOS(.v10_15), .iOS(.v13)],
    products: [
        .library(
            name: "CryptoLib",
            targets: ["CryptoLib"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "2.0.0")
    ],
    targets: [
        .target(
            name: "CryptoLib",
            dependencies: [.product(name: "Crypto", package: "swift-crypto")],
                        resources: [
                            .process("keys.env"), 
                        ]
        ),
        .testTarget(
            name: "CryptoLibTests",
            dependencies: ["CryptoLib"]),
    ]
)
