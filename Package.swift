// swift-tools-version: 5.6
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "LibCrypto",
    platforms: [
        .macOS(.v10_15),
        .iOS(.v13),
        .watchOS(.v6),
        .tvOS(.v13),
    ],
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "LibCrypto",
            targets: ["LibCrypto"]),
    ],
    dependencies: [
        .package(url: "https://github.com/P-H-C/phc-winner-argon2.git", branch: "master"),
        .package(url: "https://github.com/apple/swift-crypto.git", .upToNextMajor(from: "3.4.0")),
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "LibCrypto",
            dependencies: [
                .product(name: "argon2", package: "phc-winner-argon2"),
                .product(name: "Crypto", package: "swift-crypto")
            ]),
        .testTarget(
            name: "LibCryptoTests",
            dependencies: ["LibCrypto"]),
    ]
)
