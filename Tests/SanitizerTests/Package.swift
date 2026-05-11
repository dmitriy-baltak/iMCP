// swift-tools-version: 5.9
//
// Standalone test package for MailSanitizer + SecretPatterns.
// Symlinks the source files from App/Services so the iMCP-MY app build and
// these tests share a single source-of-truth.
//
// Run from this directory: `swift test`

import PackageDescription

let package = Package(
    name: "SanitizerTests",
    platforms: [
        .macOS(.v13),
    ],
    dependencies: [
        .package(url: "https://github.com/scinfu/SwiftSoup.git", from: "2.7.0"),
    ],
    targets: [
        .target(
            name: "MailSanitizer",
            dependencies: [
                .product(name: "SwiftSoup", package: "SwiftSoup"),
            ],
            path: "Sources/MailSanitizer"
        ),
        .testTarget(
            name: "MailSanitizerTests",
            dependencies: ["MailSanitizer"],
            path: "Tests/MailSanitizerTests",
            resources: [
                .copy("Fixtures"),
            ]
        ),
    ]
)
