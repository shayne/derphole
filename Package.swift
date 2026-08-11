// swift-tools-version: 5.10
import PackageDescription

let package = Package(
    name: "derphole",
    platforms: [
        .iOS(.v17)
    ],
    products: [
        .library(name: "DerpholeTunnel", targets: ["DerpholeTunnel"])
    ],
    targets: [
        .binaryTarget(
            name: "DerpholeMobile",
            url: "https://github.com/shayne/derphole/releases/download/v0.18.0/DerpholeMobile.xcframework.zip",
            checksum: "f33e4862547f3c8d7ad082f7875e368c2cedec8ead721dfeb6a2464e43d543de"
        ),
        .target(
            name: "DerpholeTunnel",
            dependencies: ["DerpholeMobile"],
            path: "Sources/DerpholeTunnel"
        ),
        .testTarget(
            name: "DerpholeTunnelTests",
            dependencies: ["DerpholeTunnel"],
            path: "Tests/DerpholeTunnelTests"
        )
    ]
)
