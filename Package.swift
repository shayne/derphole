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
            url: "https://github.com/shayne/derphole/releases/download/v0.16.2/DerpholeMobile.xcframework.zip",
            checksum: "96cfc66eee26ac71137e5fc5db8b472ea9b6a8fafea9f605e317f08678cf73cc"
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
