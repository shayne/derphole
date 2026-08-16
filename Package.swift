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
            url: "https://github.com/shayne/derphole/releases/download/v0.18.2/DerpholeMobile.xcframework.zip",
            checksum: "79c277c191ee4108b896e566ce6634f43a1b8d1758e0bee4a62a43bf51c2f08f"
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
