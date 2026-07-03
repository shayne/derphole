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
            url: "https://github.com/shayne/derphole/releases/download/v0.16.0/DerpholeMobile.xcframework.zip",
            checksum: "f957bbe3bbd80d18514e0d6096af81d55c191b1e855f4378fedef123c6e49e9a"
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
