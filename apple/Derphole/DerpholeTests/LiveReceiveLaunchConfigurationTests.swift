import XCTest
@testable import Derphole

final class LiveReceiveLaunchConfigurationTests: XCTestCase {
    func testPayloadRequiresAutostartAndRuntimeTokenForEnvironmentInjection() {
        XCTAssertNil(LiveReceiveLaunchConfiguration.payload(
            from: ["DERPHOLE_LIVE_RECEIVE_TOKEN": "token-123"],
            arguments: []
        ))
        XCTAssertNil(LiveReceiveLaunchConfiguration.payload(
            from: [
                "DERPHOLE_LIVE_RECEIVE_AUTOSTART": "1",
                "DERPHOLE_LIVE_RECEIVE_TOKEN": "   "
            ],
            arguments: []
        ))

        XCTAssertEqual(LiveReceiveLaunchConfiguration.payload(
            from: [
                "DERPHOLE_LIVE_RECEIVE_AUTOSTART": "1",
                "DERPHOLE_LIVE_RECEIVE_TOKEN": " token-123 "
            ],
            arguments: []
        ), "token-123")
    }

    func testPayloadCanComeFromRuntimeLaunchArgument() {
        XCTAssertEqual(LiveReceiveLaunchConfiguration.payload(
            from: [:],
            arguments: ["Derphole", "--derphole-live-receive-token", " token-456 "]
        ), "token-456")
    }

    func testPayloadCanComeFromRuntimeTokenFile() throws {
        let fileURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("DerpholeLiveReceiveLaunchConfigurationTests-\(UUID().uuidString).txt")
        try " token-789 ".write(to: fileURL, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(at: fileURL) }

        XCTAssertEqual(LiveReceiveLaunchConfiguration.payload(
            from: [:],
            arguments: [],
            fileURL: fileURL
        ), "token-789")
    }
}
