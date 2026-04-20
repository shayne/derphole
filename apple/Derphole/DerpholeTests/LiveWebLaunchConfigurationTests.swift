import XCTest
@testable import Derphole

final class LiveWebLaunchConfigurationTests: XCTestCase {
    func testPayloadCanComeFromRuntimeEnvironment() {
        XCTAssertNil(LiveWebLaunchConfiguration.payload(
            from: ["DERPHOLE_LIVE_WEB_PAYLOAD": "   "],
            arguments: []
        ))

        XCTAssertEqual(LiveWebLaunchConfiguration.payload(
            from: ["DERPHOLE_LIVE_WEB_PAYLOAD": " derphole://web?token=runtime-token&v=1 "],
            arguments: []
        ), "derphole://web?token=runtime-token&v=1")
    }

    func testPayloadCanComeFromRuntimeLaunchArgument() {
        XCTAssertEqual(LiveWebLaunchConfiguration.payload(
            from: [:],
            arguments: [
                "Derphole",
                "--derphole-live-web-payload",
                " derphole://web?token=runtime-argument&v=1 "
            ]
        ), "derphole://web?token=runtime-argument&v=1")
    }

    @MainActor
    func testInitialTabUsesWebWhenPayloadExists() {
        XCTAssertEqual(LiveWebLaunchConfiguration.initialTab(
            environment: ["DERPHOLE_LIVE_WEB_PAYLOAD": "derphole://web?token=runtime-token&v=1"],
            arguments: []
        ), .web)
        XCTAssertEqual(LiveWebLaunchConfiguration.initialTab(environment: [:], arguments: []), .files)
    }
}
