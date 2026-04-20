import XCTest
@testable import Derphole

final class LiveSSHLaunchConfigurationTests: XCTestCase {
    func testPayloadCanComeFromRuntimeEnvironment() {
        XCTAssertNil(LiveSSHLaunchConfiguration.payload(
            from: ["DERPHOLE_LIVE_SSH_PAYLOAD": "   "],
            arguments: []
        ))

        XCTAssertEqual(LiveSSHLaunchConfiguration.payload(
            from: ["DERPHOLE_LIVE_SSH_PAYLOAD": " derphole://tcp?token=runtime-token&v=1 "],
            arguments: []
        ), "derphole://tcp?token=runtime-token&v=1")
    }

    func testPayloadCanComeFromRuntimeLaunchArgument() {
        XCTAssertEqual(LiveSSHLaunchConfiguration.payload(
            from: [:],
            arguments: [
                "Derphole",
                "--derphole-live-ssh-payload",
                " derphole://tcp?token=runtime-argument&v=1 "
            ]
        ), "derphole://tcp?token=runtime-argument&v=1")
    }

    @MainActor
    func testAppInitialTabUsesSSHPayloadBeforeWebPayload() {
        XCTAssertEqual(LiveAppLaunchConfiguration.initialTab(
            environment: [
                "DERPHOLE_LIVE_WEB_PAYLOAD": "derphole://web?token=runtime-web&v=1",
                "DERPHOLE_LIVE_SSH_PAYLOAD": "derphole://tcp?token=runtime-ssh&v=1"
            ],
            arguments: []
        ), .ssh)
        XCTAssertEqual(LiveAppLaunchConfiguration.initialTab(
            environment: ["DERPHOLE_LIVE_WEB_PAYLOAD": "derphole://web?token=runtime-web&v=1"],
            arguments: []
        ), .web)
        XCTAssertEqual(LiveAppLaunchConfiguration.initialTab(environment: [:], arguments: []), .files)
    }
}
