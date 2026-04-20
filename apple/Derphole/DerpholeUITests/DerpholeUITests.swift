import XCTest

final class DerpholeUITests: XCTestCase {
    override func setUpWithError() throws {
        continueAfterFailure = false
    }

    @MainActor
    func testLaunchShowsNativeTabsAndMinimalFilesUI() throws {
        let app = XCUIApplication()
        app.launch()

        XCTAssertTrue(app.tabBars.buttons["Files"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.tabBars.buttons["Web"].exists)
        XCTAssertTrue(app.tabBars.buttons["SSH"].exists)
        XCTAssertTrue(app.descendants(matching: .any)["filesTab"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.buttons["filesScanQRCodeButton"].waitForExistence(timeout: 5))
        XCTAssertFalse(app.textFields["filesDebugPayloadField"].exists)

        app.tabBars.buttons["Web"].tap()
        XCTAssertTrue(app.descendants(matching: .any)["webTab"].waitForExistence(timeout: 5))

        app.tabBars.buttons["SSH"].tap()
        XCTAssertTrue(app.descendants(matching: .any)["sshTab"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.buttons["sshScanQRCodeButton"].waitForExistence(timeout: 5))
    }

    @MainActor
    func testDebugPayloadControlsAreHiddenUnlessLaunchModeRequestsThem() throws {
        let app = XCUIApplication()
        app.launchArguments.append("--derphole-debug-payload-controls")
        app.launch()

        XCTAssertTrue(app.descendants(matching: .any)["filesTab"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.textFields["filesDebugPayloadField"].waitForExistence(timeout: 5))
    }

    @MainActor
    func testScanButtonPresentsModalScanner() throws {
        let app = XCUIApplication()
        addUIInterruptionMonitor(withDescription: "Camera permission") { alert in
            let button = alert.buttons.element(boundBy: 0)
            if button.exists {
                button.tap()
                return true
            }
            return false
        }
        app.launch()
        app.tap()

        let scanButton = app.buttons["filesScanQRCodeButton"]
        XCTAssertTrue(scanButton.waitForExistence(timeout: 5))
        scanButton.tap()

        XCTAssertTrue(app.otherElements["filesScannerSheet"].waitForExistence(timeout: 10))
    }

    @MainActor
    func testLiveWebTunnelPayloadLoadsFixtureMarker() throws {
        let environment = ProcessInfo.processInfo.environment
        let arguments = ProcessInfo.processInfo.arguments
        guard let payload = runtimeValue(
            environmentKey: "DERPHOLE_LIVE_WEB_PAYLOAD",
            argument: "--derphole-live-web-payload",
            environment: environment,
            arguments: arguments
        ),
              !payload.isEmpty,
              !payload.hasPrefix("$(") else {
            throw XCTSkip("DERPHOLE_LIVE_WEB_PAYLOAD is only set by the live web tunnel harness.")
        }
        guard let marker = runtimeValue(
            environmentKey: "DERPHOLE_LIVE_WEB_MARKER",
            argument: "--derphole-live-web-marker",
            environment: environment,
            arguments: arguments
        ),
              !marker.isEmpty,
              !marker.hasPrefix("$(") else {
            throw XCTSkip("DERPHOLE_LIVE_WEB_MARKER is only set by the live web tunnel harness.")
        }

        let app = XCUIApplication()
        app.launchEnvironment["DERPHOLE_LIVE_WEB_PAYLOAD"] = payload
        app.launchEnvironment["DERPHOLE_LIVE_WEB_MARKER"] = marker
        app.launchArguments.append("--derphole-live-web-payload")
        app.launchArguments.append(payload)
        app.launch()

        XCTAssertTrue(
            app.descendants(matching: .any)["webBrowserView"].waitForExistence(timeout: 45),
            "Web browser did not open after live web payload injection.\n\(app.debugDescription)"
        )

        let exactMarker = app.staticTexts[marker]
        if !exactMarker.waitForExistence(timeout: 45) {
            XCTAssertTrue(
                app.webViews.staticTexts[marker].waitForExistence(timeout: 10),
                "WKWebView did not expose fixture marker \(marker).\n\(app.debugDescription)"
            )
        }
    }

    private func runtimeValue(
        environmentKey: String,
        argument: String,
        environment: [String: String],
        arguments: [String]
    ) -> String? {
        if let index = arguments.firstIndex(of: argument) {
            let valueIndex = arguments.index(after: index)
            if valueIndex < arguments.endIndex {
                return trimmedValue(arguments[valueIndex])
            }
        }
        return trimmedValue(environment[environmentKey] ?? "")
    }

    private func trimmedValue(_ value: String) -> String? {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }
}
