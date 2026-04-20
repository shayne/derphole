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

    @MainActor
    func testLiveSSHTunnelPayloadOpensTerminal() throws {
        let environment = ProcessInfo.processInfo.environment
        let arguments = ProcessInfo.processInfo.arguments
        guard let payload = runtimeValue(
            environmentKey: "DERPHOLE_LIVE_SSH_PAYLOAD",
            argument: "--derphole-live-ssh-payload",
            environment: environment,
            arguments: arguments
        ),
              !payload.isEmpty,
              !payload.hasPrefix("$(") else {
            throw XCTSkip("DERPHOLE_LIVE_SSH_PAYLOAD is only set by the live SSH tunnel harness.")
        }
        guard let username = runtimeValue(
            environmentKey: "DERPHOLE_LIVE_SSH_USERNAME",
            argument: "--derphole-live-ssh-username",
            environment: environment,
            arguments: arguments
        ),
              let password = runtimeValue(
                environmentKey: "DERPHOLE_LIVE_SSH_PASSWORD",
                argument: "--derphole-live-ssh-password",
                environment: environment,
                arguments: arguments
        ) else {
            throw XCTSkip("DERPHOLE_LIVE_SSH_USERNAME/PASSWORD are only set by the live SSH tunnel harness.")
        }
        let inputProbe = runtimeValue(
            environmentKey: "DERPHOLE_LIVE_SSH_INPUT_PROBE",
            argument: "--derphole-live-ssh-input-probe",
            environment: environment,
            arguments: arguments
        )

        let app = XCUIApplication()
        app.launchEnvironment["DERPHOLE_LIVE_SSH_PAYLOAD"] = payload
        app.launchArguments.append("--derphole-live-ssh-payload")
        app.launchArguments.append(payload)
        app.launch()

        XCTAssertTrue(app.descendants(matching: .any)["sshTab"].waitForExistence(timeout: 10))
        XCTAssertTrue(app.descendants(matching: .any)["sshCredentialPrompt"].waitForExistence(timeout: 20))

        let usernameField = app.textFields["sshUsernameField"]
        XCTAssertTrue(usernameField.waitForExistence(timeout: 10))
        usernameField.tap()
        usernameField.typeText(username)

        let passwordField = app.secureTextFields["sshPasswordField"]
        XCTAssertTrue(passwordField.waitForExistence(timeout: 10))
        passwordField.tap()
        passwordField.typeText(password)

        let connectButton = app.buttons["sshCredentialConnectButton"]
        XCTAssertTrue(connectButton.waitForExistence(timeout: 10))
        connectButton.tap()

        let terminalView = app.descendants(matching: .any)["sshTerminalView"]
        let terminalTextView = app.textViews["SSH Terminal"]
        let deadline = Date().addingTimeInterval(45)
        while Date() < deadline {
            if terminalView.exists || terminalTextView.exists {
                if let inputProbe {
                    try sendLiveSSHInputProbe(
                        app: app,
                        probe: inputProbe,
                        terminalView: terminalView,
                        terminalTextView: terminalTextView
                    )
                }
                return
            }
            RunLoop.current.run(until: Date().addingTimeInterval(0.25))
        }

        XCTFail("SSH terminal did not appear after live payload injection.\n\(app.debugDescription)")
    }

    @MainActor
    private func sendLiveSSHInputProbe(
        app: XCUIApplication,
        probe: String,
        terminalView: XCUIElement,
        terminalTextView: XCUIElement
    ) throws {
        let terminal = terminalView.exists ? terminalView : terminalTextView
        terminal.tap()
        XCTAssertTrue(app.keyboards.firstMatch.waitForExistence(timeout: 10), "SSH terminal did not focus the software keyboard.\n\(app.debugDescription)")

        app.typeText("\(probe)-software")
        tapKeyboardReturn(app: app)

        app.typeText("\(probe)-software-backspaceX")
        try tapKeyboardBackspace(app: app)
        app.typeText("d")
        tapKeyboardReturn(app: app)
    }

    @MainActor
    private func tapKeyboardReturn(app: XCUIApplication) {
        let keyboardReturn = app.keyboards.buttons["return"]
        if keyboardReturn.waitForExistence(timeout: 3) {
            keyboardReturn.tap()
        } else {
            app.typeText("\n")
        }
    }

    @MainActor
    private func tapKeyboardBackspace(app: XCUIApplication) throws {
        let keyboard = app.keyboards.firstMatch
        XCTAssertTrue(keyboard.waitForExistence(timeout: 5), "Software keyboard was not visible.\n\(app.debugDescription)")

        let candidates = [
            keyboard.keys[XCUIKeyboardKey.delete.rawValue],
            keyboard.keys["delete"],
            keyboard.keys["Delete"],
            keyboard.buttons[XCUIKeyboardKey.delete.rawValue],
            keyboard.buttons["delete"],
            keyboard.buttons["Delete"]
        ]
        for candidate in candidates where candidate.waitForExistence(timeout: 1) {
            candidate.tap()
            return
        }

        XCTFail("Software keyboard Backspace key was not found.\n\(app.debugDescription)")
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
