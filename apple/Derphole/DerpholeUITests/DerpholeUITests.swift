import XCTest

final class DerpholeUITests: XCTestCase {
    override func setUpWithError() throws {
        continueAfterFailure = false
    }

    @MainActor
    func testLaunchShowsQRFirstUIAndPayloadSupport() throws {
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

        let scanButton = app.buttons["Scan QR Code"]
        XCTAssertTrue(scanButton.waitForExistence(timeout: 5))
        XCTAssertTrue(app.otherElements["qrScannerView"].waitForExistence(timeout: 10))
        XCTAssertTrue(app.otherElements["pastedPayloadSection"].waitForExistence(timeout: 5))

        scanButton.tap()
        XCTAssertTrue(app.staticTexts["Scanning for QR code."].waitForExistence(timeout: 5))

        let payloadField = app.textFields["pastedPayloadField"]
        XCTAssertTrue(payloadField.waitForExistence(timeout: 5))

        payloadField.tap()
        payloadField.typeText("raw-token-123")

        let validateButton = app.buttons["validatePayloadButton"]
        XCTAssertTrue(validateButton.waitForExistence(timeout: 5))
        XCTAssertTrue(validateButton.isEnabled)
        validateButton.tap()

        XCTAssertTrue(app.staticTexts["Payload looks valid."].waitForExistence(timeout: 5))
        XCTAssertTrue(app.buttons["receivePayloadButton"].isEnabled)
        XCTAssertTrue(app.buttons["validatePayloadButton"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.buttons["receivePayloadButton"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.buttons["cancelReceiveButton"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.buttons["exportReceivedFileButton"].waitForExistence(timeout: 5))
    }
}
