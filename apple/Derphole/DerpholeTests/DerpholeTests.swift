import XCTest
@testable import Derphole

final class DerpholeTests: XCTestCase {
    @MainActor
    func testInitialStateIsIdle() {
        let state = TransferState()

        XCTAssertEqual(state.phase, .idle)
        XCTAssertEqual(state.statusText, "Ready.")
        XCTAssertEqual(state.route, .unknown)
        XCTAssertEqual(state.pastedPayload, "")
        XCTAssertEqual(state.validatedToken, "")
        XCTAssertNil(state.completedFileURL)
        XCTAssertNil(state.errorText)
        XCTAssertNil(state.progressFraction)
        XCTAssertFalse(state.isReceiving)
        XCTAssertFalse(state.canValidatePayload)
        XCTAssertFalse(state.canStartReceive)
        XCTAssertFalse(state.canExport)
        XCTAssertTrue(state.canStartScan)
    }

    @MainActor
    func testScanStartedSetsScanningState() {
        let state = TransferState()
        state.pastedPayload = "raw-token-123"
        state.validatePastedPayload()
        XCTAssertEqual(state.validatedToken, "raw-token-123")

        state.scanStarted()

        XCTAssertEqual(state.phase, .scanning)
        XCTAssertEqual(state.statusText, "Scanning for QR code.")
        XCTAssertEqual(state.statusSummary, "Scanning")
        XCTAssertEqual(state.route, .unknown)
        XCTAssertEqual(state.validatedToken, "")
        XCTAssertEqual(state.progressCurrent, 0)
        XCTAssertEqual(state.progressTotal, 0)
        XCTAssertNil(state.completedFileURL)
        XCTAssertNil(state.progressFraction)
        XCTAssertNil(state.errorText)
        XCTAssertTrue(state.canStartScan)
    }

    @MainActor
    func testCancelSetsCanceledState() {
        let state = TransferState()

        state.cancel()

        XCTAssertEqual(state.phase, .canceled)
        XCTAssertEqual(state.statusText, "Receive canceled.")
        XCTAssertEqual(state.statusSummary, "Receive canceled")
        XCTAssertNil(state.errorText)
    }

    @MainActor
    func testValidatePastedPayloadAcceptsRawToken() {
        let state = TransferState()
        state.pastedPayload = "  raw-token-123  "

        XCTAssertTrue(state.canValidatePayload)

        state.validatePastedPayload()

        XCTAssertEqual(state.phase, .idle)
        XCTAssertEqual(state.statusText, "Payload looks valid.")
        XCTAssertEqual(state.validatedToken, "raw-token-123")
        XCTAssertNil(state.errorText)
    }

    @MainActor
    func testCancelReceiveUsesCanceledState() {
        let state = TransferState()
        state.pastedPayload = "token-789"
        state.validatePastedPayload()

        state.cancelReceive()

        XCTAssertEqual(state.phase, .canceled)
        XCTAssertEqual(state.statusText, "Receive canceled.")
        XCTAssertEqual(state.validatedToken, "token-789")
        XCTAssertNil(state.errorText)
        XCTAssertFalse(state.isReceiving)
    }

    @MainActor
    func testInvalidScannedPayloadThenCorrectedValidation() {
        let state = TransferState()

        state.receiveScannedPayload("http://example.com")

        XCTAssertEqual(state.phase, .failed)
        XCTAssertEqual(state.statusText, "Scanned code was invalid.")
        XCTAssertEqual(state.pastedPayload, "http://example.com")
        XCTAssertEqual(state.validatedToken, "")
        XCTAssertNotNil(state.errorText)

        state.pastedPayload = "derphole://receive?v=1&token=token-123"
        state.notePastedPayloadEdited()

        XCTAssertEqual(state.phase, .idle)
        XCTAssertEqual(state.statusText, "Ready.")
        XCTAssertNil(state.errorText)

        state.validatePastedPayload()

        XCTAssertEqual(state.phase, .idle)
        XCTAssertEqual(state.statusText, "Payload looks valid.")
        XCTAssertEqual(state.validatedToken, "token-123")
        XCTAssertNil(state.errorText)
    }
}
