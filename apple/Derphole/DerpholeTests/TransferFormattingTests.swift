import XCTest
@testable import Derphole

final class TransferFormattingTests: XCTestCase {
    func testFormatsMiBAndSpeed() {
        XCTAssertEqual(TransferFormatting.mib(1_048_576), "1.0 MiB")
        XCTAssertEqual(TransferFormatting.mib(1_572_864), "1.5 MiB")
        XCTAssertEqual(TransferFormatting.speed(bytesPerSecond: 2_097_152), "2.0 MiB/s")
        XCTAssertEqual(TransferFormatting.speed(bytesPerSecond: 0), "0.0 MiB/s")

        let token = "token_abcdefghijklmnopqrstuvwxyz"
        let fingerprint = TransferFormatting.fingerprint(token)
        XCTAssertLessThan(fingerprint.count, token.count)
        XCTAssertTrue(fingerprint.hasPrefix("token_"))
        XCTAssertTrue(fingerprint.hasSuffix("wxyz"))
    }

    func testFingerprintKeepsShortTokensReadable() {
        XCTAssertEqual(TransferFormatting.fingerprint("short-token"), "short-token")
    }
}
