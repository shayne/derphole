import XCTest
@testable import Derphole

final class TokenStoreTests: XCTestCase {
    func testPersistsWebAndTCPButNotCredentials() {
        let suiteName = "TokenStoreTests-\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defer { defaults.removePersistentDomain(forName: suiteName) }
        let store = TokenStore(defaults: defaults)

        store.webToken = "web-token-for-test"
        store.tcpToken = "tcp-token-for-test"

        XCTAssertEqual(TokenStore(defaults: defaults).webToken, "web-token-for-test")
        XCTAssertEqual(TokenStore(defaults: defaults).tcpToken, "tcp-token-for-test")
        XCTAssertNil(defaults.string(forKey: "sshUsername"))
        XCTAssertNil(defaults.string(forKey: "sshPassword"))
    }

    func testClearsTokensWhenSetToNil() {
        let suiteName = "TokenStoreTests-\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defer { defaults.removePersistentDomain(forName: suiteName) }
        let store = TokenStore(defaults: defaults)

        store.webToken = "web-token-for-test"
        store.tcpToken = "tcp-token-for-test"
        store.webToken = nil
        store.tcpToken = nil

        XCTAssertNil(TokenStore(defaults: defaults).webToken)
        XCTAssertNil(TokenStore(defaults: defaults).tcpToken)
    }
}
