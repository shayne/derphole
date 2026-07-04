import XCTest
@testable import Derphole

final class WebTunnelStateTests: XCTestCase {
    @MainActor
    func testAcceptingLegacyWebPayloadPersistsTokenAndBuildsBrowserURLAfterBind() async throws {
        let suiteName = "WebTunnelStateTests-\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defer { defaults.removePersistentDomain(forName: suiteName) }
        let store = TokenStore(defaults: defaults)
        let opener = RecordingWebTunnelOpener(boundAddr: "127.0.0.1:49281")
        let state = WebTunnelState(tokenStore: store, tunnelOpenerFactory: { opener })

        state.acceptScannedPayload("derphole://web?path=%2Fadmin&scheme=http&token=web-token-for-test&v=1")
        await fulfillment(of: [opener.openedExpectation], timeout: 2)
        await Task.yield()

        XCTAssertEqual(store.webToken, "web-token-for-test")
        XCTAssertEqual(opener.openedToken, "web-token-for-test")
        XCTAssertEqual(opener.openedListenAddr, "127.0.0.1:0")
        XCTAssertEqual(state.boundAddr, "127.0.0.1:49281")
        XCTAssertEqual(state.browserURL?.absoluteString, "http://127.0.0.1:49281/admin")
        XCTAssertTrue(state.isConnected)
        XCTAssertFalse(state.isConnecting)
    }

    @MainActor
    func testAcceptingGenericTCPPayloadPersistsTokenAndUsesHTTPDefaults() async throws {
        let suiteName = "WebTunnelStateTests-\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defer { defaults.removePersistentDomain(forName: suiteName) }
        let store = TokenStore(defaults: defaults)
        let opener = RecordingWebTunnelOpener(boundAddr: "127.0.0.1:49280")
        let state = WebTunnelState(tokenStore: store, tunnelOpenerFactory: { opener })

        state.acceptScannedPayload("derphole://tcp?token=web-token-for-test&v=1")
        await fulfillment(of: [opener.openedExpectation], timeout: 2)
        await Task.yield()

        XCTAssertEqual(store.webToken, "web-token-for-test")
        XCTAssertEqual(opener.openedToken, "web-token-for-test")
        XCTAssertEqual(state.browserURL?.absoluteString, "http://127.0.0.1:49280/")
        XCTAssertTrue(state.isConnected)
        XCTAssertFalse(state.isConnecting)
    }

    @MainActor
    func testDisconnectKeepsRememberedTokenAndMarksDisconnected() async {
        let suiteName = "WebTunnelStateTests-\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defer { defaults.removePersistentDomain(forName: suiteName) }
        let store = TokenStore(defaults: defaults)
        let opener = RecordingWebTunnelOpener(boundAddr: "127.0.0.1:49282")
        let state = WebTunnelState(tokenStore: store, tunnelOpenerFactory: { opener })

        state.acceptScannedPayload("derphole://tcp?token=web-token-for-test&v=1")
        await fulfillment(of: [opener.openedExpectation], timeout: 2)
        await Task.yield()

        state.disconnect()

        XCTAssertEqual(store.webToken, "web-token-for-test")
        XCTAssertTrue(opener.cancelCalled)
        XCTAssertFalse(state.isConnected)
        XCTAssertFalse(state.isConnecting)
        XCTAssertNil(state.browserURL)
        XCTAssertEqual(state.statusText, "Disconnected.")
    }

    @MainActor
    func testNonWebPayloadsAreRejected() {
        let suiteName = "WebTunnelStateTests-\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defer { defaults.removePersistentDomain(forName: suiteName) }
        let store = TokenStore(defaults: defaults)
        let opener = RecordingWebTunnelOpener(boundAddr: "127.0.0.1:49283")
        let state = WebTunnelState(tokenStore: store, tunnelOpenerFactory: { opener })

        state.acceptScannedPayload("derphole://file?token=file-token&v=1")

        XCTAssertNil(store.webToken)
        XCTAssertNil(opener.openedToken)
        XCTAssertEqual(state.statusText, "Scanned code was not a web tunnel.")
        XCTAssertNotNil(state.errorText)
        XCTAssertFalse(state.isConnected)
        XCTAssertFalse(state.isConnecting)
    }

    @MainActor
    func testReconnectUsesRememberedTokenWithDefaultSchemeAndPath() async {
        let suiteName = "WebTunnelStateTests-\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defer { defaults.removePersistentDomain(forName: suiteName) }
        let store = TokenStore(defaults: defaults)
        store.webToken = "remembered-token-for-test"
        let opener = RecordingWebTunnelOpener(boundAddr: "127.0.0.1:49284")
        let state = WebTunnelState(tokenStore: store, tunnelOpenerFactory: { opener })

        state.reconnect()
        await fulfillment(of: [opener.openedExpectation], timeout: 2)
        await Task.yield()

        XCTAssertEqual(opener.openedToken, "remembered-token-for-test")
        XCTAssertEqual(state.browserURL?.absoluteString, "http://127.0.0.1:49284/")
        XCTAssertTrue(state.isConnected)
    }

    @MainActor
    func testDisconnectBeforeOpenStartsSkipsStaleOpen() async throws {
        let suiteName = "WebTunnelStateTests-\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defer { defaults.removePersistentDomain(forName: suiteName) }
        let store = TokenStore(defaults: defaults)
        let opener = RecordingWebTunnelOpener(boundAddr: "127.0.0.1:49285")
        let state = WebTunnelState(tokenStore: store, tunnelOpenerFactory: { opener })

        state.acceptScannedPayload("derphole://tcp?token=web-token-for-test&v=1")
        state.disconnect()

        try await Task.sleep(nanoseconds: 100_000_000)

        XCTAssertNil(opener.openedToken)
        XCTAssertTrue(opener.cancelCalled)
        XCTAssertFalse(state.isConnected)
        XCTAssertFalse(state.isConnecting)
    }

    @MainActor
    func testRuntimeInjectedPayloadStartsWebTunnelOnce() async throws {
        let suiteName = "WebTunnelStateTests-\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defer { defaults.removePersistentDomain(forName: suiteName) }
        let store = TokenStore(defaults: defaults)
        let opener = RecordingWebTunnelOpener(boundAddr: "127.0.0.1:49286")
        let state = WebTunnelState(tokenStore: store, tunnelOpenerFactory: { opener })

        state.openRuntimeInjectedPayloadIfConfigured(
            environment: ["DERPHOLE_LIVE_WEB_PAYLOAD": " derphole://tcp?token=runtime-web-token-for-test&v=1 "],
            arguments: []
        )
        await fulfillment(of: [opener.openedExpectation], timeout: 2)
        await Task.yield()

        state.openRuntimeInjectedPayloadIfConfigured(
            environment: ["DERPHOLE_LIVE_WEB_PAYLOAD": " derphole://tcp?token=second-web-token-for-test&v=1 "],
            arguments: []
        )

        XCTAssertEqual(store.webToken, "runtime-web-token-for-test")
        XCTAssertEqual(opener.openedToken, "runtime-web-token-for-test")
        XCTAssertEqual(opener.openCallCount, 1)
        XCTAssertEqual(state.browserURL?.absoluteString, "http://127.0.0.1:49286/")
    }

    @MainActor
    func testDuplicateScannedWebPayloadWhileOpeningDoesNotRestartTunnel() async throws {
        let suiteName = "WebTunnelStateTests-\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defer { defaults.removePersistentDomain(forName: suiteName) }
        let store = TokenStore(defaults: defaults)
        var createdOpeners: [RecordingWebTunnelOpener] = []
        let state = WebTunnelState(tokenStore: store, tunnelOpenerFactory: {
            let opener = RecordingWebTunnelOpener(boundAddr: nil)
            createdOpeners.append(opener)
            return opener
        })

        let payload = "derphole://tcp?token=web-token-for-test&v=1"
        state.acceptScannedPayload(payload)
        guard let firstOpener = createdOpeners.first else {
            XCTFail("expected first web tunnel opener")
            return
        }
        await fulfillment(of: [firstOpener.openedExpectation], timeout: 2)

        state.acceptScannedPayload(payload)
        try await Task.sleep(nanoseconds: 100_000_000)

        XCTAssertEqual(createdOpeners.count, 1)
        XCTAssertEqual(firstOpener.openCallCount, 1)
        XCTAssertFalse(firstOpener.cancelCalled)
        XCTAssertTrue(state.isConnecting)
    }

    @MainActor
    func testTestingHelperAcceptsGenericTCPInviteDefaults() {
        let suiteName = "WebTunnelStateTests-\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defer { defaults.removePersistentDomain(forName: suiteName) }
        let store = TokenStore(defaults: defaults)
        let state = WebTunnelState(tokenStore: store, tunnelOpenerFactory: { nil })

        state.acceptPayloadForTesting(kind: "tcp", token: "web-token-for-test")
        state.markBoundForTesting("127.0.0.1:49287")

        XCTAssertEqual(store.webToken, "web-token-for-test")
        XCTAssertEqual(state.browserURL?.absoluteString, "http://127.0.0.1:49287/")
        XCTAssertTrue(state.isConnected)
        XCTAssertFalse(state.isConnecting)
    }
}

nonisolated private final class RecordingWebTunnelOpener: WebTunnelOpening, @unchecked Sendable {
    let openedExpectation = XCTestExpectation(description: "web tunnel opened")
    private let boundAddrToReport: String?

    private(set) var openedToken: String?
    private(set) var openedListenAddr: String?
    private(set) var cancelCalled = false
    private(set) var openCallCount = 0

    init(boundAddr: String?) {
        self.boundAddrToReport = boundAddr
    }

    func open(token: String, listenAddr: String, callbacks: WebTunnelCallbacks) throws {
        openCallCount += 1
        openedToken = token
        openedListenAddr = listenAddr

        callbacks.status("connected-direct")
        if let boundAddrToReport {
            callbacks.boundAddr(boundAddrToReport)
        }
        openedExpectation.fulfill()
    }

    func cancel() {
        cancelCalled = true
    }
}
