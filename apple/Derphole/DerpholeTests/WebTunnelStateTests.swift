import XCTest
@testable import Derphole

final class WebTunnelStateTests: XCTestCase {
    @MainActor
    func testAcceptingWebPayloadPersistsTokenAndBuildsBrowserURLAfterBind() async throws {
        let suiteName = "WebTunnelStateTests-\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defer { defaults.removePersistentDomain(forName: suiteName) }
        let store = TokenStore(defaults: defaults)
        let opener = RecordingWebTunnelOpener(boundAddr: "127.0.0.1:49281")
        let state = WebTunnelState(tokenStore: store, tunnelOpenerFactory: { opener })

        state.acceptScannedPayload("derphole://web?path=%2Fadmin&scheme=http&token=dtc1_web_token&v=1")
        await fulfillment(of: [opener.openedExpectation], timeout: 2)
        await Task.yield()

        XCTAssertEqual(store.webToken, "dtc1_web_token")
        XCTAssertEqual(opener.openedToken, "dtc1_web_token")
        XCTAssertEqual(opener.openedListenAddr, "127.0.0.1:0")
        XCTAssertEqual(state.boundAddr, "127.0.0.1:49281")
        XCTAssertEqual(state.browserURL?.absoluteString, "http://127.0.0.1:49281/admin")
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

        state.acceptScannedPayload("derphole://web?path=%2Fadmin&scheme=http&token=dtc1_web_token&v=1")
        await fulfillment(of: [opener.openedExpectation], timeout: 2)
        await Task.yield()

        state.disconnect()

        XCTAssertEqual(store.webToken, "dtc1_web_token")
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

        state.acceptScannedPayload("derphole://tcp?token=dtc1_tcp_token&v=1")

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
        store.webToken = "dtc1_remembered"
        let opener = RecordingWebTunnelOpener(boundAddr: "127.0.0.1:49284")
        let state = WebTunnelState(tokenStore: store, tunnelOpenerFactory: { opener })

        state.reconnect()
        await fulfillment(of: [opener.openedExpectation], timeout: 2)
        await Task.yield()

        XCTAssertEqual(opener.openedToken, "dtc1_remembered")
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

        state.acceptScannedPayload("derphole://web?path=%2Fadmin&scheme=http&token=dtc1_web_token&v=1")
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
            environment: ["DERPHOLE_LIVE_WEB_PAYLOAD": " derphole://web?path=%2Fprobe&scheme=http&token=dtc1_runtime_web&v=1 "],
            arguments: []
        )
        await fulfillment(of: [opener.openedExpectation], timeout: 2)
        await Task.yield()

        state.openRuntimeInjectedPayloadIfConfigured(
            environment: ["DERPHOLE_LIVE_WEB_PAYLOAD": " derphole://web?path=%2Fsecond&scheme=http&token=dtc1_second_web&v=1 "],
            arguments: []
        )

        XCTAssertEqual(store.webToken, "dtc1_runtime_web")
        XCTAssertEqual(opener.openedToken, "dtc1_runtime_web")
        XCTAssertEqual(opener.openCallCount, 1)
        XCTAssertEqual(state.browserURL?.absoluteString, "http://127.0.0.1:49286/probe")
    }
}

nonisolated private final class RecordingWebTunnelOpener: WebTunnelOpening, @unchecked Sendable {
    let openedExpectation = XCTestExpectation(description: "web tunnel opened")
    private let boundAddrToReport: String

    private(set) var openedToken: String?
    private(set) var openedListenAddr: String?
    private(set) var cancelCalled = false
    private(set) var openCallCount = 0

    init(boundAddr: String) {
        self.boundAddrToReport = boundAddr
    }

    func open(token: String, listenAddr: String, callbacks: WebTunnelCallbacks) throws {
        openCallCount += 1
        openedToken = token
        openedListenAddr = listenAddr

        callbacks.status("connected-direct")
        callbacks.boundAddr(boundAddrToReport)
        openedExpectation.fulfill()
    }

    func cancel() {
        cancelCalled = true
    }
}
