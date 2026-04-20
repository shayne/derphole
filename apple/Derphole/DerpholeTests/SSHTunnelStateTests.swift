import XCTest
@testable import Derphole

final class SSHTunnelStateTests: XCTestCase {
    @MainActor
    func testAcceptingTCPPayloadPersistsTokenAndPromptsForCredentialsOnlyInMemory() {
        let suiteName = "SSHTunnelStateTests-\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defer { defaults.removePersistentDomain(forName: suiteName) }
        let store = TokenStore(defaults: defaults)
        let connector = RecordingSSHConnector(session: RecordingSSHTerminalSession())
        let state = SSHTunnelState(tokenStore: store, connectorFactory: { connector })

        state.acceptScannedPayload("derphole://tcp?token=dtc1_tcp_token&v=1")

        XCTAssertEqual(store.tcpToken, "dtc1_tcp_token")
        XCTAssertEqual(state.rememberedTokenFingerprint, TransferFormatting.fingerprint("dtc1_tcp_token"))
        XCTAssertTrue(state.isCredentialPromptPresented)
        XCTAssertFalse(state.isConnecting)
        XCTAssertFalse(state.isConnected)
        XCTAssertEqual(state.username, "")
        XCTAssertEqual(state.password, "")
        XCTAssertNil(defaults.string(forKey: "sshUsername"))
        XCTAssertNil(defaults.string(forKey: "sshPassword"))
        XCTAssertNil(connector.connectedToken)
    }

    @MainActor
    func testNonTCPPayloadIsRejected() {
        let suiteName = "SSHTunnelStateTests-\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defer { defaults.removePersistentDomain(forName: suiteName) }
        let store = TokenStore(defaults: defaults)
        let connector = RecordingSSHConnector(session: RecordingSSHTerminalSession())
        let state = SSHTunnelState(tokenStore: store, connectorFactory: { connector })

        state.acceptScannedPayload("derphole://web?path=%2F&scheme=http&token=dtc1_web_token&v=1")

        XCTAssertNil(store.tcpToken)
        XCTAssertFalse(state.isCredentialPromptPresented)
        XCTAssertEqual(state.statusText, "Scanned code was not an SSH tunnel.")
        XCTAssertEqual(state.errorText, "Scan a Derphole TCP tunnel QR code.")
        XCTAssertNil(connector.connectedToken)
    }

    @MainActor
    func testDisconnectClearsTransientCredentialsAndKeepsRememberedToken() async {
        let suiteName = "SSHTunnelStateTests-\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defer { defaults.removePersistentDomain(forName: suiteName) }
        let store = TokenStore(defaults: defaults)
        store.tcpToken = "dtc1_remembered"
        let session = RecordingSSHTerminalSession()
        let connector = RecordingSSHConnector(session: session)
        let state = SSHTunnelState(tokenStore: store, connectorFactory: { connector })

        state.reconnect()
        state.username = "shayne"
        state.password = "secret"
        await state.submitCredentials()
        state.disconnect()

        XCTAssertEqual(store.tcpToken, "dtc1_remembered")
        XCTAssertTrue(session.closeCalled)
        XCTAssertEqual(state.username, "")
        XCTAssertEqual(state.password, "")
        XCTAssertFalse(state.isCredentialPromptPresented)
        XCTAssertFalse(state.isConnecting)
        XCTAssertFalse(state.isConnected)
    }

    @MainActor
    func testSubmittingCredentialsCallsConnectorAndClearsCredentialsOnPlaceholderFailure() async {
        let suiteName = "SSHTunnelStateTests-\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defer { defaults.removePersistentDomain(forName: suiteName) }
        let store = TokenStore(defaults: defaults)
        store.tcpToken = "dtc1_tcp_token"
        let connector = RecordingSSHConnector(error: SSHConnectionError.terminalIntegrationPending)
        let state = SSHTunnelState(tokenStore: store, connectorFactory: { connector })

        state.reconnect()
        state.username = "shayne"
        state.password = "secret"
        await state.submitCredentials()

        XCTAssertEqual(connector.connectedToken, "dtc1_tcp_token")
        XCTAssertEqual(connector.connectedUsername, "shayne")
        XCTAssertEqual(connector.connectedPassword, "secret")
        XCTAssertEqual(state.username, "")
        XCTAssertEqual(state.password, "")
        XCTAssertFalse(state.isCredentialPromptPresented)
        XCTAssertFalse(state.isConnecting)
        XCTAssertFalse(state.isConnected)
        XCTAssertEqual(state.statusText, "Terminal integration pending.")
        XCTAssertEqual(state.errorText, "Terminal integration pending.")
        XCTAssertNil(defaults.string(forKey: "sshUsername"))
        XCTAssertNil(defaults.string(forKey: "sshPassword"))
    }

    @MainActor
    func testSubmittingCredentialsPublishesTerminalSessionOnSuccess() async {
        let suiteName = "SSHTunnelStateTests-\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defer { defaults.removePersistentDomain(forName: suiteName) }
        let store = TokenStore(defaults: defaults)
        store.tcpToken = "dtc1_tcp_token"
        let session = RecordingSSHTerminalSession()
        let connector = RecordingSSHConnector(session: session)
        let state = SSHTunnelState(tokenStore: store, connectorFactory: { connector })

        state.reconnect()
        state.username = "shayne"
        state.password = "secret"
        await state.submitCredentials()

        XCTAssertEqual(connector.connectedToken, "dtc1_tcp_token")
        XCTAssertEqual(connector.connectedUsername, "shayne")
        XCTAssertEqual(connector.connectedPassword, "secret")
        XCTAssertTrue(state.terminalSession === session)
        XCTAssertTrue(state.isConnected)
        XCTAssertFalse(state.isConnecting)
        XCTAssertEqual(state.statusText, "SSH terminal connected.")
        XCTAssertEqual(state.username, "")
        XCTAssertEqual(state.password, "")
    }

    @MainActor
    func testTerminalExitReturnsToReconnectScreenAndKeepsRememberedToken() async {
        let suiteName = "SSHTunnelStateTests-\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defer { defaults.removePersistentDomain(forName: suiteName) }
        let store = TokenStore(defaults: defaults)
        store.tcpToken = "dtc1_tcp_token"
        let session = RecordingSSHTerminalSession()
        let state = SSHTunnelState(tokenStore: store, connectorFactory: { RecordingSSHConnector(session: session) })

        state.reconnect()
        state.username = "shayne"
        state.password = "secret"
        await state.submitCredentials()
        state.terminalExited()

        XCTAssertNil(state.terminalSession)
        XCTAssertFalse(state.isConnected)
        XCTAssertFalse(state.isConnecting)
        XCTAssertEqual(state.statusText, "SSH session ended.")
        XCTAssertEqual(store.tcpToken, "dtc1_tcp_token")
        XCTAssertNotNil(state.rememberedTokenFingerprint)
    }

    @MainActor
    func testCredentialSheetDismissalAfterSubmitDoesNotClearBoundaryMessage() async {
        let suiteName = "SSHTunnelStateTests-\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defer { defaults.removePersistentDomain(forName: suiteName) }
        let store = TokenStore(defaults: defaults)
        store.tcpToken = "dtc1_tcp_token"
        let connector = RecordingSSHConnector(error: SSHConnectionError.terminalIntegrationPending)
        let state = SSHTunnelState(tokenStore: store, connectorFactory: { connector })

        state.reconnect()
        state.username = "shayne"
        state.password = "secret"
        await state.submitCredentials()
        state.credentialPromptDismissed()

        XCTAssertEqual(state.statusText, "Terminal integration pending.")
        XCTAssertEqual(state.errorText, "Terminal integration pending.")
    }

    @MainActor
    func testDisconnectBeforeConnectorCompletesKeepsDisconnectedState() async {
        let suiteName = "SSHTunnelStateTests-\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defer { defaults.removePersistentDomain(forName: suiteName) }
        let store = TokenStore(defaults: defaults)
        store.tcpToken = "dtc1_tcp_token"
        let connector = DelayedSSHConnector()
        let state = SSHTunnelState(tokenStore: store, connectorFactory: { connector })

        state.reconnect()
        state.username = "shayne"
        state.password = "secret"
        let submitTask = Task {
            await state.submitCredentials()
        }
        await fulfillment(of: [connector.startedExpectation], timeout: 2)

        state.disconnect()
        connector.succeed()
        await submitTask.value

        XCTAssertTrue(connector.disconnectCalled)
        XCTAssertFalse(state.isConnected)
        XCTAssertFalse(state.isConnecting)
        XCTAssertEqual(state.statusText, "Disconnected.")
        XCTAssertNil(state.errorText)
        XCTAssertEqual(state.username, "")
        XCTAssertEqual(state.password, "")
        XCTAssertEqual(store.tcpToken, "dtc1_tcp_token")
    }

    @MainActor
    func testCancelCredentialPromptClearsValidationError() async {
        let suiteName = "SSHTunnelStateTests-\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defer { defaults.removePersistentDomain(forName: suiteName) }
        let store = TokenStore(defaults: defaults)
        store.tcpToken = "dtc1_tcp_token"
        let state = SSHTunnelState(tokenStore: store, connectorFactory: { RecordingSSHConnector() })

        state.reconnect()
        await state.submitCredentials()
        state.cancelCredentialPrompt()

        XCTAssertEqual(state.statusText, "Ready.")
        XCTAssertNil(state.errorText)
    }
}

@MainActor
final class TerminalInputTranslatorTests: XCTestCase {
    func testSoftwareKeyboardReturnBecomesTerminalEnterKey() {
        XCTAssertEqual(TerminalInputTranslator.insertOperation(for: "\n"), .key(.enter))
    }

    func testSoftwareKeyboardTabBecomesTerminalTabKey() {
        XCTAssertEqual(TerminalInputTranslator.insertOperation(for: "\t"), .key(.tab))
    }

    func testSoftwareKeyboardBackspaceBecomesTerminalBackspaceKey() {
        XCTAssertEqual(TerminalInputTranslator.deleteOperation(), .key(.backspace))
    }

    func testPastedMultilineInputNormalizesLineEndingsForTerminal() {
        XCTAssertEqual(TerminalInputTranslator.insertOperation(for: "pwd\nwhoami\r\n"), .text("pwd\rwhoami\r"))
    }
}

nonisolated private final class RecordingSSHConnector: SSHLocalTunnelConnecting {
    private let error: Error?
    private let session: RecordingSSHTerminalSession?

    private(set) var connectedToken: String?
    private(set) var connectedUsername: String?
    private(set) var connectedPassword: String?
    private(set) var disconnectCalled = false

    init(error: Error? = nil, session: RecordingSSHTerminalSession? = nil) {
        self.error = error
        self.session = session
    }

    func connect(token: String, username: String, password: String) async throws -> SSHConnectedTerminalSession {
        connectedToken = token
        connectedUsername = username
        connectedPassword = password
        if let error {
            throw error
        }
        return session ?? RecordingSSHTerminalSession()
    }

    func disconnect() {
        disconnectCalled = true
    }
}

nonisolated private final class DelayedSSHConnector: SSHLocalTunnelConnecting {
    let startedExpectation = XCTestExpectation(description: "ssh connector started")
    private var continuation: CheckedContinuation<Void, Error>?
    private(set) var disconnectCalled = false

    func connect(token: String, username: String, password: String) async throws -> SSHConnectedTerminalSession {
        startedExpectation.fulfill()
        try await withCheckedThrowingContinuation { continuation in
            self.continuation = continuation
        }
        return RecordingSSHTerminalSession()
    }

    func disconnect() {
        disconnectCalled = true
    }

    func succeed() {
        continuation?.resume(returning: ())
        continuation = nil
    }
}

nonisolated private final class RecordingSSHTerminalSession: SSHConnectedTerminalSession, @unchecked Sendable {
    let output = AsyncStream<Data> { continuation in
        continuation.finish()
    }

    private(set) var writes: [Data] = []
    private(set) var resizeRequests: [(cols: Int, rows: Int)] = []
    private(set) var closeCalled = false

    func write(_ data: Data) async throws {
        writes.append(data)
    }

    func resize(cols: Int, rows: Int) async throws {
        resizeRequests.append((cols: cols, rows: rows))
    }

    func close() {
        closeCalled = true
    }
}
