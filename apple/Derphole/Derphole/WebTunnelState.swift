import Combine
import DerpholeMobile
import Foundation

nonisolated protocol WebTunnelCallbacks: AnyObject, Sendable {
    func boundAddr(_ addr: String)
    func status(_ status: String)
    func trace(_ trace: String)
}

nonisolated protocol WebTunnelOpening: AnyObject, Sendable {
    func open(token: String, listenAddr: String, callbacks: WebTunnelCallbacks) throws
    func cancel()
}

@MainActor
final class WebTunnelState: ObservableObject {
    enum Route: Equatable {
        case unknown
        case relay
        case direct

        var label: String {
            switch self {
            case .unknown:
                return "Negotiating"
            case .relay:
                return "Relay"
            case .direct:
                return "Direct"
            }
        }
    }

    @Published var isScannerPresented = false
    @Published var isBrowserPresented = false
    @Published private(set) var statusText = "Ready."
    @Published private(set) var errorText: String?
    @Published private(set) var boundAddr: String?
    @Published private(set) var browserURL: URL?
    @Published private(set) var route: Route = .unknown
    @Published private(set) var traceText = ""
    @Published private(set) var isConnecting = false
    @Published private(set) var isConnected = false

    private let tokenStore: TokenStore
    private let tunnelOpenerFactory: () -> WebTunnelOpening?
    private var activeOpener: WebTunnelOpening?
    private var connectionID = UUID()
    private var currentScheme = "http"
    private var currentPath = "/"
    #if DEBUG
    private var runtimeInjectedWebStarted = false
    #endif

    init(
        tokenStore: TokenStore,
        tunnelOpenerFactory: @escaping () -> WebTunnelOpening? = { MobileWebTunnelOpener() }
    ) {
        self.tokenStore = tokenStore
        self.tunnelOpenerFactory = tunnelOpenerFactory
    }

    var rememberedToken: String? {
        tokenStore.webToken
    }

    var rememberedTokenFingerprint: String? {
        guard let token = tokenStore.webToken else { return nil }
        return TransferFormatting.fingerprint(token)
    }

    func scanStarted() {
        guard !isConnecting else { return }
        errorText = nil
        statusText = "Scanning for web tunnel QR code."
        isScannerPresented = true
    }

    func scannerDismissed() {
        isScannerPresented = false
        if !isConnecting, !isConnected {
            statusText = "Ready."
        }
    }

    func acceptScannedPayload(_ payload: String) {
        isScannerPresented = false
        do {
            let parsed = try parseWebPayload(payload)
            tokenStore.webToken = parsed.token
            connect(token: parsed.token, scheme: parsed.scheme, path: parsed.path, openingStatus: "QR code scanned. Opening web tunnel...")
        } catch WebTunnelError.nonWebPayload {
            failBeforeConnect(status: "Scanned code was not a web tunnel.", error: "Scan a Derphole web tunnel QR code.")
        } catch {
            failBeforeConnect(status: "Scanned code was invalid.", error: error.localizedDescription)
        }
    }

    func reconnect() {
        guard let token = tokenStore.webToken?.trimmingCharacters(in: .whitespacesAndNewlines), !token.isEmpty else {
            failBeforeConnect(status: "No remembered web tunnel.", error: "Scan a web tunnel QR code first.")
            return
        }
        connect(token: token, scheme: "http", path: "/", openingStatus: "Reconnecting web tunnel...")
    }

    func disconnect() {
        activeOpener?.cancel()
        activeOpener = nil
        connectionID = UUID()
        isConnecting = false
        isConnected = false
        isBrowserPresented = false
        browserURL = nil
        boundAddr = nil
        route = .unknown
        traceText = ""
        errorText = nil
        statusText = "Disconnected."
    }

    func browserDismissed() {
        isBrowserPresented = false
    }

    #if DEBUG
    func openRuntimeInjectedPayloadIfConfigured(
        environment: [String: String] = ProcessInfo.processInfo.environment,
        arguments: [String] = ProcessInfo.processInfo.arguments
    ) {
        guard !runtimeInjectedWebStarted else { return }
        guard let payload = LiveWebLaunchConfiguration.payload(from: environment, arguments: arguments) else { return }

        runtimeInjectedWebStarted = true
        acceptScannedPayload(payload)
    }

    func acceptPayloadForTesting(kind: String, token: String, scheme: String = "http", path: String = "/") {
        guard kind == "web" else {
            failBeforeConnect(status: "Scanned code was not a web tunnel.", error: "Scan a Derphole web tunnel QR code.")
            return
        }
        tokenStore.webToken = token
        currentScheme = normalizedScheme(scheme)
        currentPath = normalizedPath(path)
        isConnecting = true
        isConnected = false
        statusText = "Opening web tunnel..."
        errorText = nil
    }

    func markBoundForTesting(_ addr: String) {
        handleBoundAddr(addr, connectionID: connectionID)
    }
    #endif

    private func connect(token: String, scheme: String, path: String, openingStatus: String) {
        activeOpener?.cancel()
        guard let opener = tunnelOpenerFactory() else {
            failBeforeConnect(status: "Tunnel initialization failed.", error: "Could not create the Derphole tunnel bridge.")
            return
        }

        let currentConnectionID = UUID()
        connectionID = currentConnectionID
        currentScheme = normalizedScheme(scheme)
        currentPath = normalizedPath(path)
        activeOpener = opener
        isConnecting = true
        isConnected = false
        isBrowserPresented = false
        browserURL = nil
        boundAddr = nil
        route = .unknown
        traceText = ""
        errorText = nil
        statusText = openingStatus

        let callbacks = WebTunnelCallbackAdapter(
            onBoundAddr: { [weak self] addr in
                let state = self
                Task { @MainActor in
                    state?.handleBoundAddr(addr, connectionID: currentConnectionID)
                }
            },
            onStatus: { [weak self] status in
                let state = self
                Task { @MainActor in
                    state?.handleStatus(status, connectionID: currentConnectionID)
                }
            },
            onTrace: { [weak self] trace in
                let state = self
                Task { @MainActor in
                    state?.handleTrace(trace, connectionID: currentConnectionID)
                }
            }
        )

        Task.detached(priority: .userInitiated) { [weak self, opener, callbacks, token] in
            let shouldOpen = await MainActor.run { [weak self] in
                guard let self else { return false }
                return self.connectionID == currentConnectionID && self.activeOpener === opener && self.isConnecting
            }
            guard shouldOpen else {
                opener.cancel()
                return
            }

            do {
                try opener.open(token: token, listenAddr: "127.0.0.1:0", callbacks: callbacks)
            } catch {
                let state = self
                Task { @MainActor in
                    state?.failOpen(error, connectionID: currentConnectionID)
                }
            }
        }
    }

    private func parseWebPayload(_ raw: String) throws -> (token: String, scheme: String, path: String) {
        var error: NSError?
        guard let parsed = DerpholemobileParsePayload(raw, &error) else {
            throw error ?? WebTunnelError.invalidPayload
        }
        if let error {
            throw error
        }
        guard parsed.kind() == "web" else {
            throw WebTunnelError.nonWebPayload
        }
        return (
            token: parsed.token(),
            scheme: parsed.scheme(),
            path: parsed.path()
        )
    }

    private func handleBoundAddr(_ addr: String, connectionID: UUID) {
        guard self.connectionID == connectionID else { return }
        let trimmedAddr = addr.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedAddr.isEmpty else { return }

        boundAddr = trimmedAddr
        browserURL = URL(string: "\(currentScheme)://\(trimmedAddr)\(currentPath)")
        isConnecting = false
        isConnected = true
        isBrowserPresented = browserURL != nil
        if route == .unknown {
            route = .direct
        }
        statusText = "Connected to local web tunnel."
    }

    private func handleStatus(_ status: String, connectionID: UUID) {
        guard self.connectionID == connectionID else { return }
        let normalized = status.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !normalized.isEmpty else { return }

        switch normalized {
        case "connected-relay":
            route = .relay
            statusText = "Connected through relay."
        case "connected-direct":
            route = .direct
            statusText = "Connected directly."
        default:
            statusText = normalized.replacingOccurrences(of: "-", with: " ")
        }
    }

    private func handleTrace(_ trace: String, connectionID: UUID) {
        guard self.connectionID == connectionID else { return }
        let normalized = trace.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !normalized.isEmpty else { return }

        traceText = normalized
        if normalized.contains("webrelay") && route == .unknown {
            route = .relay
        }
    }

    private func failOpen(_ error: Error, connectionID: UUID) {
        guard self.connectionID == connectionID else { return }
        activeOpener = nil
        isConnecting = false
        isConnected = false
        isBrowserPresented = false
        browserURL = nil
        boundAddr = nil
        statusText = "Web tunnel failed."
        errorText = error.localizedDescription
    }

    private func failBeforeConnect(status: String, error: String) {
        activeOpener?.cancel()
        activeOpener = nil
        isConnecting = false
        isConnected = false
        isBrowserPresented = false
        browserURL = nil
        boundAddr = nil
        route = .unknown
        traceText = ""
        statusText = status
        errorText = error
    }

    private func normalizedScheme(_ scheme: String) -> String {
        let trimmed = scheme.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? "http" : trimmed
    }

    private func normalizedPath(_ path: String) -> String {
        let trimmed = path.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return "/" }
        return trimmed.hasPrefix("/") ? trimmed : "/\(trimmed)"
    }
}

private enum WebTunnelError: LocalizedError {
    case invalidPayload
    case nonWebPayload

    var errorDescription: String? {
        switch self {
        case .invalidPayload:
            return "Payload could not be parsed."
        case .nonWebPayload:
            return "Payload is not a web tunnel."
        }
    }
}

nonisolated private final class MobileWebTunnelOpener: WebTunnelOpening, @unchecked Sendable {
    private let client: DerpholemobileTunnelClient
    private let lock = NSLock()
    private var activeCallbacks: MobileWebTunnelCallbacks?
    private var canceled = false

    nonisolated init?() {
        guard let client = DerpholemobileNewTunnelClient() else { return nil }
        self.client = client
    }

    nonisolated func open(token: String, listenAddr: String, callbacks: WebTunnelCallbacks) throws {
        let mobileCallbacks = MobileWebTunnelCallbacks(callbacks: callbacks)

        lock.lock()
        if canceled {
            lock.unlock()
            throw CancellationError()
        }
        activeCallbacks = mobileCallbacks
        lock.unlock()

        do {
            try client.open(token, listenAddr: listenAddr, callbacks: mobileCallbacks)
        } catch {
            lock.lock()
            if activeCallbacks === mobileCallbacks {
                activeCallbacks = nil
            }
            lock.unlock()
            throw error
        }

        lock.lock()
        let wasCanceled = canceled
        if wasCanceled {
            activeCallbacks = nil
        }
        lock.unlock()
        if wasCanceled {
            client.cancel()
            throw CancellationError()
        }
    }

    nonisolated func cancel() {
        lock.lock()
        canceled = true
        activeCallbacks = nil
        lock.unlock()
        client.cancel()
    }
}

nonisolated private final class MobileWebTunnelCallbacks: NSObject, DerpholemobileTunnelCallbacksProtocol, @unchecked Sendable {
    private let callbacks: WebTunnelCallbacks

    init(callbacks: WebTunnelCallbacks) {
        self.callbacks = callbacks
    }

    func boundAddr(_ addr: String?) {
        callbacks.boundAddr(addr ?? "")
    }

    func status(_ status: String?) {
        callbacks.status(status ?? "")
    }

    func trace(_ trace: String?) {
        callbacks.trace(trace ?? "")
    }
}

nonisolated private final class WebTunnelCallbackAdapter: WebTunnelCallbacks, @unchecked Sendable {
    private let onBoundAddr: @Sendable (String) -> Void
    private let onStatus: @Sendable (String) -> Void
    private let onTrace: @Sendable (String) -> Void

    init(
        onBoundAddr: @escaping @Sendable (String) -> Void,
        onStatus: @escaping @Sendable (String) -> Void,
        onTrace: @escaping @Sendable (String) -> Void
    ) {
        self.onBoundAddr = onBoundAddr
        self.onStatus = onStatus
        self.onTrace = onTrace
    }

    func boundAddr(_ addr: String) {
        onBoundAddr(addr)
    }

    func status(_ status: String) {
        onStatus(status)
    }

    func trace(_ trace: String) {
        onTrace(trace)
    }
}
