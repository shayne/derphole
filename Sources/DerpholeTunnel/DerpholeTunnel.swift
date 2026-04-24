import DerpholeMobile
import Foundation

public struct DerptunInvite: Equatable, Sendable {
    public let rawValue: String

    public init(_ rawValue: String) throws {
        try self.init(rawValue: rawValue)
    }

    public init(rawValue: String) throws {
        let trimmed = rawValue.trimmingCharacters(in: .whitespacesAndNewlines)
        var error: NSError?
        guard let parsed = DerpholemobileParsePayload(trimmed, &error) else {
            throw DerpholeTunnelError.invalidInvite(error?.localizedDescription ?? "Payload could not be parsed.")
        }
        if let error {
            throw DerpholeTunnelError.invalidInvite(error.localizedDescription)
        }
        guard parsed.kind() == "tcp" else {
            throw DerpholeTunnelError.unsupportedInviteKind(parsed.kind())
        }
        self.rawValue = trimmed
    }
}

public struct DerptunEndpoint: Equatable, Sendable {
    public let boundAddress: String
    public let host: String
    public let port: Int
    public let websocketURL: URL

    public init(boundAddress: String) throws {
        let trimmed = boundAddress.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let colon = trimmed.lastIndex(of: ":") else {
            throw DerpholeTunnelError.invalidBoundAddress(trimmed)
        }

        let rawHost = String(trimmed[..<colon])
        var host = rawHost
        if rawHost.hasPrefix("[") || rawHost.hasSuffix("]") {
            guard rawHost.hasPrefix("["),
                  rawHost.hasSuffix("]"),
                  rawHost.count > 2 else {
                throw DerpholeTunnelError.invalidBoundAddress(rawHost)
            }
            host.removeFirst()
            host.removeLast()
        }

        let portText = String(trimmed[trimmed.index(after: colon)...])
        guard !host.isEmpty, DerptunEndpoint.isValidHost(host) else {
            throw DerpholeTunnelError.invalidBoundAddress(host.isEmpty ? rawHost : host)
        }
        guard let port = Int(portText), (1...65_535).contains(port) else {
            throw DerpholeTunnelError.invalidBoundAddress(portText)
        }

        let urlHost = host.contains(":") ? "[\(host)]" : host
        guard let websocketURL = URL(string: "ws://\(urlHost):\(port)/") else {
            throw DerpholeTunnelError.invalidBoundAddress(trimmed)
        }
        guard DerptunEndpoint.normalizedHost(websocketURL.host ?? "") == DerptunEndpoint.normalizedHost(host),
              websocketURL.port == port else {
            throw DerpholeTunnelError.invalidBoundAddress(trimmed)
        }

        self.boundAddress = trimmed
        self.host = host
        self.port = port
        self.websocketURL = websocketURL
    }

    private static func isValidHost(_ host: String) -> Bool {
        let forbidden = CharacterSet(charactersIn: "/?#").union(.whitespacesAndNewlines)
        return host.rangeOfCharacter(from: forbidden) == nil
    }

    private static func normalizedHost(_ host: String) -> String {
        if host.hasPrefix("[") && host.hasSuffix("]") {
            return String(host.dropFirst().dropLast())
        }
        return host
    }
}

public enum DerpholeRoute: Equatable, Sendable {
    case negotiating
    case relay
    case direct
}

public enum DerpholeTunnelEvent: Equatable, Sendable {
    case status(String)
    case route(DerpholeRoute)
    case trace(String)
}

public enum DerpholeTunnelError: Error, Equatable, LocalizedError, Sendable {
    case invalidInvite(String)
    case unsupportedInviteKind(String)
    case mobileClientUnavailable
    case missingBoundAddress
    case invalidBoundAddress(String)
    case openFailed(String)
    case openAlreadyInProgress

    public var errorDescription: String? {
        switch self {
        case .invalidInvite(let message):
            return "Derptun invite is invalid: \(message)"
        case .unsupportedInviteKind(let kind):
            return "Derptun invite kind is unsupported: \(kind)"
        case .mobileClientUnavailable:
            return "DerpholeMobile could not create a tunnel client."
        case .missingBoundAddress:
            return "DerpholeMobile did not report a bound tunnel address."
        case .invalidBoundAddress(let address):
            return "DerpholeMobile reported an invalid bound address: \(address)"
        case .openFailed(let message):
            return "Derptun tunnel failed to open: \(message)"
        case .openAlreadyInProgress:
            return "A derptun tunnel is already open or opening; cancel it before opening another tunnel."
        }
    }
}

public final class DerptunTunnelClient: @unchecked Sendable {
    private let client: DerpholemobileTunnelClient
    private let lock = NSLock()
    private var openState = TunnelOpenState()

    public init() throws {
        guard let client = DerpholemobileNewTunnelClient() else {
            throw DerpholeTunnelError.mobileClientUnavailable
        }
        self.client = client
    }

    public func open(
        invite: DerptunInvite,
        onEvent: @escaping @Sendable (DerpholeTunnelEvent) -> Void = { _ in }
    ) async throws -> DerptunEndpoint {
        let adapter = CallbackAdapter(onEvent: onEvent)
        let generation = try beginOpen(adapter: adapter)

        do {
            let endpoint = try await withTaskCancellationHandler(operation: {
                try Task.checkCancellation()
                if self.isOpenCanceled(generation) {
                    throw CancellationError()
                }
                return try await Task.detached(priority: .userInitiated) { [client] in
                    do {
                        try client.openInvite(
                            invite.rawValue,
                            listenAddr: "127.0.0.1:0",
                            callbacks: adapter
                        )
                    } catch is CancellationError {
                        throw CancellationError()
                    } catch {
                        if self.isOpenCanceled(generation) || Task.isCancelled {
                            throw CancellationError()
                        }
                        throw DerpholeTunnelError.openFailed(error.localizedDescription)
                    }

                    if self.isOpenCanceled(generation) {
                        throw CancellationError()
                    }
                    try Task.checkCancellation()
                    guard let boundAddress = adapter.boundAddress else {
                        throw DerpholeTunnelError.missingBoundAddress
                    }
                    return try DerptunEndpoint(boundAddress: boundAddress)
                }.value
            }, onCancel: {
                self.markOpenCanceled()
                self.client.cancel()
            })
            if isOpenCanceled(generation) {
                throw CancellationError()
            }
            return endpoint
        } catch {
            if clearFailedOpen(generation: generation, adapter: adapter) {
                client.cancel()
            }
            throw error
        }
    }

    public func open(
        _ invite: DerptunInvite,
        onEvent: @escaping @Sendable (DerpholeTunnelEvent) -> Void = { _ in }
    ) async throws -> DerptunEndpoint {
        try await open(invite: invite, onEvent: onEvent)
    }

    public func cancel() {
        markOpenCanceled()
        client.cancel()
    }

    deinit {
        cancel()
    }

    private func beginOpen(adapter: CallbackAdapter) throws -> UInt64 {
        lock.lock()
        defer { lock.unlock() }
        return try openState.begin(adapter: adapter)
    }

    private func markOpenCanceled() {
        lock.lock()
        openState.cancelActive()
        lock.unlock()
    }

    private func isOpenCanceled(_ generation: UInt64) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return openState.isCanceled(generation)
    }

    private func clearFailedOpen(generation: UInt64, adapter: CallbackAdapter) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return openState.clearFailure(generation: generation, adapter: adapter)
    }
}

struct TunnelOpenState {
    private(set) var generation: UInt64 = 0
    private var canceledGenerations: Set<UInt64> = []
    private var activeGeneration: UInt64?
    private var activeAdapter: CallbackAdapter?

    mutating func begin(adapter: CallbackAdapter) throws -> UInt64 {
        guard activeAdapter == nil else {
            throw DerpholeTunnelError.openAlreadyInProgress
        }
        generation &+= 1
        activeGeneration = generation
        activeAdapter = adapter
        return generation
    }

    mutating func cancelActive() {
        guard let activeGeneration, activeAdapter != nil else { return }
        canceledGenerations.insert(activeGeneration)
        self.activeGeneration = nil
        activeAdapter = nil
    }

    func isCanceled(_ generation: UInt64) -> Bool {
        canceledGenerations.contains(generation)
    }

    func isActive(_ generation: UInt64) -> Bool {
        activeGeneration == generation && activeAdapter != nil
    }

    mutating func clearFailure(generation: UInt64, adapter: CallbackAdapter) -> Bool {
        guard activeGeneration == generation, activeAdapter === adapter else { return false }
        activeGeneration = nil
        activeAdapter = nil
        return true
    }
}

nonisolated final class CallbackAdapter: NSObject, DerpholemobileTunnelCallbacksProtocol, @unchecked Sendable {
    private let lock = NSLock()
    private var boundAddressValue: String?
    private let onEvent: @Sendable (DerpholeTunnelEvent) -> Void

    init(onEvent: @escaping @Sendable (DerpholeTunnelEvent) -> Void) {
        self.onEvent = onEvent
    }

    var boundAddress: String? {
        lock.lock()
        defer { lock.unlock() }
        return boundAddressValue
    }

    func boundAddr(_ addr: String?) {
        let trimmed = (addr ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        lock.lock()
        boundAddressValue = trimmed
        lock.unlock()
    }

    func status(_ status: String?) {
        let trimmed = (status ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        switch trimmed {
        case "connected-relay":
            onEvent(.route(.relay))
        case "connected-direct":
            onEvent(.route(.direct))
        case "negotiating":
            onEvent(.route(.negotiating))
        default:
            guard !trimmed.isEmpty else { return }
            onEvent(.status(trimmed))
        }
    }

    func trace(_ trace: String?) {
        let trimmed = (trace ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        onEvent(.trace(trimmed))
    }
}
