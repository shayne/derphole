import Darwin
import DerpholeMobile
import Foundation

nonisolated private func withLock<T>(_ lock: NSLock, _ operation: () throws -> T) rethrows -> T {
    lock.lock()
    defer { lock.unlock() }
    return try operation()
}

nonisolated final class DerpholeSSHConnector: SSHLocalTunnelConnecting, @unchecked Sendable {
    private let tunnelClient: DerpholemobileTunnelClient
    private let lock = NSLock()
    private var activeCallbacks: MobileSSHTunnelCallbacks?
    private var activeSession: SSHConnectedTerminalSession?
    private var canceled = false

    init?() {
        guard let tunnelClient = DerpholemobileNewTunnelClient() else { return nil }
        self.tunnelClient = tunnelClient
    }

    func connect(token: String, username: String, password: String) async throws -> SSHConnectedTerminalSession {
        let callbacks = MobileSSHTunnelCallbacks()
        try withLock(lock) {
            if canceled {
                throw CancellationError()
            }
            activeCallbacks = callbacks
        }

        do {
            try tunnelClient.open(token, listenAddr: "127.0.0.1:0", callbacks: callbacks)
            let endpoint = try callbacks.endpoint()
            let session = try await LibSSH2TerminalSession.connect(
                host: endpoint.host,
                port: endpoint.port,
                username: username,
                password: password
            )
            let wasCanceled = withLock(lock) {
                activeSession = session
                return canceled
            }
            if wasCanceled {
                session.close()
                tunnelClient.cancel()
                throw CancellationError()
            }
            return session
        } catch {
            withLock(lock) {
                activeCallbacks = nil
            }
            tunnelClient.cancel()
            throw error
        }
    }

    func disconnect() {
        let session = withLock(lock) {
            canceled = true
            let session = activeSession
            activeSession = nil
            activeCallbacks = nil
            return session
        }
        session?.close()
        tunnelClient.cancel()
    }
}

private struct LocalTCPEndpoint: Equatable {
    let host: String
    let port: Int

    nonisolated static func parse(_ raw: String) throws -> LocalTCPEndpoint {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let colon = trimmed.lastIndex(of: ":") else {
            throw SSHConnectionError.invalidTunnelEndpoint(trimmed)
        }
        var host = String(trimmed[..<colon])
        if host.hasPrefix("[") && host.hasSuffix("]") {
            host.removeFirst()
            host.removeLast()
        }
        let portText = String(trimmed[trimmed.index(after: colon)...])
        guard !host.isEmpty, let port = Int(portText), port > 0 else {
            throw SSHConnectionError.invalidTunnelEndpoint(trimmed)
        }
        return LocalTCPEndpoint(host: host, port: port)
    }
}

nonisolated private final class MobileSSHTunnelCallbacks: NSObject, DerpholemobileTunnelCallbacksProtocol, @unchecked Sendable {
    private let lock = NSLock()
    private var boundAddrValue: String?

    func boundAddr(_ addr: String?) {
        withLock(lock) {
            boundAddrValue = addr ?? ""
        }
    }

    func status(_ status: String?) {}
    func trace(_ trace: String?) {}

    func endpoint() throws -> LocalTCPEndpoint {
        let addr = withLock(lock) {
            boundAddrValue ?? ""
        }
        return try LocalTCPEndpoint.parse(addr)
    }
}

nonisolated private enum LibSSH2Runtime {
    private static let lock = NSLock()
    private static var initialized = false

    static func ensureInitialized() throws {
        lock.lock()
        defer { lock.unlock() }
        guard !initialized else { return }
        let rc = libssh2_init(0)
        guard rc == 0 else {
            throw SSHConnectionError.sshFailed("libssh2_init failed: \(rc)")
        }
        initialized = true
    }
}

nonisolated private enum LibSSH2Constants {
    static let channelWindowDefault: UInt32 = 2 * 1024 * 1024
    static let channelPacketDefault: UInt32 = 32_768
    static let sshDisconnectByApplication: Int32 = 11
}

nonisolated final class LibSSH2TerminalSession: SSHConnectedTerminalSession, @unchecked Sendable {
    let output: AsyncStream<Data>

    private let outputContinuation: AsyncStream<Data>.Continuation
    private let lock = NSLock()
    private var socketFD: Int32 = -1
    private var session: OpaquePointer?
    private var channel: OpaquePointer?
    private var closed = false
    private var readTask: Task<Void, Never>?

    private init(socketFD: Int32, session: OpaquePointer, channel: OpaquePointer) {
        self.socketFD = socketFD
        self.session = session
        self.channel = channel

        var continuation: AsyncStream<Data>.Continuation!
        self.output = AsyncStream<Data> { streamContinuation in
            continuation = streamContinuation
        }
        self.outputContinuation = continuation
    }

    static func connect(
        host: String,
        port: Int,
        username: String,
        password: String,
        cols: Int = 80,
        rows: Int = 24
    ) async throws -> LibSSH2TerminalSession {
        try await Task.detached(priority: .userInitiated) {
            try LibSSH2Runtime.ensureInitialized()
            let fd = try connectSocket(host: host, port: port)
            var sshSessionForCleanup: OpaquePointer?
            var sshChannelForCleanup: OpaquePointer?
            do {
                guard let sshSession = libssh2_session_init_ex(nil, nil, nil, nil) else {
                    throw SSHConnectionError.sshFailed("Could not create SSH session.")
                }
                sshSessionForCleanup = sshSession
                libssh2_session_set_timeout(sshSession, 30_000)
                var rc = libssh2_session_handshake(sshSession, fd)
                guard rc == 0 else {
                    throw SSHConnectionError.sshFailed(lastError(from: sshSession, fallback: "SSH handshake failed: \(rc)"))
                }

                rc = username.withCString { usernamePtr in
                    password.withCString { passwordPtr in
                        libssh2_userauth_password_ex(
                            sshSession,
                            usernamePtr,
                            UInt32(username.utf8.count),
                            passwordPtr,
                            UInt32(password.utf8.count),
                            nil
                        )
                    }
                }
                guard rc == 0 else {
                    throw SSHConnectionError.authenticationFailed
                }

                let channel = "session".withCString { channelType in
                    libssh2_channel_open_ex(
                        sshSession,
                        channelType,
                        UInt32("session".utf8.count),
                        LibSSH2Constants.channelWindowDefault,
                        LibSSH2Constants.channelPacketDefault,
                        nil,
                        0
                    )
                }
                guard let channel else {
                    throw SSHConnectionError.sshFailed(lastError(from: sshSession, fallback: "Failed to open SSH channel."))
                }
                sshChannelForCleanup = channel

                rc = "xterm-256color".withCString { termPtr in
                    libssh2_channel_request_pty_ex(
                        channel,
                        termPtr,
                        UInt32("xterm-256color".utf8.count),
                        nil,
                        0,
                        Int32(cols),
                        Int32(rows),
                        0,
                        0
                    )
                }
                guard rc == 0 else {
                    libssh2_channel_free(channel)
                    throw SSHConnectionError.sshFailed("Failed to request SSH PTY.")
                }

                rc = "shell".withCString { requestPtr in
                    libssh2_channel_process_startup(
                        channel,
                        requestPtr,
                        UInt32("shell".utf8.count),
                        nil,
                        0
                    )
                }
                guard rc == 0 else {
                    libssh2_channel_free(channel)
                    throw SSHConnectionError.sshFailed("Failed to start remote shell.")
                }

                libssh2_session_set_blocking(sshSession, 0)
                libssh2_channel_set_blocking(channel, 0)
                let terminalSession = LibSSH2TerminalSession(socketFD: fd, session: sshSession, channel: channel)
                sshChannelForCleanup = nil
                sshSessionForCleanup = nil
                terminalSession.startReading()
                return terminalSession
            } catch {
                if let channel = sshChannelForCleanup {
                    libssh2_channel_close(channel)
                    libssh2_channel_free(channel)
                }
                if let sshSession = sshSessionForCleanup {
                    "Derphole connect failed".withCString { descriptionPtr in
                        "".withCString { langPtr in
                            _ = libssh2_session_disconnect_ex(
                                sshSession,
                                LibSSH2Constants.sshDisconnectByApplication,
                                descriptionPtr,
                                langPtr
                            )
                        }
                    }
                    libssh2_session_free(sshSession)
                }
                Darwin.close(fd)
                throw error
            }
        }.value
    }

    func write(_ data: Data) async throws {
        try await Task.detached(priority: .userInitiated) { [weak self] in
            try self?.writeBlocking(data)
        }.value
    }

    func resize(cols: Int, rows: Int) async throws {
        try await Task.detached(priority: .utility) { [weak self] in
            guard let self else { return }
            while true {
                let rc = withLock(lock) {
                    guard !self.closed, let channel = self.channel else {
                        return Int32(0)
                    }
                    return libssh2_channel_request_pty_size_ex(channel, Int32(cols), Int32(rows), 0, 0)
                }
                if rc == Int32(LIBSSH2_ERROR_EAGAIN) {
                    try await Task.sleep(for: .milliseconds(20))
                    continue
                }
                if rc != 0 {
                    throw SSHConnectionError.sshFailed("Failed to resize SSH PTY.")
                }
                return
            }
        }.value
    }

    func close() {
        let resources = withLock(lock) {
            guard !closed else {
                return (channel: OpaquePointer?.none, session: OpaquePointer?.none, socketFD: Int32(-1), shouldClose: false)
            }
            closed = true
            let resources = (channel: channel, session: session, socketFD: socketFD, shouldClose: true)
            self.channel = nil
            self.session = nil
            self.socketFD = -1
            return resources
        }
        guard resources.shouldClose else { return }

        readTask?.cancel()
        if let channel = resources.channel {
            libssh2_channel_close(channel)
            libssh2_channel_free(channel)
        }
        if let session = resources.session {
            "Derphole disconnect".withCString { descriptionPtr in
                "".withCString { langPtr in
                    _ = libssh2_session_disconnect_ex(
                        session,
                        LibSSH2Constants.sshDisconnectByApplication,
                        descriptionPtr,
                        langPtr
                    )
                }
            }
            libssh2_session_free(session)
        }
        if resources.socketFD >= 0 {
            Darwin.close(resources.socketFD)
        }
        outputContinuation.finish()
    }

    private func startReading() {
        readTask = Task.detached(priority: .userInitiated) { [weak self] in
            await self?.readLoop()
        }
    }

    private func readLoop() async {
        while !Task.isCancelled {
            do {
                if let data = try readAvailable() {
                    outputContinuation.yield(data)
                } else {
                    try await Task.sleep(for: .milliseconds(20))
                }
            } catch {
                outputContinuation.finish()
                close()
                return
            }
        }
    }

    private func readAvailable() throws -> Data? {
        var buffer = [CChar](repeating: 0, count: 8192)
        let readResult = withLock(lock) { () -> (count: Int, channelEOF: Bool)? in
            guard !closed, let channel else {
                return nil
            }
            let count = buffer.withUnsafeMutableBufferPointer { bufferPtr in
                libssh2_channel_read_ex(channel, 0, bufferPtr.baseAddress, bufferPtr.count)
            }
            return (count, libssh2_channel_eof(channel) != 0)
        }
        guard let readResult else {
            return nil
        }

        if readResult.count == Int(LIBSSH2_ERROR_EAGAIN) {
            return nil
        }
        if readResult.count < 0 {
            throw SSHConnectionError.sshFailed("SSH read failed: \(readResult.count)")
        }
        if readResult.count == 0 {
            if readResult.channelEOF {
                throw SSHConnectionError.sshFailed("SSH channel closed.")
            }
            return nil
        }
        return Data(buffer.prefix(readResult.count).map { UInt8(bitPattern: $0) })
    }

    private func writeBlocking(_ data: Data) throws {
        var offset = 0
        while offset < data.count {
            let written = data.withUnsafeBytes { rawBuffer -> Int in
                guard let base = rawBuffer.baseAddress else { return 0 }
                let ptr = base.advanced(by: offset).assumingMemoryBound(to: CChar.self)
                return withLock(lock) {
                    guard !closed, let channel else {
                        return -1
                    }
                    return libssh2_channel_write_ex(channel, 0, ptr, data.count - offset)
                }
            }
            if written == Int(LIBSSH2_ERROR_EAGAIN) {
                Thread.sleep(forTimeInterval: 0.02)
                continue
            }
            if written < 0 {
                throw SSHConnectionError.sshFailed("SSH write failed: \(written)")
            }
            if written == 0 {
                Thread.sleep(forTimeInterval: 0.02)
                continue
            }
            offset += written
        }
    }

    private static func connectSocket(host: String, port: Int) throws -> Int32 {
        var hints = addrinfo(
            ai_flags: AI_NUMERICSERV,
            ai_family: AF_UNSPEC,
            ai_socktype: SOCK_STREAM,
            ai_protocol: IPPROTO_TCP,
            ai_addrlen: 0,
            ai_canonname: nil,
            ai_addr: nil,
            ai_next: nil
        )
        var result: UnsafeMutablePointer<addrinfo>?
        let rc = getaddrinfo(host, String(port), &hints, &result)
        guard rc == 0, let result else {
            throw SSHConnectionError.sshFailed("Could not resolve SSH tunnel endpoint \(host):\(port).")
        }
        defer { freeaddrinfo(result) }

        var cursor: UnsafeMutablePointer<addrinfo>? = result
        while let addr = cursor {
            let info = addr.pointee
            let fd = socket(info.ai_family, info.ai_socktype, info.ai_protocol)
            if fd >= 0 {
                if Darwin.connect(fd, info.ai_addr, info.ai_addrlen) == 0 {
                    return fd
                }
                Darwin.close(fd)
            }
            cursor = info.ai_next
        }
        throw SSHConnectionError.sshFailed("Could not connect to SSH tunnel endpoint \(host):\(port).")
    }

    private static func lastError(from session: OpaquePointer, fallback: String) -> String {
        var messagePtr: UnsafeMutablePointer<CChar>?
        var messageLength: Int32 = 0
        let code = libssh2_session_last_error(session, &messagePtr, &messageLength, 0)
        guard let messagePtr, messageLength > 0 else {
            return fallback
        }
        let message = String(decoding: UnsafeBufferPointer(start: messagePtr, count: Int(messageLength)).map { UInt8(bitPattern: $0) }, as: UTF8.self)
        return "\(fallback) (\(code): \(message))"
    }
}
