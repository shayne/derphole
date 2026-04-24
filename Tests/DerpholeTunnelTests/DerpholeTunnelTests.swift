import XCTest
@testable import DerpholeTunnel

final class DerpholeTunnelTests: XCTestCase {
    func testEndpointParsesBoundAddressAndBuildsWebsocketURL() throws {
        let endpoint = try DerptunEndpoint(boundAddress: "127.0.0.1:54321")

        XCTAssertEqual(endpoint.host, "127.0.0.1")
        XCTAssertEqual(endpoint.port, 54321)
        XCTAssertEqual(endpoint.websocketURL.absoluteString, "ws://127.0.0.1:54321/")
    }

    func testEndpointRejectsMalformedBoundAddress() {
        XCTAssertThrowsError(try DerptunEndpoint(boundAddress: "not-a-port")) { error in
            XCTAssertEqual(error as? DerpholeTunnelError, .invalidBoundAddress("not-a-port"))
        }
    }

    func testEndpointRejectsURLLikeHost() {
        XCTAssertThrowsError(try DerptunEndpoint(boundAddress: "example.com/path:80"))
    }

    func testEndpointRejectsEmptyBracketedHost() {
        XCTAssertThrowsError(try DerptunEndpoint(boundAddress: "[]:1234"))
    }

    func testEndpointParsesBracketedIPv6Address() throws {
        let endpoint = try DerptunEndpoint(boundAddress: "[::1]:54321")

        XCTAssertEqual(endpoint.host, "::1")
        XCTAssertEqual(endpoint.port, 54321)
        XCTAssertEqual(endpoint.websocketURL.absoluteString, "ws://[::1]:54321/")
    }

    func testCallbackAdapterEmitsRouteStatusAndTraceEvents() {
        let recorder = EventRecorder()
        let adapter = CallbackAdapter { event in
            recorder.append(event)
        }

        adapter.status("connected-relay")
        adapter.status("connected-direct")
        adapter.status("negotiating")
        adapter.status("warming-up")
        adapter.status("  ")
        adapter.trace(" relay trace ")
        adapter.trace("")

        XCTAssertEqual(recorder.events, [
            .route(.relay),
            .route(.direct),
            .route(.negotiating),
            .status("warming-up"),
            .trace("relay trace")
        ])
    }

    func testOpenStateTracksExplicitCancelByGeneration() throws {
        var state = TunnelOpenState()
        let first = try state.begin(adapter: CallbackAdapter { _ in })

        XCTAssertFalse(state.isCanceled(first))

        state.cancelActive()

        XCTAssertTrue(state.isCanceled(first))

        let second = try state.begin(adapter: CallbackAdapter { _ in })

        XCTAssertFalse(state.isCanceled(second))
        XCTAssertTrue(state.isCanceled(first))
    }

    func testOpenStateRejectsSecondBeginWhileActive() throws {
        var state = TunnelOpenState()
        _ = try state.begin(adapter: CallbackAdapter { _ in })

        XCTAssertThrowsError(try state.begin(adapter: CallbackAdapter { _ in })) { error in
            XCTAssertEqual(error as? DerpholeTunnelError, .openAlreadyInProgress)
        }
    }

    func testOpenStateStaleFailureCannotClearNewerActiveGeneration() throws {
        var state = TunnelOpenState()
        let oldAdapter = CallbackAdapter { _ in }
        let old = try state.begin(adapter: oldAdapter)

        state.cancelActive()

        let newAdapter = CallbackAdapter { _ in }
        let newer = try state.begin(adapter: newAdapter)

        XCTAssertFalse(state.clearFailure(generation: old, adapter: oldAdapter))
        XCTAssertTrue(state.isActive(newer))
        XCTAssertThrowsError(try state.begin(adapter: CallbackAdapter { _ in })) { error in
            XCTAssertEqual(error as? DerpholeTunnelError, .openAlreadyInProgress)
        }
    }
}

private final class EventRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var values: [DerpholeTunnelEvent] = []

    var events: [DerpholeTunnelEvent] {
        lock.lock()
        defer { lock.unlock() }
        return values
    }

    func append(_ event: DerpholeTunnelEvent) {
        lock.lock()
        values.append(event)
        lock.unlock()
    }
}
