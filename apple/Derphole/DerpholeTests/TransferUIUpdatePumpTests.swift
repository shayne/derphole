import XCTest
@testable import Derphole

final class TransferUIUpdatePumpTests: XCTestCase {
    func testCoalescesProgressBurstsIntoOneScheduledDelivery() {
        var scheduled: [() -> Void] = []
        var snapshots: [TransferUIUpdatePump.Snapshot] = []
        let pump = TransferUIUpdatePump(
            schedule: { scheduled.append($0) },
            apply: { snapshots.append($0) }
        )

        for byte in 1...100 {
            pump.progress(current: Int64(byte), total: 100)
        }

        XCTAssertEqual(scheduled.count, 1)
        XCTAssertTrue(snapshots.isEmpty)

        scheduled.removeFirst()()

        XCTAssertEqual(snapshots.count, 1)
        XCTAssertEqual(snapshots[0].progress?.current, 100)
        XCTAssertEqual(snapshots[0].progress?.total, 100)
    }

    func testSchedulesNewDeliveryAfterPreviousFlush() {
        var scheduled: [() -> Void] = []
        var snapshots: [TransferUIUpdatePump.Snapshot] = []
        let pump = TransferUIUpdatePump(
            schedule: { scheduled.append($0) },
            apply: { snapshots.append($0) }
        )

        pump.status("connected-relay")
        XCTAssertEqual(scheduled.count, 1)
        scheduled.removeFirst()()

        pump.trace("udp-send-goodput-mbps=10")
        XCTAssertEqual(scheduled.count, 1)
        scheduled.removeFirst()()

        XCTAssertEqual(snapshots.count, 2)
        XCTAssertEqual(snapshots[0].status, "connected-relay")
        XCTAssertEqual(snapshots[1].trace, "udp-send-goodput-mbps=10")
    }
}
