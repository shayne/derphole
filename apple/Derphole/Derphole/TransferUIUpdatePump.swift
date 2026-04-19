import Foundation

final class TransferUIUpdatePump {
    struct Progress: Equatable {
        let current: Int64
        let total: Int64
    }

    struct Snapshot: Equatable {
        var progress: Progress?
        var status: String?
        var trace: String?
    }

    typealias Scheduler = (@escaping () -> Void) -> Void

    private static let frameInterval: TimeInterval = 1.0 / 30.0

    private let lock = NSLock()
    private let schedule: Scheduler
    private let apply: (Snapshot) -> Void

    private var scheduled = false
    private var pending = Snapshot()

    init(schedule: Scheduler? = nil, apply: @escaping (Snapshot) -> Void) {
        self.schedule = schedule ?? { work in
            DispatchQueue.main.asyncAfter(deadline: .now() + Self.frameInterval, execute: work)
        }
        self.apply = apply
    }

    func progress(current: Int64, total: Int64) {
        enqueue {
            pending.progress = Progress(current: current, total: total)
        }
    }

    func status(_ status: String) {
        enqueue {
            pending.status = status
        }
    }

    func trace(_ trace: String) {
        enqueue {
            pending.trace = trace
        }
    }

    func flushPending() {
        let snapshot: Snapshot

        lock.lock()
        guard pending.progress != nil || pending.status != nil || pending.trace != nil else {
            scheduled = false
            lock.unlock()
            return
        }
        snapshot = pending
        pending = Snapshot()
        scheduled = false
        lock.unlock()

        apply(snapshot)
    }

    private func enqueue(_ update: () -> Void) {
        var shouldSchedule = false

        lock.lock()
        update()
        if !scheduled {
            scheduled = true
            shouldSchedule = true
        }
        lock.unlock()

        if shouldSchedule {
            schedule { [weak self] in
                self?.flushPending()
            }
        }
    }
}
