//
//  TransferState.swift
//  Derphole
//
//  Created by Codex on 4/19/26.
//

import Combine
import Foundation
import DerpholeMobile

final class TransferState: ObservableObject {
    enum Phase: Equatable {
        case idle
        case scanning
        case receiving
        case received
        case failed
        case canceled
    }

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

    @Published var pastedPayload = ""
    @Published private(set) var phase: Phase = .idle
    @Published private(set) var statusText = "Ready."
    @Published private(set) var traceText = ""
    @Published private(set) var route: Route = .unknown
    @Published private(set) var progressCurrent: Int64 = 0
    @Published private(set) var progressTotal: Int64 = 0
    @Published private(set) var validatedToken = ""
    @Published private(set) var completedFileURL: URL?
    @Published private(set) var errorText: String?
    @Published var isExporterPresented = false

    private var activeReceiver: DerpholemobileReceiver?
    private var transferID = UUID()
    private var cancelRequested = false
    private var lastScannedPayload = ""

    var isReceiving: Bool {
        phase == .receiving
    }

    var isScanning: Bool {
        phase == .scanning
    }

    var canValidatePayload: Bool {
        !pastedPayload.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && !isReceiving && !canExport
    }

    var canStartReceive: Bool {
        canValidatePayload && !canExport
    }

    var canStartScan: Bool {
        !isReceiving && !canExport
    }

    var canExport: Bool {
        completedFileURL != nil && !isReceiving
    }

    var progressFraction: Double? {
        guard progressTotal > 0 else { return nil }
        return min(max(Double(progressCurrent) / Double(progressTotal), 0), 1)
    }

    var statusSummary: String {
        switch phase {
        case .idle:
            return "Ready to receive"
        case .scanning:
            return "Scanning"
        case .receiving:
            return "Receiving"
        case .received:
            return "Receive complete"
        case .failed:
            return "Receive failed"
        case .canceled:
            return "Receive canceled"
        }
    }

    func validatePastedPayload() {
        do {
            let token = try parsePayload(pastedPayload)
            validatedToken = token
            errorText = nil
            phase = .idle
            statusText = "Payload looks valid."
        } catch {
            validatedToken = ""
            errorText = error.localizedDescription
            statusText = "Payload validation failed."
        }
    }

    func scanStarted() {
        guard canStartScan else { return }
        phase = .scanning
        route = .unknown
        progressCurrent = 0
        progressTotal = 0
        validatedToken = ""
        completedFileURL = nil
        traceText = ""
        statusText = "Scanning for QR code."
        errorText = nil
        cancelRequested = false
        lastScannedPayload = ""
    }

    func receivePastedPayload() {
        startReceive(from: pastedPayload, source: .manual)
    }

    func receiveScannedPayload(_ payload: String) {
        let trimmed = payload.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, canStartScan, trimmed != lastScannedPayload else {
            return
        }
        pastedPayload = trimmed
        startReceive(from: trimmed, source: .scanner)
    }

    func notePastedPayloadEdited() {
        if !isReceiving {
            validatedToken = ""
            errorText = nil
            if phase == .failed || phase == .canceled {
                phase = .idle
                statusText = "Ready."
            }
        }
    }

    func cancelReceive() {
        cancel()
    }

    func cancel() {
        guard isReceiving else {
            phase = .canceled
            statusText = "Receive canceled."
            errorText = nil
            return
        }
        cancelRequested = true
        statusText = "Canceling receive..."
        activeReceiver?.cancel()
    }

    func presentExporter() {
        guard completedFileURL != nil else { return }
        isExporterPresented = true
    }

    func exporterFinished(exported: Bool) {
        isExporterPresented = false
        guard exported else { return }
        phase = .idle
        route = .unknown
        progressCurrent = 0
        progressTotal = 0
        completedFileURL = nil
        traceText = ""
        statusText = "Ready."
    }

    private enum ReceiveSource {
        case manual
        case scanner
    }

    private func startReceive(from payload: String, source: ReceiveSource) {
        guard !isReceiving, !canExport else { return }

        let token: String
        do {
            token = try parsePayload(payload)
        } catch {
            validatedToken = ""
            lastScannedPayload = ""
            phase = .failed
            errorText = error.localizedDescription
            statusText = source == .scanner ? "Scanned code was invalid." : "Payload validation failed."
            return
        }

        let receiveRoot = FileManager.default.temporaryDirectory.appendingPathComponent("DerpholeReceive-\(UUID().uuidString)", isDirectory: true)
        do {
            try FileManager.default.createDirectory(at: receiveRoot, withIntermediateDirectories: true)
        } catch {
            phase = .failed
            errorText = error.localizedDescription
            statusText = "Could not prepare a receive directory."
            return
        }

        guard let receiver = DerpholemobileNewReceiver() else {
            phase = .failed
            errorText = "Could not create the Derphole receiver bridge."
            statusText = "Receiver initialization failed."
            return
        }

        let currentTransferID = UUID()
        transferID = currentTransferID
        activeReceiver = receiver
        if source == .scanner {
            lastScannedPayload = payload.trimmingCharacters(in: .whitespacesAndNewlines)
        }
        cancelRequested = false
        phase = .receiving
        route = .unknown
        progressCurrent = 0
        progressTotal = 0
        validatedToken = token
        completedFileURL = nil
        errorText = nil
        traceText = ""
        statusText = source == .scanner ? "QR code scanned. Starting receive..." : "Starting receive..."

        let callbacks = TransferCallbacks(
            onProgress: { [weak self] current, total in
                DispatchQueue.main.async {
                    self?.handleProgress(current: current, total: total, transferID: currentTransferID)
                }
            },
            onStatus: { [weak self] status in
                DispatchQueue.main.async {
                    self?.handleStatus(status, transferID: currentTransferID)
                }
            },
            onTrace: { [weak self] trace in
                DispatchQueue.main.async {
                    self?.handleTrace(trace, transferID: currentTransferID)
                }
            }
        )

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            do {
                let outputPath = try Self.receiveWithBridge(receiver: receiver, payload: payload, outputDir: receiveRoot.path, callbacks: callbacks)
                DispatchQueue.main.async {
                    self?.completeReceive(at: URL(fileURLWithPath: outputPath), transferID: currentTransferID)
                }
            } catch {
                DispatchQueue.main.async {
                    self?.failReceive(error, transferID: currentTransferID)
                }
            }
        }
    }

    private func parsePayload(_ payload: String) throws -> String {
        var error: NSError?
        let token = DerpholemobileParsePayload(payload, &error)
        if let error {
            throw error
        }
        return token
    }

    private func handleProgress(current: Int64, total: Int64, transferID: UUID) {
        guard self.transferID == transferID else { return }
        progressCurrent = current
        progressTotal = total
    }

    private func handleStatus(_ status: String, transferID: UUID) {
        guard self.transferID == transferID else { return }

        let normalized = status.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !normalized.isEmpty else { return }

        switch normalized {
        case "connected-relay":
            route = .relay
            statusText = "Connected through relay."
        case "connected-direct":
            route = .direct
            statusText = "Promoted to direct path."
        default:
            statusText = normalized.replacingOccurrences(of: "-", with: " ")
        }
    }

    private func handleTrace(_ trace: String, transferID: UUID) {
        guard self.transferID == transferID else { return }

        let normalized = trace.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !normalized.isEmpty else { return }

        traceText = normalized
        if normalized.contains("webrelay") && route == .unknown {
            route = .relay
        }
    }

    private func completeReceive(at fileURL: URL, transferID: UUID) {
        guard self.transferID == transferID else { return }
        activeReceiver = nil
        phase = .received
        completedFileURL = fileURL
        statusText = "Receive complete."
        if progressTotal > 0 {
            progressCurrent = progressTotal
        }
        lastScannedPayload = ""
    }

    private func failReceive(_ error: Error, transferID: UUID) {
        guard self.transferID == transferID else { return }
        activeReceiver = nil
        completedFileURL = nil
        lastScannedPayload = ""

        let description = error.localizedDescription
        if cancelRequested || description.localizedCaseInsensitiveContains("canceled") {
            phase = .canceled
            statusText = "Receive canceled."
            errorText = nil
        } else {
            phase = .failed
            statusText = "Receive failed."
            errorText = description
        }
        cancelRequested = false
    }

    private static func receiveWithBridge(
        receiver: DerpholemobileReceiver,
        payload: String,
        outputDir: String,
        callbacks: TransferCallbacks
    ) throws -> String {
        var error: NSError?
        let outputPath = receiver.receive(payload, outputDir: outputDir, callbacks: callbacks, error: &error)
        if let error {
            throw error
        }
        return outputPath
    }
}

private final class TransferCallbacks: NSObject, DerpholemobileCallbacksProtocol, @unchecked Sendable {
    private let onProgress: @Sendable (Int64, Int64) -> Void
    private let onStatus: @Sendable (String) -> Void
    private let onTrace: @Sendable (String) -> Void

    init(
        onProgress: @escaping @Sendable (Int64, Int64) -> Void,
        onStatus: @escaping @Sendable (String) -> Void,
        onTrace: @escaping @Sendable (String) -> Void
    ) {
        self.onProgress = onProgress
        self.onStatus = onStatus
        self.onTrace = onTrace
    }

    func progress(_ current: Int64, total: Int64) {
        onProgress(current, total)
    }

    func status(_ status: String?) {
        onStatus(status ?? "")
    }

    func trace(_ trace: String?) {
        onTrace(trace ?? "")
    }
}
