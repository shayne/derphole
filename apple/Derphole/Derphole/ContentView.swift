//
//  ContentView.swift
//  Derphole
//
//  Created by Shayne Sweeney on 4/19/26.
//

import SwiftUI

struct ContentView: View {
    @StateObject private var transferState = TransferState()

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    scannerSection
                    manualPayloadSection
                    transferStatusSection
                    actionSection
                }
                .padding(20)
            }
            .navigationTitle("Receive")
            .sheet(isPresented: $transferState.isExporterPresented) {
                if let fileURL = transferState.completedFileURL {
                    DocumentExporter(fileURL: fileURL) {
                        transferState.exporterFinished(exported: $0)
                    }
                }
            }
            .onAppear {
                #if DEBUG
                transferState.receiveRuntimeInjectedPayloadIfConfigured()
                #endif
            }
        }
    }

    private var scannerSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Button {
                transferState.scanStarted()
            } label: {
                Label("Scan QR Code", systemImage: "qrcode.viewfinder")
            }
            .buttonStyle(.borderedProminent)
            .disabled(!transferState.canStartScan)
            .accessibilityIdentifier("scanQRCodeButton")

            QRScannerView(isScanning: transferState.isScanning && !transferState.isReceiving) { payload in
                transferState.receiveScannedPayload(payload)
            }
            .frame(minHeight: 260)
            .overlay {
                RoundedRectangle(cornerRadius: 8)
                    .strokeBorder(.quaternary, lineWidth: 1)
            }
            .accessibilityIdentifier("qrScannerView")
        }
    }

    private var manualPayloadSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Paste Payload")
                .font(.headline)

            TextField("Paste a Derphole QR payload or raw token", text: $transferState.pastedPayload, axis: .vertical)
                .textInputAutocapitalization(.never)
                .disableAutocorrection(true)
                .padding(12)
                .background(
                    RoundedRectangle(cornerRadius: 8)
                        .fill(Color(.secondarySystemBackground))
                )
                .accessibilityIdentifier("pastedPayloadField")
                .onChange(of: transferState.pastedPayload) { _, _ in
                    transferState.notePastedPayloadEdited()
                }

            HStack(spacing: 12) {
                Button("Validate") {
                    transferState.validatePastedPayload()
                }
                .buttonStyle(.bordered)
                .disabled(!transferState.canValidatePayload)
                .accessibilityIdentifier("validatePayloadButton")

                Button("Receive") {
                    transferState.receivePastedPayload()
                }
                .buttonStyle(.borderedProminent)
                .disabled(!transferState.canStartReceive)
                .accessibilityIdentifier("receivePayloadButton")
            }
            .accessibilityElement(children: .contain)
            .accessibilityIdentifier("pastedPayloadSection")
        }
    }

    private var transferStatusSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Label(transferState.statusSummary, systemImage: transferState.phase == .received ? "checkmark.circle.fill" : "arrow.down.circle")
                    .font(.headline)
                Spacer()
                Text(transferState.route.label)
                    .font(.caption.weight(.semibold))
                    .padding(.horizontal, 10)
                    .padding(.vertical, 6)
                    .background(routeBackground)
                    .clipShape(Capsule())
            }

            Text(transferState.statusText)
                .font(.body)

            if let fraction = transferState.progressFraction {
                VStack(alignment: .leading, spacing: 6) {
                    ProgressView(value: fraction)
                    Text("\(transferState.progressCurrent) / \(transferState.progressTotal) bytes")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            } else if transferState.isReceiving {
                ProgressView()
            }

            if !transferState.traceText.isEmpty {
                Text(transferState.traceText)
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
            }

            if let fileURL = transferState.completedFileURL {
                Text("Received file: \(fileURL.lastPathComponent)")
                    .font(.subheadline)
            }

            if let errorText = transferState.errorText {
                Text(errorText)
                    .font(.footnote)
                    .foregroundStyle(.red)
            }
        }
        .padding(16)
        .background(
            RoundedRectangle(cornerRadius: 8)
                .fill(Color(.tertiarySystemBackground))
        )
    }

    private var actionSection: some View {
        HStack(spacing: 12) {
            Button("Cancel Receive") {
                transferState.cancelReceive()
            }
            .buttonStyle(.bordered)
            .disabled(!transferState.isReceiving)
            .accessibilityIdentifier("cancelReceiveButton")

            Button("Export File") {
                transferState.presentExporter()
            }
            .buttonStyle(.borderedProminent)
            .disabled(!transferState.canExport)
            .accessibilityIdentifier("exportReceivedFileButton")
        }
    }

    private var routeBackground: Color {
        switch transferState.route {
        case .unknown:
            return .gray.opacity(0.16)
        case .relay:
            return .orange.opacity(0.18)
        case .direct:
            return .green.opacity(0.18)
        }
    }
}

#Preview {
    ContentView()
}
