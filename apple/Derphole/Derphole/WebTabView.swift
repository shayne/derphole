import SwiftUI

struct WebTabView: View {
    @StateObject private var state: WebTunnelState

    init(tokenStore: TokenStore) {
        _state = StateObject(wrappedValue: WebTunnelState(tokenStore: tokenStore))
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                connectionSection

                if let errorText = state.errorText {
                    Text(errorText)
                        .font(.footnote)
                        .foregroundStyle(.red)
                }

                if let traceText = visibleTraceText {
                    Text(traceText)
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                        .lineLimit(4)
                        .textSelection(.enabled)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(20)
        }
        .accessibilityIdentifier("webTab")
        .navigationTitle("Web")
        .onAppear {
            #if DEBUG
            DispatchQueue.main.async {
                state.openRuntimeInjectedPayloadIfConfigured()
            }
            #endif
        }
        .fullScreenCover(isPresented: $state.isScannerPresented, onDismiss: state.scannerDismissed) {
            ScannerSheet(
                accessibilityIdentifier: "webScannerSheet",
                onPayload: state.acceptScannedPayload,
                onCancel: state.scannerDismissed
            )
        }
        .navigationDestination(
            isPresented: Binding(
                get: { state.isBrowserPresented },
                set: { presented in
                    if !presented {
                        state.browserDismissed()
                    }
                }
            )
        ) {
            if let url = state.browserURL {
                WebBrowserView(
                    url: url,
                    route: state.route,
                    onDisconnect: state.disconnect
                )
            }
        }
    }

    @ViewBuilder
    private var connectionSection: some View {
        if state.isConnecting {
            connectingView
        } else if state.isConnected {
            connectedView
        } else {
            zeroStateView
        }
    }

    private var zeroStateView: some View {
        VStack(alignment: .leading, spacing: 16) {
            Button {
                state.scanStarted()
            } label: {
                Label("Scan QR Code", systemImage: "qrcode.viewfinder")
                    .font(.headline)
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .accessibilityIdentifier("webScanQRCodeButton")

            if let fingerprint = state.rememberedTokenFingerprint {
                VStack(alignment: .leading, spacing: 10) {
                    Label {
                        Text(fingerprint)
                            .font(.caption.monospaced())
                    } icon: {
                        Image(systemName: "key.horizontal")
                    }
                    .foregroundStyle(.secondary)
                    .accessibilityIdentifier("webRememberedToken")

                    Button {
                        state.reconnect()
                    } label: {
                        Label("Reconnect", systemImage: "arrow.clockwise")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.large)
                    .accessibilityIdentifier("webReconnectButton")
                }
            }

            Text(state.statusText)
                .font(.callout)
                .foregroundStyle(.secondary)
        }
    }

    private var connectingView: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(alignment: .firstTextBaseline) {
                Text("Opening tunnel")
                    .font(.headline)
                Spacer()
                routeBadge
            }

            ProgressView()

            Text(state.statusText)
                .font(.callout)
                .foregroundStyle(.secondary)

            Button("Disconnect", role: .destructive) {
                state.disconnect()
            }
            .buttonStyle(.bordered)
            .accessibilityIdentifier("webDisconnectButton")
        }
        .padding(16)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 8))
    }

    private var connectedView: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(alignment: .firstTextBaseline) {
                Label("Connected", systemImage: "checkmark.circle.fill")
                    .font(.headline)
                    .foregroundStyle(.green)
                Spacer()
                routeBadge
            }

            if let browserURL = state.browserURL {
                Text(browserURL.absoluteString)
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
                    .textSelection(.enabled)

                Button {
                    state.isBrowserPresented = true
                } label: {
                    Label("Open Browser", systemImage: "safari")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
            }

            Button(role: .destructive) {
                state.disconnect()
            } label: {
                Label("Disconnect", systemImage: "xmark.circle")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.bordered)
            .controlSize(.large)
            .accessibilityIdentifier("webDisconnectButton")
        }
        .padding(16)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 8))
    }

    private var routeBadge: some View {
        Text(state.route.label)
            .font(.caption.weight(.semibold))
            .padding(.horizontal, 10)
            .padding(.vertical, 6)
            .background(routeBackground)
            .clipShape(Capsule())
    }

    private var routeBackground: Color {
        switch state.route {
        case .unknown:
            return .gray.opacity(0.16)
        case .relay:
            return .orange.opacity(0.18)
        case .direct:
            return .green.opacity(0.18)
        }
    }

    private var visibleTraceText: String? {
        let trace = state.traceText.trimmingCharacters(in: .whitespacesAndNewlines)
        return trace.isEmpty ? nil : trace
    }
}

#Preview {
    NavigationStack {
        WebTabView(tokenStore: TokenStore())
    }
}
