import SwiftUI

struct SSHTabView: View {
    @StateObject private var state: SSHTunnelState

    init(tokenStore: TokenStore) {
        _state = StateObject(wrappedValue: SSHTunnelState(tokenStore: tokenStore))
    }

    var body: some View {
        connectionSection
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("sshTab")
        .navigationTitle("SSH")
        .toolbar {
            if state.isConnected {
                ToolbarItem(placement: .topBarTrailing) {
                    Button(role: .destructive) {
                        state.disconnect()
                    } label: {
                        Image(systemName: "xmark.circle")
                    }
                    .accessibilityLabel("Disconnect")
                    .accessibilityIdentifier("sshDisconnectButton")
                }
            }
        }
        .fullScreenCover(isPresented: $state.isScannerPresented, onDismiss: state.scannerDismissed) {
            ScannerSheet(
                accessibilityIdentifier: "sshScannerSheet",
                onPayload: state.acceptScannedPayload,
                onCancel: state.scannerDismissed
            )
        }
        .sheet(isPresented: $state.isCredentialPromptPresented, onDismiss: state.credentialPromptDismissed) {
            SSHCredentialPrompt(
                username: $state.username,
                password: $state.password,
                onCancel: state.cancelCredentialPrompt,
                onConnect: {
                    Task {
                        await state.submitCredentials()
                    }
                }
            )
        }
        #if DEBUG
        .task {
            state.openRuntimeInjectedPayloadIfConfigured()
        }
        #endif
    }

    @ViewBuilder
    private var connectionSection: some View {
        if state.isConnecting {
            paddedContent {
                connectingView
            }
        } else if state.isConnected {
            connectedView
        } else {
            paddedContent {
                zeroStateView
            }
        }
    }

    private func paddedContent<Content: View>(@ViewBuilder content: () -> Content) -> some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                content()

                if let errorText = state.errorText {
                    Text(errorText)
                        .font(.footnote)
                        .foregroundStyle(.red)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(20)
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
            .accessibilityIdentifier("sshScanQRCodeButton")

            if let fingerprint = state.rememberedTokenFingerprint {
                VStack(alignment: .leading, spacing: 10) {
                    Label {
                        Text(fingerprint)
                            .font(.caption.monospaced())
                    } icon: {
                        Image(systemName: "key.horizontal")
                    }
                    .foregroundStyle(.secondary)
                    .accessibilityIdentifier("sshRememberedToken")

                    Button {
                        state.reconnect()
                    } label: {
                        Label("Reconnect", systemImage: "arrow.clockwise")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.large)
                    .accessibilityIdentifier("sshReconnectButton")
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
                Image(systemName: "terminal")
                    .foregroundStyle(.secondary)
            }

            ProgressView()

            Text(state.statusText)
                .font(.callout)
                .foregroundStyle(.secondary)

            Button("Disconnect", role: .destructive) {
                state.disconnect()
            }
            .buttonStyle(.bordered)
            .accessibilityIdentifier("sshDisconnectButton")
        }
        .padding(16)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 8))
    }

    private var connectedView: some View {
        VStack(spacing: 0) {
            HStack(spacing: 10) {
                Label("Connected", systemImage: "checkmark.circle.fill")
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(.green)

                Spacer()

                Text(state.statusText)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 10)
            .background(.bar)

            if let session = state.terminalSession {
                SSHTerminalSurfaceView(session: session, onExit: state.terminalExited)
                    .background(.black)
                    .accessibilityIdentifier("sshTerminalContainer")
            } else {
                ContentUnavailableView("Terminal unavailable", systemImage: "terminal")
            }
        }
    }
}

#Preview {
    NavigationStack {
        SSHTabView(tokenStore: TokenStore())
    }
}
