import SwiftUI
import UIKit

@MainActor
private enum DerpholeGhosttyRuntime {
    private static var app: ghostty_app_t?

    static func appHandle() throws -> ghostty_app_t {
        if let app {
            return app
        }

        let initResult = ghostty_init(0, nil)
        guard initResult == GHOSTTY_SUCCESS else {
            throw SSHConnectionError.terminalInitializationFailed("ghostty_init failed: \(initResult)")
        }

        var runtimeConfig = ghostty_runtime_config_s(
            userdata: nil,
            supports_selection_clipboard: false,
            wakeup_cb: derpholeGhosttyWakeupCallback,
            action_cb: derpholeGhosttyActionCallback,
            read_clipboard_cb: derpholeGhosttyReadClipboardCallback,
            confirm_read_clipboard_cb: derpholeGhosttyConfirmReadClipboardCallback,
            write_clipboard_cb: derpholeGhosttyWriteClipboardCallback,
            close_surface_cb: derpholeGhosttyCloseSurfaceCallback
        )

        guard let config = ghostty_config_new() else {
            throw SSHConnectionError.terminalInitializationFailed("ghostty_config_new failed")
        }
        ghostty_config_finalize(config)
        defer { ghostty_config_free(config) }

        guard let newApp = ghostty_app_new(&runtimeConfig, config) else {
            throw SSHConnectionError.terminalInitializationFailed("ghostty_app_new failed")
        }

        app = newApp
        return newApp
    }

    static func appTick() {
        guard let app else { return }
        ghostty_app_tick(app)
    }
}

nonisolated private func derpholeGhosttyWakeupCallback(_ userdata: UnsafeMutableRawPointer?) {
    Task { @MainActor in
        DerpholeGhosttyRuntime.appTick()
    }
}

nonisolated private func derpholeGhosttyActionCallback(
    _ app: ghostty_app_t?,
    _ target: ghostty_target_s,
    _ action: ghostty_action_s
) -> Bool {
    switch action.tag {
    case GHOSTTY_ACTION_SET_TITLE,
         GHOSTTY_ACTION_PROMPT_TITLE,
         GHOSTTY_ACTION_PROGRESS_REPORT,
         GHOSTTY_ACTION_CELL_SIZE,
         GHOSTTY_ACTION_SCROLLBAR,
         GHOSTTY_ACTION_MOUSE_SHAPE,
         GHOSTTY_ACTION_MOUSE_VISIBILITY,
         GHOSTTY_ACTION_MOUSE_OVER_LINK:
        return true
    default:
        return false
    }
}

nonisolated private func derpholeGhosttyReadClipboardCallback(
    _ userdata: UnsafeMutableRawPointer?,
    _ location: ghostty_clipboard_e,
    _ state: UnsafeMutableRawPointer?
) {}

nonisolated private func derpholeGhosttyConfirmReadClipboardCallback(
    _ userdata: UnsafeMutableRawPointer?,
    _ string: UnsafePointer<CChar>?,
    _ state: UnsafeMutableRawPointer?,
    _ request: ghostty_clipboard_request_e
) {}

nonisolated private func derpholeGhosttyWriteClipboardCallback(
    _ userdata: UnsafeMutableRawPointer?,
    _ location: ghostty_clipboard_e,
    _ contents: UnsafePointer<ghostty_clipboard_content_s>?,
    _ count: Int,
    _ confirm: Bool
) {}

nonisolated private func derpholeGhosttyCloseSurfaceCallback(_ userdata: UnsafeMutableRawPointer?, _ processAlive: Bool) {}

enum TerminalInputKey: Equatable {
    case escape
    case tab
    case enter
    case backspace
    case controlC
    case arrowUp
    case arrowDown
    case arrowLeft
    case arrowRight
}

enum TerminalInputOperation: Equatable {
    case text(String)
    case key(TerminalInputKey)
}

enum TerminalInputTranslator {
    static func deleteOperation() -> TerminalInputOperation {
        .key(.backspace)
    }

    static func insertOperation(for insertedText: String) -> TerminalInputOperation {
        if insertedText == "\n" || insertedText == "\r" {
            return .key(.enter)
        }
        if insertedText == "\t" {
            return .key(.tab)
        }
        return .text(terminalText(for: insertedText))
    }

    static func terminalText(for insertedText: String) -> String {
        insertedText
            .replacingOccurrences(of: "\r\n", with: "\n")
            .replacingOccurrences(of: "\r", with: "\n")
            .replacingOccurrences(of: "\n", with: "\r")
    }
}

@MainActor
final class DerpholeGhosttyTerminalView: UIView, UIKeyInput, UITextInputTraits {
    var onInput: ((Data) -> Void)?
    var onResize: ((Int, Int) -> Void)?

    private var surface: ghostty_surface_t?
    private var lastTerminalSize: (cols: Int, rows: Int)?
    private lazy var toolbar = TerminalAccessoryToolbar(target: self)

    override init(frame: CGRect) {
        super.init(frame: frame)
        backgroundColor = .black
        contentScaleFactor = max(traitCollection.displayScale, 1)
        isMultipleTouchEnabled = true
        isUserInteractionEnabled = true
        isAccessibilityElement = true
        accessibilityIdentifier = "sshTerminalView"
        accessibilityLabel = "SSH Terminal"
        accessibilityTraits.insert(.allowsDirectInteraction)
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    deinit {
        if let surface {
            ghostty_surface_set_write_callback(surface, nil, nil)
            ghostty_surface_free(surface)
        }
    }

    override var canBecomeFirstResponder: Bool { true }
    override var inputAccessoryView: UIView? { toolbar }
    var hasText: Bool { true }
    var keyboardType: UIKeyboardType {
        get { .asciiCapable }
        set {}
    }
    var keyboardAppearance: UIKeyboardAppearance {
        get { .dark }
        set {}
    }
    var returnKeyType: UIReturnKeyType {
        get { .default }
        set {}
    }
    var autocapitalizationType: UITextAutocapitalizationType {
        get { .none }
        set {}
    }
    var autocorrectionType: UITextAutocorrectionType {
        get { .no }
        set {}
    }
    var spellCheckingType: UITextSpellCheckingType {
        get { .no }
        set {}
    }
    var smartQuotesType: UITextSmartQuotesType {
        get { .no }
        set {}
    }
    var smartDashesType: UITextSmartDashesType {
        get { .no }
        set {}
    }
    var smartInsertDeleteType: UITextSmartInsertDeleteType {
        get { .no }
        set {}
    }
    var enablesReturnKeyAutomatically: Bool {
        get { false }
        set {}
    }
    @available(iOS 17.0, *)
    var inlinePredictionType: UITextInlinePredictionType {
        get { .no }
        set {}
    }

    func installSurface() throws {
        guard surface == nil else { return }
        let app = try DerpholeGhosttyRuntime.appHandle()
        var config = ghostty_surface_config_new()
        config.platform_tag = GHOSTTY_PLATFORM_IOS
        config.platform.ios.uiview = Unmanaged.passUnretained(self).toOpaque()
        config.userdata = Unmanaged.passUnretained(self).toOpaque()
        config.scale_factor = Double(contentScaleFactor)
        config.font_size = 10
        config.use_custom_io = true

        guard let cSurface = ghostty_surface_new(app, &config) else {
            throw SSHConnectionError.terminalInitializationFailed("ghostty_surface_new failed")
        }
        surface = cSurface
        installWriteCallback(on: cSurface)
        configureIOSurfaceLayers(size: bounds.size)
        updateSurfaceSize()
        becomeFirstResponder()
    }

    func cleanup() {
        guard let cSurface = surface else { return }
        ghostty_surface_set_write_callback(cSurface, nil, nil)
        ghostty_surface_free(cSurface)
        surface = nil
    }

    override func layoutSubviews() {
        super.layoutSubviews()
        updateSurfaceSize()
    }

    override func touchesBegan(_ touches: Set<UITouch>, with event: UIEvent?) {
        becomeFirstResponder()
        super.touchesBegan(touches, with: event)
    }

    func insertText(_ text: String) {
        sendInputOperation(TerminalInputTranslator.insertOperation(for: text))
    }

    func deleteBackward() {
        sendInputOperation(TerminalInputTranslator.deleteOperation())
    }

    func feedData(_ data: Data) {
        guard let cSurface = surface, !data.isEmpty else { return }
        data.withUnsafeBytes { buffer in
            guard let ptr = buffer.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return }
            ghostty_surface_feed_data(cSurface, ptr, buffer.count)
        }
        redraw()
    }

    func sendText(_ text: String) {
        guard let cSurface = surface, !text.isEmpty else { return }
        text.withCString { ptr in
            ghostty_surface_text(cSurface, ptr, UInt(text.utf8.count))
        }
        redraw()
    }

    private func sendInputOperation(_ operation: TerminalInputOperation) {
        switch operation {
        case .text(let text):
            sendText(text)
        case .key(let key):
            sendTerminalKey(key)
        }
    }

    private func sendTerminalKey(_ key: TerminalInputKey) {
        switch key {
        case .escape:
            sendGhosttyKey(keyCode: 0x0035)
        case .tab:
            sendGhosttyKey(keyCode: 0x0030)
        case .enter:
            sendGhosttyKey(keyCode: 0x0024)
        case .backspace:
            sendGhosttyKey(keyCode: 0x0033)
        case .controlC:
            sendGhosttyKey(keyCode: 0x0008, mods: GHOSTTY_MODS_CTRL, unshiftedCodepoint: UInt32(Character("c").asciiValue ?? 0))
        case .arrowUp:
            sendGhosttyKey(keyCode: 0x007e)
        case .arrowDown:
            sendGhosttyKey(keyCode: 0x007d)
        case .arrowLeft:
            sendGhosttyKey(keyCode: 0x007b)
        case .arrowRight:
            sendGhosttyKey(keyCode: 0x007c)
        }
    }

    private func sendGhosttyKey(
        keyCode: UInt32,
        mods: ghostty_input_mods_e = GHOSTTY_MODS_NONE,
        unshiftedCodepoint: UInt32 = 0
    ) {
        guard let cSurface = surface else { return }
        sendGhosttyKeyEvent(to: cSurface, action: GHOSTTY_ACTION_PRESS, keyCode: keyCode, mods: mods, unshiftedCodepoint: unshiftedCodepoint)
        sendGhosttyKeyEvent(to: cSurface, action: GHOSTTY_ACTION_RELEASE, keyCode: keyCode, mods: mods, unshiftedCodepoint: unshiftedCodepoint)
        redraw()
    }

    private func sendGhosttyKeyEvent(
        to cSurface: ghostty_surface_t,
        action: ghostty_input_action_e,
        keyCode: UInt32,
        mods: ghostty_input_mods_e,
        unshiftedCodepoint: UInt32
    ) {
        var keyEvent = ghostty_input_key_s()
        keyEvent.action = action
        keyEvent.mods = mods
        keyEvent.consumed_mods = GHOSTTY_MODS_NONE
        keyEvent.keycode = keyCode
        keyEvent.text = nil
        keyEvent.unshifted_codepoint = unshiftedCodepoint
        keyEvent.composing = false
        ghostty_surface_key(cSurface, keyEvent)
    }

    private func updateSurfaceSize() {
        guard let cSurface = surface else { return }
        let scale = window?.screen.scale ?? max(traitCollection.displayScale, 1)
        contentScaleFactor = scale
        configureIOSurfaceLayers(size: bounds.size)
        let width = max(UInt32(bounds.width * scale), 1)
        let height = max(UInt32(bounds.height * scale), 1)
        ghostty_surface_set_content_scale(cSurface, scale, scale)
        ghostty_surface_set_size(cSurface, width, height)
        redraw()

        let size = ghostty_surface_size(cSurface)
        let cols = max(Int(size.columns), 1)
        let rows = max(Int(size.rows), 1)
        if lastTerminalSize?.cols != cols || lastTerminalSize?.rows != rows {
            lastTerminalSize = (cols: cols, rows: rows)
            onResize?(cols, rows)
        }
    }

    private func redraw() {
        guard let cSurface = surface else { return }
        ghostty_surface_refresh(cSurface)
        ghostty_surface_draw(cSurface)
        layer.setNeedsDisplay()
        layer.sublayers?.forEach { $0.setNeedsDisplay() }
    }

    private func configureIOSurfaceLayers(size: CGSize) {
        guard let sublayers = layer.sublayers else { return }
        let frame = CGRect(origin: .zero, size: size)
        CATransaction.begin()
        CATransaction.setDisableActions(true)
        for sublayer in sublayers {
            sublayer.frame = frame
            sublayer.contentsScale = contentScaleFactor
        }
        CATransaction.commit()
    }

    private func installWriteCallback(on cSurface: ghostty_surface_t) {
        let userdata = Unmanaged.passUnretained(self).toOpaque()
        ghostty_surface_set_write_callback(cSurface, { userdata, data, len in
            guard let userdata, let data, len > 0 else { return }
            let view = Unmanaged<DerpholeGhosttyTerminalView>.fromOpaque(userdata).takeUnretainedValue()
            view.onInput?(Data(bytes: data, count: len))
        }, userdata)
    }

    @objc fileprivate func sendEscape() { sendTerminalKey(.escape) }
    @objc fileprivate func sendTab() { sendTerminalKey(.tab) }
    @objc fileprivate func sendReturn() { sendTerminalKey(.enter) }
    @objc fileprivate func sendBackspace() { sendTerminalKey(.backspace) }
    @objc fileprivate func sendControlC() { sendTerminalKey(.controlC) }
    @objc fileprivate func sendArrowUp() { sendTerminalKey(.arrowUp) }
    @objc fileprivate func sendArrowDown() { sendTerminalKey(.arrowDown) }
    @objc fileprivate func sendArrowLeft() { sendTerminalKey(.arrowLeft) }
    @objc fileprivate func sendArrowRight() { sendTerminalKey(.arrowRight) }

    override var keyCommands: [UIKeyCommand]? {
        [
            UIKeyCommand(input: UIKeyCommand.inputEscape, modifierFlags: [], action: #selector(sendEscape)),
            UIKeyCommand(input: UIKeyCommand.inputUpArrow, modifierFlags: [], action: #selector(sendArrowUp)),
            UIKeyCommand(input: UIKeyCommand.inputDownArrow, modifierFlags: [], action: #selector(sendArrowDown)),
            UIKeyCommand(input: UIKeyCommand.inputLeftArrow, modifierFlags: [], action: #selector(sendArrowLeft)),
            UIKeyCommand(input: UIKeyCommand.inputRightArrow, modifierFlags: [], action: #selector(sendArrowRight))
        ]
    }
}

private final class TerminalAccessoryToolbar: UIInputView {
    init(target: DerpholeGhosttyTerminalView) {
        super.init(frame: CGRect(x: 0, y: 0, width: 0, height: 48), inputViewStyle: .keyboard)
        setup(target: target)
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    override var intrinsicContentSize: CGSize {
        CGSize(width: UIView.noIntrinsicMetric, height: 48)
    }

    private func setup(target: DerpholeGhosttyTerminalView) {
        autoresizingMask = [.flexibleWidth, .flexibleHeight]
        backgroundColor = UIColor.secondarySystemBackground

        let scrollView = UIScrollView()
        scrollView.translatesAutoresizingMaskIntoConstraints = false
        scrollView.alwaysBounceHorizontal = true
        scrollView.showsHorizontalScrollIndicator = false
        addSubview(scrollView)

        let stackView = UIStackView()
        stackView.translatesAutoresizingMaskIntoConstraints = false
        stackView.axis = .horizontal
        stackView.alignment = .center
        stackView.spacing = 8
        stackView.distribution = .fill
        stackView.setContentHuggingPriority(.required, for: .horizontal)
        stackView.setContentCompressionResistancePriority(.required, for: .horizontal)
        scrollView.addSubview(stackView)

        NSLayoutConstraint.activate([
            scrollView.topAnchor.constraint(equalTo: topAnchor),
            scrollView.bottomAnchor.constraint(equalTo: bottomAnchor),
            scrollView.leadingAnchor.constraint(equalTo: leadingAnchor),
            scrollView.trailingAnchor.constraint(equalTo: trailingAnchor),

            stackView.topAnchor.constraint(equalTo: scrollView.contentLayoutGuide.topAnchor, constant: 6),
            stackView.bottomAnchor.constraint(equalTo: scrollView.contentLayoutGuide.bottomAnchor, constant: -6),
            stackView.leadingAnchor.constraint(equalTo: scrollView.contentLayoutGuide.leadingAnchor, constant: 8),
            stackView.trailingAnchor.constraint(equalTo: scrollView.contentLayoutGuide.trailingAnchor, constant: -8),
            stackView.heightAnchor.constraint(equalTo: scrollView.frameLayoutGuide.heightAnchor, constant: -12)
        ])

        stackView.addArrangedSubview(makeTextButton("Esc", accessibilityLabel: "Escape", accessibilityIdentifier: "sshAccessoryEscapeButton", target: target, action: #selector(target.sendEscape)))
        stackView.addArrangedSubview(makeTextButton("Tab", accessibilityLabel: "Tab", accessibilityIdentifier: "sshAccessoryTabButton", target: target, action: #selector(target.sendTab)))
        stackView.addArrangedSubview(makeTextButton("^C", accessibilityLabel: "Control C", accessibilityIdentifier: "sshAccessoryControlCButton", target: target, action: #selector(target.sendControlC)))
        stackView.addArrangedSubview(makeSeparator())
        stackView.addArrangedSubview(makeIconButton("arrow.left", accessibilityLabel: "Left arrow", accessibilityIdentifier: "sshAccessoryLeftButton", target: target, action: #selector(target.sendArrowLeft)))
        stackView.addArrangedSubview(makeIconButton("arrow.up", accessibilityLabel: "Up arrow", accessibilityIdentifier: "sshAccessoryUpButton", target: target, action: #selector(target.sendArrowUp)))
        stackView.addArrangedSubview(makeIconButton("arrow.down", accessibilityLabel: "Down arrow", accessibilityIdentifier: "sshAccessoryDownButton", target: target, action: #selector(target.sendArrowDown)))
        stackView.addArrangedSubview(makeIconButton("arrow.right", accessibilityLabel: "Right arrow", accessibilityIdentifier: "sshAccessoryRightButton", target: target, action: #selector(target.sendArrowRight)))
    }

    private func makeTextButton(
        _ title: String,
        accessibilityLabel: String,
        accessibilityIdentifier: String,
        target: DerpholeGhosttyTerminalView,
        action: Selector
    ) -> UIButton {
        var configuration = UIButton.Configuration.plain()
        configuration.title = title
        configuration.buttonSize = .small
        configuration.contentInsets = NSDirectionalEdgeInsets(top: 5, leading: 10, bottom: 5, trailing: 10)

        let button = UIButton(configuration: configuration)
        button.addTarget(target, action: action, for: .touchUpInside)
        button.accessibilityLabel = accessibilityLabel
        button.accessibilityIdentifier = accessibilityIdentifier
        button.heightAnchor.constraint(equalToConstant: 36).isActive = true
        button.widthAnchor.constraint(greaterThanOrEqualToConstant: 46).isActive = true
        return button
    }

    private func makeIconButton(
        _ systemName: String,
        accessibilityLabel: String,
        accessibilityIdentifier: String,
        target: DerpholeGhosttyTerminalView,
        action: Selector
    ) -> UIButton {
        var configuration = UIButton.Configuration.plain()
        configuration.image = UIImage(systemName: systemName)
        configuration.buttonSize = .small
        configuration.contentInsets = NSDirectionalEdgeInsets(top: 5, leading: 9, bottom: 5, trailing: 9)

        let button = UIButton(configuration: configuration)
        button.addTarget(target, action: action, for: .touchUpInside)
        button.accessibilityLabel = accessibilityLabel
        button.accessibilityIdentifier = accessibilityIdentifier
        button.heightAnchor.constraint(equalToConstant: 36).isActive = true
        button.widthAnchor.constraint(equalToConstant: 42).isActive = true
        return button
    }

    private func makeSeparator() -> UIView {
        let separator = UIView()
        separator.translatesAutoresizingMaskIntoConstraints = false
        separator.backgroundColor = .separator
        separator.widthAnchor.constraint(equalToConstant: 1).isActive = true
        separator.heightAnchor.constraint(equalToConstant: 26).isActive = true
        return separator
    }
}

struct SSHTerminalSurfaceView: UIViewRepresentable {
    let session: SSHConnectedTerminalSession
    let onExit: () -> Void

    func makeCoordinator() -> Coordinator {
        Coordinator(session: session, onExit: onExit)
    }

    func makeUIView(context: Context) -> DerpholeGhosttyTerminalView {
        let view = DerpholeGhosttyTerminalView()
        view.onInput = { data in
            context.coordinator.write(data)
        }
        view.onResize = { cols, rows in
            context.coordinator.resize(cols: cols, rows: rows)
        }
        do {
            try view.installSurface()
            context.coordinator.startStreaming(to: view)
        } catch {
            let message = "\r\nTerminal failed: \(error.localizedDescription)\r\n"
            view.feedData(Data(message.utf8))
        }
        return view
    }

    func updateUIView(_ uiView: DerpholeGhosttyTerminalView, context: Context) {}

    static func dismantleUIView(_ uiView: DerpholeGhosttyTerminalView, coordinator: Coordinator) {
        coordinator.stop()
        uiView.cleanup()
    }

    final class Coordinator {
        private let session: SSHConnectedTerminalSession
        private let onExit: () -> Void
        private var outputTask: Task<Void, Never>?

        init(session: SSHConnectedTerminalSession, onExit: @escaping () -> Void) {
            self.session = session
            self.onExit = onExit
        }

        func startStreaming(to view: DerpholeGhosttyTerminalView) {
            outputTask?.cancel()
            outputTask = Task {
                for await data in session.output {
                    guard !Task.isCancelled else { return }
                    await MainActor.run {
                        view.feedData(data)
                    }
                }
                guard !Task.isCancelled else { return }
                await MainActor.run {
                    onExit()
                }
            }
        }

        func write(_ data: Data) {
            Task(priority: .userInitiated) { [session] in
                try? await session.write(data)
            }
        }

        func resize(cols: Int, rows: Int) {
            Task(priority: .utility) { [session] in
                try? await session.resize(cols: cols, rows: rows)
            }
        }

        func stop() {
            outputTask?.cancel()
            outputTask = nil
        }
    }
}
