import Foundation

struct LiveReceiveLaunchConfiguration {
    private static let autostartKey = "DERPHOLE_LIVE_RECEIVE_AUTOSTART"
    private static let tokenKey = "DERPHOLE_LIVE_RECEIVE_TOKEN"
    private static let tokenArgument = "--derphole-live-receive-token"
    static let payloadFileName = "DerpholeLiveReceivePayload.txt"

    static func payload(
        from environment: [String: String],
        arguments: [String] = ProcessInfo.processInfo.arguments,
        fileURL: URL? = defaultPayloadFileURL()
    ) -> String? {
        if let token = argumentValue(after: tokenArgument, in: arguments) {
            return trimmedPayload(token)
        }

        if environment[autostartKey] == "1", let token = trimmedPayload(environment[tokenKey] ?? "") {
            return token
        }

        if let fileURL, let token = try? String(contentsOf: fileURL, encoding: .utf8) {
            return trimmedPayload(token)
        }

        return nil
    }

    static func defaultPayloadFileURL() -> URL {
        FileManager.default.temporaryDirectory.appendingPathComponent(payloadFileName, isDirectory: false)
    }

    private static func argumentValue(after flag: String, in arguments: [String]) -> String? {
        guard let index = arguments.firstIndex(of: flag) else { return nil }
        let valueIndex = arguments.index(after: index)
        guard valueIndex < arguments.endIndex else { return nil }
        return arguments[valueIndex]
    }

    private static func trimmedPayload(_ payload: String) -> String? {
        let token = payload.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !token.isEmpty else { return nil }
        return token
    }
}
