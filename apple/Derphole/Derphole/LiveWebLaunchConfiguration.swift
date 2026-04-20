import Foundation

struct LiveWebLaunchConfiguration {
    private static let payloadKey = "DERPHOLE_LIVE_WEB_PAYLOAD"
    private static let payloadArgument = "--derphole-live-web-payload"

    static func payload(
        from environment: [String: String],
        arguments: [String] = ProcessInfo.processInfo.arguments
    ) -> String? {
        if let payload = argumentValue(after: payloadArgument, in: arguments) {
            return trimmedPayload(payload)
        }

        return trimmedPayload(environment[payloadKey] ?? "")
    }

    static func initialTab(
        environment: [String: String] = ProcessInfo.processInfo.environment,
        arguments: [String] = ProcessInfo.processInfo.arguments
    ) -> AppTab {
        payload(from: environment, arguments: arguments) == nil ? .files : .web
    }

    private static func argumentValue(after flag: String, in arguments: [String]) -> String? {
        guard let index = arguments.firstIndex(of: flag) else { return nil }
        let valueIndex = arguments.index(after: index)
        guard valueIndex < arguments.endIndex else { return nil }
        return arguments[valueIndex]
    }

    private static func trimmedPayload(_ payload: String) -> String? {
        let payload = payload.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !payload.isEmpty else { return nil }
        return payload
    }
}
