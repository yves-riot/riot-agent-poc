import Foundation

// Mirrors of core/riot-ipc. Keys are camelCase on the wire, so the default coders apply.

struct TargetApp: Codable, Equatable, Identifiable {
    var serviceId: String
    var displayName: String
    var bundleId: String
    var installed: Bool
    var id: String { bundleId }
}

struct TypeCount: Codable, Equatable, Hashable {
    var flag: String
    var label: String
    var count: Int
}

struct RecentEvent: Codable, Equatable, Identifiable {
    var eventId: String
    var at: String
    var kind: String
    var appName: String
    var types: [TypeCount]
    var id: String { eventId + kind }
}

enum PopupView: Equatable {
    case loading
    case notConfigured
    case standby
    case signedIn(name: String, redactions: Int)
    case reconnect
    case error(message: String)
}

extension PopupView: Decodable {
    private enum Keys: String, CodingKey { case kind, name, redactions, message }
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: Keys.self)
        switch try c.decode(String.self, forKey: .kind) {
        case "notConfigured": self = .notConfigured
        case "standby": self = .standby
        case "signedIn":
            self = .signedIn(name: try c.decode(String.self, forKey: .name),
                             redactions: try c.decode(Int.self, forKey: .redactions))
        case "reconnect": self = .reconnect
        case "error": self = .error(message: try c.decode(String.self, forKey: .message))
        default: self = .loading
        }
    }
}

struct PopupState: Decodable, Equatable {
    var view: PopupView
    var botName: String
    var botIconUrl: String?
    var company: String?
    var portalUrl: String?
    var allowBypass: Bool
    var protectedApps: [TargetApp]
    var recentEvents: [RecentEvent]

    static let placeholder = PopupState(
        view: .loading, botName: "Albert", botIconUrl: nil, company: nil, portalUrl: nil,
        allowBypass: false, protectedApps: [], recentEvents: [])
}

struct RedactTextResult: Decodable {
    /// redacted | clean | skipped | error
    var action: String
    var text: String?
    var types: [TypeCount]
    var eventId: String?
    var allowBypass: Bool
}

struct DetokenizeResult: Decodable {
    var text: String
    var replaced: Int
}

struct FileBlocked: Decodable, Equatable {
    var eventId: String
    var fileName: String
    var bundleId: String
    var appName: String
    var types: [TypeCount]
    var allowBypass: Bool
}

enum DaemonEvent {
    case fileBlocked(FileBlocked)
    case stateChanged
}

/// Empty `ok` replies (`null`).
struct Nothing: Decodable {
    init() {}
    init(from decoder: Decoder) throws {}
}
