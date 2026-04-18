@preconcurrency
protocol Service {
    var isActivated: Bool { get async }
    func activate() async throws

    @ResourceTemplateBuilder var resourceTemplates: [ResourceTemplate] { get }
    @ToolBuilder var tools: [Tool] { get }

    func subscribe(
        resource uri: String,
        onChange: @escaping @Sendable (String) -> Void
    ) async throws -> ResourceSubscriptionToken?
}

extension Service {
    var isActivated: Bool {
        get async {
            return true
        }
    }

    func activate() async throws {}

    var resourceTemplates: [ResourceTemplate] { [] }

    var tools: [Tool] { [] }

    func read(resource uri: String) async throws -> ResourceContent? {
        for template in resourceTemplates {
            if let content = try await template.read(uri: uri) {
                return content
            }
        }
        return nil
    }

    func subscribe(
        resource uri: String,
        onChange: @escaping @Sendable (String) -> Void
    ) async throws -> ResourceSubscriptionToken? {
        nil
    }

    func call(tool name: String, with arguments: [String: Value]) async throws -> Value? {
        for tool in tools where tool.name == name {
            return try await tool.callAsFunction(arguments)
        }

        return nil
    }
}

@resultBuilder
struct ToolBuilder {
    static func buildBlock(_ tools: Tool...) -> [Tool] {
        tools
    }
}

@resultBuilder
struct ResourceTemplateBuilder {
    static func buildBlock(_ templates: ResourceTemplate...) -> [ResourceTemplate] {
        templates
    }
}

struct ResourceSubscriptionToken: Sendable {
    let uri: String
    private let _cancel: @Sendable () -> Void

    init(uri: String, cancel: @escaping @Sendable () -> Void) {
        self.uri = uri
        self._cancel = cancel
    }

    func cancel() {
        _cancel()
    }
}
