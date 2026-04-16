import AppKit
import Carbon
import Foundation
import JSONSchema
import OSLog

private let log = Logger.service("mail")

private let defaultSearchLimit = 30
private let maxSearchLimit = 500
private let snippetLength = 240

final class MailService: NSObject, Service {
    static let shared = MailService()

    private let scriptQueue = DispatchQueue(label: "me.mattt.iMCP.mail-script")
    private var cachedScript: NSAppleScript?

    var isActivated: Bool {
        get async {
            do {
                _ = try await runHandler("probeAuthorization", arguments: [])
                return true
            } catch {
                return false
            }
        }
    }

    func activate() async throws {
        _ = try await runHandler("probeAuthorization", arguments: [])
    }

    var tools: [Tool] {
        // Placeholder; real tools are added in subsequent commits.
        Tool(
            name: "mail_ping",
            description: "Verify that Mail.app is reachable via AppleEvents",
            inputSchema: .object(properties: [:], additionalProperties: false),
            annotations: .init(
                title: "Mail Ping",
                readOnlyHint: true,
                openWorldHint: false
            )
        ) { _ in
            try await self.activate()
            return Value.object(["ok": .bool(true)])
        }
    }

    // MARK: - AppleScript bridge

    fileprivate enum MailError: LocalizedError {
        case notAuthorized
        case mailNotAvailable
        case scriptCompilationFailed(String)
        case scriptExecutionFailed(code: Int, message: String)
        case invalidArgument(String)

        var errorDescription: String? {
            switch self {
            case .notAuthorized:
                return """
                    Mail automation is not authorized. Open System Settings → \
                    Privacy & Security → Automation and allow iMCP to control Mail.
                    """
            case .mailNotAvailable:
                return "Mail.app is not installed or could not be launched."
            case .scriptCompilationFailed(let message):
                return "Failed to compile AppleScript: \(message)"
            case .scriptExecutionFailed(let code, let message):
                return "AppleScript failed (code \(code)): \(message)"
            case .invalidArgument(let message):
                return message
            }
        }
    }

    fileprivate var scriptSource: String {
        // Handlers exposed to Swift. Every user-supplied value MUST enter via a
        // handler parameter — never interpolated into this source string.
        """
        on probeAuthorization()
            tell application "Mail"
                count of accounts
            end tell
            return true
        end probeAuthorization
        """
    }

    private func loadScript() throws -> NSAppleScript {
        if let cachedScript { return cachedScript }
        guard let script = NSAppleScript(source: scriptSource) else {
            throw MailError.scriptCompilationFailed("NSAppleScript init returned nil")
        }
        var errorInfo: NSDictionary?
        guard script.compileAndReturnError(&errorInfo) else {
            let message = (errorInfo?["NSAppleScriptErrorMessage"] as? String) ?? "unknown"
            throw MailError.scriptCompilationFailed(message)
        }
        cachedScript = script
        return script
    }

    @discardableResult
    fileprivate func runHandler(
        _ handlerName: String,
        arguments: [NSAppleEventDescriptor]
    ) async throws -> NSAppleEventDescriptor {
        try await withCheckedThrowingContinuation { continuation in
            scriptQueue.async {
                do {
                    let script = try self.loadScript()
                    let params = NSAppleEventDescriptor.list()
                    for (offset, descriptor) in arguments.enumerated() {
                        params.insert(descriptor, at: offset + 1)
                    }

                    let target = NSAppleEventDescriptor(
                        processIdentifier: ProcessInfo.processInfo.processIdentifier
                    )
                    let event = NSAppleEventDescriptor(
                        eventClass: AEEventClass(kASAppleScriptSuite),
                        eventID: AEEventID(kASSubroutineEvent),
                        targetDescriptor: target,
                        returnID: AEReturnID(kAutoGenerateReturnID),
                        transactionID: AETransactionID(kAnyTransactionID)
                    )
                    event.setDescriptor(
                        NSAppleEventDescriptor(string: handlerName),
                        forKeyword: AEKeyword(keyASSubroutineName)
                    )
                    event.setDescriptor(params, forKeyword: AEKeyword(keyDirectObject))

                    var errorInfo: NSDictionary?
                    let result = script.executeAppleEvent(event, error: &errorInfo)

                    if let errorInfo = errorInfo as? [String: Any] {
                        let code = errorInfo["NSAppleScriptErrorNumber"] as? Int ?? 0
                        let message =
                            errorInfo["NSAppleScriptErrorMessage"] as? String ?? "unknown"
                        log.error(
                            "Mail AppleScript handler \(handlerName, privacy: .public) failed: [\(code)] \(message, privacy: .public)"
                        )
                        switch code {
                        case -1743, -1744:
                            continuation.resume(throwing: MailError.notAuthorized)
                        case -600, -609, -10000:
                            continuation.resume(throwing: MailError.mailNotAvailable)
                        default:
                            continuation.resume(
                                throwing: MailError.scriptExecutionFailed(
                                    code: code,
                                    message: message
                                )
                            )
                        }
                        return
                    }

                    continuation.resume(returning: result)
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }
}
