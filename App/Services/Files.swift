import AppKit
import CoreServices
import Foundation
import MCP
import OSLog
import os
import UniformTypeIdentifiers

private let log = Logger.service("files")

private let filesBookmarkKey = "com.baltak.imcp-my.filesFolderBookmark"

private let maxFileSize = 100_000_000
private let maxDirectoryEntries = 1024

final class FilesService: NSObject, Service, @unchecked Sendable {
    static let shared = FilesService()

    private struct WatcherEntry {
        let watcher: FolderWatcher
        var subscribers: [UUID: @Sendable (String) -> Void]
    }

    private let watchersByURI = OSAllocatedUnfairLock<[String: WatcherEntry]>(
        initialState: [:]
    )

    var isActivated: Bool {
        get async {
            bookmarkRoot() != nil
        }
    }

    func activate() async throws {
        // Always prompt on activate — picking the folder is the whole grant.
        // Users toggling Files off and back on should get a fresh picker so
        // they can change the selection without hunting for a separate UI.
        let accepted = await MainActor.run { showAccessAlert() }
        guard accepted else { throw FilesError.userDeclinedAccess }

        let url = try await MainActor.run { try showFolderPicker() }
        guard url.startAccessingSecurityScopedResource() else {
            throw FilesError.securityScopeAccessFailed
        }
        url.stopAccessingSecurityScopedResource()
        storeBookmark(for: url)
    }

    var resourceTemplates: [ResourceTemplate] {
        ResourceTemplate(
            name: "file",
            description: "Read file or directory contents under the folder you granted iMCP-MY access to",
            uriTemplate: "file://{path}",
            mimeType: "application/json"
        ) { [weak self] uri in
            guard let self else { return nil }
            return try await self.read(fileURI: uri)
        }
    }

    func subscribe(
        resource uri: String,
        onChange: @escaping @Sendable (String) -> Void
    ) async throws -> ResourceSubscriptionToken? {
        let fileURL = try resolveScopedURL(from: uri)
        let watchPath = fileURL.hasDirectoryPath
            ? fileURL.path
            : fileURL.deletingLastPathComponent().path

        let subscriberId = UUID()
        watchersByURI.withLock { state in
            if var entry = state[uri] {
                entry.subscribers[subscriberId] = onChange
                state[uri] = entry
            } else {
                let watcher = FolderWatcher(path: watchPath)
                watcher.onChange = { [weak self] in
                    self?.emit(uri: uri)
                }
                watcher.start()
                state[uri] = WatcherEntry(
                    watcher: watcher,
                    subscribers: [subscriberId: onChange]
                )
            }
        }

        return ResourceSubscriptionToken(uri: uri) { [weak self] in
            self?.cancel(uri: uri, subscriberId: subscriberId)
        }
    }

    private func cancel(uri: String, subscriberId: UUID) {
        watchersByURI.withLock { state in
            guard var entry = state[uri] else { return }
            entry.subscribers.removeValue(forKey: subscriberId)
            if entry.subscribers.isEmpty {
                entry.watcher.stop()
                state.removeValue(forKey: uri)
            } else {
                state[uri] = entry
            }
        }
    }

    private func emit(uri: String) {
        let callbacks = watchersByURI.withLock { state -> [@Sendable (String) -> Void] in
            guard let subs = state[uri]?.subscribers else { return [] }
            return Array(subs.values)
        }
        for cb in callbacks {
            cb(uri)
        }
    }

    // MARK: - Reading

    private func read(fileURI: String) async throws -> ResourceContent {
        let fileURL = try resolveScopedURL(from: fileURI)
        guard let root = bookmarkRoot() else {
            throw FilesError.notActivated
        }
        guard root.startAccessingSecurityScopedResource() else {
            throw FilesError.securityScopeAccessFailed
        }
        defer { root.stopAccessingSecurityScopedResource() }

        guard (try? fileURL.checkResourceIsReachable()) == true else {
            throw FilesError.notFound(fileURL.path)
        }

        let values = try fileURL.resourceValues(forKeys: [
            .isDirectoryKey, .fileSizeKey,
        ])

        if values.isDirectory == true {
            let json = try directoryJSON(for: fileURL)
            return .text(json, uri: fileURI, mimeType: "inode/directory+json")
        }

        if let size = values.fileSize, size > maxFileSize {
            throw FilesError.fileTooLarge(size)
        }

        let mimeType = Self.mimeType(for: fileURL)
        if Self.looksTextual(mimeType),
            let text = try? String(contentsOf: fileURL, encoding: .utf8)
        {
            return .text(text, uri: fileURI, mimeType: mimeType)
        }
        let data = try Data(contentsOf: fileURL)
        return .binary(data, uri: fileURI, mimeType: mimeType)
    }

    // MARK: - Bookmark / scope resolution

    private func bookmarkRoot() -> URL? {
        guard let data = UserDefaults.standard.data(forKey: filesBookmarkKey) else {
            return nil
        }
        var isStale = false
        guard
            let url = try? URL(
                resolvingBookmarkData: data,
                options: .withSecurityScope,
                relativeTo: nil,
                bookmarkDataIsStale: &isStale
            )
        else {
            return nil
        }
        return url
    }

    private func storeBookmark(for url: URL) {
        do {
            let data = try url.bookmarkData(
                options: .securityScopeAllowOnlyReadAccess,
                includingResourceValuesForKeys: nil,
                relativeTo: nil
            )
            UserDefaults.standard.set(data, forKey: filesBookmarkKey)
        } catch {
            log.error("Failed to store Files bookmark: \(error.localizedDescription)")
        }
    }

    /// Resolves a `file://...` URI, validates the scheme and that the
    /// requested path resides within the user-bookmarked root.
    private func resolveScopedURL(from uri: String) throws -> URL {
        guard let parsed = URL(string: uri),
            parsed.scheme?.lowercased() == "file"
        else {
            throw FilesError.invalidURI(uri)
        }
        guard let root = bookmarkRoot() else {
            throw FilesError.notActivated
        }
        let requested = URL(fileURLWithPath: parsed.path).standardizedFileURL
        let normalizedRoot = root.standardizedFileURL
        // Resolve symlinks via the filesystem: if a component or the final
        // path is a symlink that escapes the root, reject it. Walks up until
        // it hits an existing ancestor, then realpath's that.
        let resolvedRequested = resolveSymlinks(requested)
        let resolvedRoot = resolveSymlinks(normalizedRoot)
        let reqPath = resolvedRequested.path
        let rootPath = resolvedRoot.path
        guard reqPath == rootPath
            || reqPath.hasPrefix(rootPath + "/")
        else {
            throw FilesError.outOfScope(reqPath)
        }
        return requested
    }

    private func resolveSymlinks(_ url: URL) -> URL {
        // FileManager's destinationOfSymbolicLink only resolves one level.
        // URL.resolvingSymlinksInPath resolves fully, but only for components
        // that exist. For non-existent leaves (e.g. about-to-be-created path),
        // strip leaves until one exists, resolve, and reattach.
        let fm = FileManager.default
        if fm.fileExists(atPath: url.path) {
            return url.resolvingSymlinksInPath()
        }
        var prefix = url
        var trailing: [String] = []
        while !fm.fileExists(atPath: prefix.path),
            prefix.pathComponents.count > 1
        {
            trailing.append(prefix.lastPathComponent)
            prefix.deleteLastPathComponent()
        }
        var resolved = prefix.resolvingSymlinksInPath()
        for component in trailing.reversed() {
            resolved.appendPathComponent(component)
        }
        return resolved
    }

    // MARK: - UI

    @MainActor
    private func showAccessAlert() -> Bool {
        let alert = NSAlert()
        alert.messageText = "Pick a folder to share with iMCP-MY"
        alert.informativeText = """
            iMCP-MY's Files service exposes files only under a single folder \
            you pick here (and its descendants). It never reads anywhere \
            else. You can change the folder later from the menu bar \
            toggle by resetting it.
            """
        alert.alertStyle = .informational
        alert.addButton(withTitle: "Choose Folder…")
        alert.addButton(withTitle: "Cancel")
        return alert.runModal() == .alertFirstButtonReturn
    }

    @MainActor
    private func showFolderPicker() throws -> URL {
        let panel = NSOpenPanel()
        panel.message = "Pick the folder you want to expose to MCP clients"
        panel.prompt = "Grant Access"
        panel.directoryURL = FileManager.default.urls(
            for: .downloadsDirectory, in: .userDomainMask
        ).first
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.showsHiddenFiles = false
        guard panel.runModal() == .OK, let url = panel.url else {
            throw FilesError.userDeclinedAccess
        }
        return url
    }

    // MARK: - Helpers

    private static func mimeType(for url: URL) -> String {
        if let utType = UTType(filenameExtension: url.pathExtension),
            let mime = utType.preferredMIMEType
        {
            return mime
        }
        return "application/octet-stream"
    }

    private static func looksTextual(_ mimeType: String) -> Bool {
        if mimeType.hasPrefix("text/") { return true }
        switch mimeType {
        case "application/json",
            "application/xml",
            "application/x-yaml",
            "application/toml",
            "application/javascript":
            return true
        default:
            return false
        }
    }
}

// MARK: - Directory listing

private struct FileEntry: Codable {
    enum Kind: String, Codable {
        case file
        case directory
    }

    let name: String
    let kind: Kind
    let size: Int?
    let modified: String?
}

private func directoryJSON(for url: URL) throws -> String {
    let contents = try FileManager.default.contentsOfDirectory(
        at: url,
        includingPropertiesForKeys: [
            .isDirectoryKey, .fileSizeKey, .contentModificationDateKey,
        ]
    )
    guard contents.count < maxDirectoryEntries else {
        throw FilesError.directoryTooLarge(contents.count)
    }

    let formatter = ISO8601DateFormatter()
    let entries = contents.compactMap { url -> FileEntry? in
        guard
            let values = try? url.resourceValues(forKeys: [
                .isDirectoryKey, .fileSizeKey, .contentModificationDateKey,
            ])
        else { return nil }
        return FileEntry(
            name: url.lastPathComponent,
            kind: values.isDirectory == true ? .directory : .file,
            size: values.fileSize,
            modified: values.contentModificationDate.map { formatter.string(from: $0) }
        )
    }
    .sorted { $0.name < $1.name }

    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
    let data = try encoder.encode(entries)
    return String(data: data, encoding: .utf8) ?? "[]"
}

// MARK: - FSEvents watcher

private final class FolderWatcher {
    private let path: String
    private let queue = DispatchQueue(label: "com.baltak.imcp-my.files.watch")
    private var stream: FSEventStreamRef?
    var onChange: (() -> Void)?

    init(path: String) {
        self.path = path
    }

    func start() {
        var context = FSEventStreamContext(
            version: 0,
            info: Unmanaged.passUnretained(self).toOpaque(),
            retain: nil,
            release: nil,
            copyDescription: nil
        )
        let callback: FSEventStreamCallback = { _, info, _, _, _, _ in
            guard let info else { return }
            let watcher = Unmanaged<FolderWatcher>.fromOpaque(info).takeUnretainedValue()
            watcher.onChange?()
        }
        let pathsToWatch = [path] as CFArray
        let flags: FSEventStreamCreateFlags = FSEventStreamCreateFlags(
            kFSEventStreamCreateFlagUseCFTypes
                | kFSEventStreamCreateFlagFileEvents
                | kFSEventStreamCreateFlagNoDefer
        )
        stream = FSEventStreamCreate(
            kCFAllocatorDefault,
            callback,
            &context,
            pathsToWatch,
            FSEventStreamEventId(kFSEventStreamEventIdSinceNow),
            0.5,
            flags
        )
        guard let stream else {
            log.error("FSEventStreamCreate failed for \(self.path, privacy: .public)")
            return
        }
        FSEventStreamSetDispatchQueue(stream, queue)
        FSEventStreamStart(stream)
    }

    func stop() {
        guard let stream else { return }
        FSEventStreamStop(stream)
        FSEventStreamInvalidate(stream)
        FSEventStreamRelease(stream)
        self.stream = nil
    }

    deinit {
        stop()
    }
}

// MARK: - Errors

enum FilesError: LocalizedError {
    case notActivated
    case userDeclinedAccess
    case securityScopeAccessFailed
    case invalidURI(String)
    case outOfScope(String)
    case notFound(String)
    case fileTooLarge(Int)
    case directoryTooLarge(Int)

    var errorDescription: String? {
        switch self {
        case .notActivated:
            return "Files service has no folder selected. Activate it first and pick a folder."
        case .userDeclinedAccess:
            return "User declined to pick a folder."
        case .securityScopeAccessFailed:
            return "Failed to start accessing the bookmarked folder."
        case .invalidURI(let uri):
            return "Not a file:// URI: \(uri)"
        case .outOfScope(let path):
            return "Path is outside the folder the user granted iMCP-MY access to: \(path)"
        case .notFound(let path):
            return "File or directory does not exist: \(path)"
        case .fileTooLarge(let size):
            return "File too large to read (\(size) bytes > \(maxFileSize))"
        case .directoryTooLarge(let count):
            return "Directory too large (\(count) entries, max \(maxDirectoryEntries))"
        }
    }
}
