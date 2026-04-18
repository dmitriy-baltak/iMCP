import AppKit
import Foundation
import OSLog
import SQLite3
import UniformTypeIdentifiers

private let log = Logger.service("mail.envelope")

private let envelopeBookmarkKey = "me.mattt.iMCP.mailEnvelopeBookmark"
private let defaultMailRoot = "\(NSHomeDirectory())/Library/Mail"

// SQLite destructor tags — used when binding text values that the binding site
// owns (we want SQLite to copy, since the Swift buffer goes away).
private let SQLITE_TRANSIENT_DESTRUCTOR = unsafeBitCast(
    -1, to: sqlite3_destructor_type.self
)

// Mail schema: recipients.type values observed in the wild.
private let recipientTypeTo = 0
private let recipientTypeCc = 1
private let recipientTypeBcc = 2

struct MailEnvelopeFilters {
    var sender: String = ""
    var recipient: String = ""
    var subject: String = ""
    var snippet: String = ""
    var mailboxName: String = ""
    var accountUUID: String = ""
    var start: Date? = nil
    var end: Date? = nil
    var limit: Int = 30
}

struct MailEnvelopeRow {
    let rowId: Int64
    let messageIdHeader: String
    let from: String
    let recipients: String
    let subject: String
    let date: Date?
    let mailboxName: String
    let mailboxURL: String
    let accountUUID: String
    let snippet: String
}

enum MailEnvelopeError: LocalizedError {
    case accessDenied
    case databaseNotFound
    case openFailed(Int32, String)
    case queryFailed(String)
    case userDeclinedAccess
    case securityScopeAccessFailed

    var errorDescription: String? {
        switch self {
        case .accessDenied:
            return """
                Mail data is not accessible. Grant iMCP Full Disk Access in \
                System Settings → Privacy & Security → Full Disk Access, or \
                re-run and select the Envelope Index file when prompted.
                """
        case .databaseNotFound:
            return "Mail's Envelope Index database could not be located."
        case .openFailed(let code, let message):
            return "Failed to open Mail database: [\(code)] \(message)"
        case .queryFailed(let message):
            return "Mail database query failed: \(message)"
        case .userDeclinedAccess:
            return "User declined to grant access to the Mail database."
        case .securityScopeAccessFailed:
            return "Failed to access security-scoped resource for Mail database."
        }
    }
}

final class MailEnvelopeDatabase: NSObject, @unchecked Sendable, NSOpenSavePanelDelegate {
    static let shared = MailEnvelopeDatabase()

    // Guards access to `db` handle.
    private let queue = DispatchQueue(label: "me.mattt.iMCP.mail-envelope")
    private var db: OpaquePointer?
    private var openedPath: String?
    // Security-scoped URL kept live for as long as `db` is open, so SQLite can
    // keep reading the file behind the bookmark.
    private var activeSecurityScopedURL: URL?

    deinit {
        closeDB()
    }

    // MARK: - Access / activation

    var isAccessible: Bool {
        return (try? ensureAccess()) != nil
    }

    /// Opens the database if not already open. Must be called before queries.
    func ensureAccess() throws {
        try queue.sync {
            if db != nil { return }
            try openDatabaseLocked()
        }
    }

    /// If the database cannot be opened with either direct path or stored
    /// bookmark, prompt the user to pick it. Call from activate().
    @MainActor
    func activate() async throws {
        // Fast path: already open or openable from default / bookmark.
        if (try? ensureAccessOrBookmark()) != nil { return }

        // Last resort: ask the user to grant access via a directory picker.
        guard await showAccessAlert() else {
            throw MailEnvelopeError.userDeclinedAccess
        }
        let directoryURL = try await showFilePicker()
        try queue.sync {
            // Clear any stale state before we commit the new scope.
            closeDBLocked()
            guard directoryURL.startAccessingSecurityScopedResource() else {
                throw MailEnvelopeError.securityScopeAccessFailed
            }
            let dbPath = directoryURL
                .appendingPathComponent("Envelope Index", isDirectory: false)
                .path
            do {
                try openDatabaseAtPathLocked(dbPath, securityScopedURL: directoryURL)
            } catch {
                directoryURL.stopAccessingSecurityScopedResource()
                throw error
            }
        }
        // Only persist the bookmark once the open+probe succeeds so we don't
        // trap the user in a prompt loop with a bookmark that can't actually
        // satisfy the query (e.g. picked a file but SQLite needs -wal/-shm).
        storeBookmark(for: directoryURL)
    }

    /// Try the stored directory bookmark first, then the default FDA path.
    /// Bookmark is preferred because if the user has granted scoped access
    /// once, the default path is typically TCC-denied for this process —
    /// probing it repeatedly is what caused the original re-prompt loop.
    private func ensureAccessOrBookmark() throws {
        try queue.sync {
            if db != nil { return }
            if let url = try? resolveBookmarkURL() {
                if url.startAccessingSecurityScopedResource() {
                    let dbPath = url.hasDirectoryPath
                        ? url.appendingPathComponent(
                            "Envelope Index", isDirectory: false
                        ).path
                        : url.path
                    do {
                        try openDatabaseAtPathLocked(dbPath, securityScopedURL: url)
                        return
                    } catch {
                        url.stopAccessingSecurityScopedResource()
                        // fall through to default-path attempt
                    }
                }
            }
            if let path = findDefaultEnvelopePath(),
                FileManager.default.isReadableFile(atPath: path)
            {
                try openDatabaseAtPathLocked(path, securityScopedURL: nil)
                return
            }
            throw MailEnvelopeError.accessDenied
        }
    }

    // MARK: - Queries

    func search(_ filters: MailEnvelopeFilters) throws -> [MailEnvelopeRow] {
        try ensureAccessOrBookmark()
        return try queue.sync { try searchLocked(filters) }
    }

    func findMessage(byRowId rowId: Int64) throws -> MailEnvelopeRow? {
        try ensureAccessOrBookmark()
        return try queue.sync {
            var filters = MailEnvelopeFilters()
            filters.limit = 1
            return try searchLocked(filters, extraWhere: "m.ROWID = ?", extraBind: [.int(rowId)])
                .first
        }
    }

    func findMessage(byMessageIdHeader header: String) throws -> MailEnvelopeRow? {
        try ensureAccessOrBookmark()
        return try queue.sync {
            var filters = MailEnvelopeFilters()
            filters.limit = 1
            return try searchLocked(
                filters,
                extraWhere: "gd.message_id_header = ?",
                extraBind: [.text(header)]
            ).first
        }
    }

    // MARK: - Internal query implementation

    private enum BindValue {
        case text(String)
        case int(Int64)
    }

    private func searchLocked(
        _ filters: MailEnvelopeFilters,
        extraWhere: String? = nil,
        extraBind: [BindValue] = []
    ) throws -> [MailEnvelopeRow] {
        guard let db else { throw MailEnvelopeError.accessDenied }

        // Mailbox-id narrowing. For Gmail (label-backed mailboxes like INBOX,
        // Sent), messages live in the All-Mail mailbox and are linked via
        // `labels`. Non-Gmail mailboxes store messages directly via
        // messages.mailbox. We handle both with an OR.
        var whereParts: [String] = ["m.deleted = 0"]
        var binds: [BindValue] = []

        if !filters.mailboxName.isEmpty || !filters.accountUUID.isEmpty {
            let matchingMailboxIds = try matchingMailboxIdsLocked(
                mailboxName: filters.mailboxName,
                accountUUID: filters.accountUUID
            )
            if matchingMailboxIds.isEmpty {
                return []
            }
            let placeholders = Array(repeating: "?", count: matchingMailboxIds.count).joined(
                separator: ","
            )
            whereParts.append(
                "(m.mailbox IN (\(placeholders)) OR m.ROWID IN (SELECT message_id FROM labels WHERE mailbox_id IN (\(placeholders))))"
            )
            for id in matchingMailboxIds { binds.append(.int(id)) }
            for id in matchingMailboxIds { binds.append(.int(id)) }
        }

        if !filters.sender.isEmpty {
            whereParts.append("(a.address LIKE ? OR a.comment LIKE ?)")
            let wildcard = "%\(escapeLikePattern(filters.sender))%"
            binds.append(.text(wildcard))
            binds.append(.text(wildcard))
        }

        if !filters.subject.isEmpty {
            whereParts.append("s.subject LIKE ? ESCAPE '\\'")
            binds.append(.text("%\(escapeLikePattern(filters.subject))%"))
        }

        if !filters.snippet.isEmpty {
            // Searches the cached body snippet from the `summaries` table.
            // Full-body search is not supported; callers must use mail_fetch
            // for exact body matching.
            whereParts.append(
                "m.summary IN (SELECT ROWID FROM summaries WHERE summary LIKE ? ESCAPE '\\')"
            )
            binds.append(.text("%\(escapeLikePattern(filters.snippet))%"))
        }

        if !filters.recipient.isEmpty {
            whereParts.append(
                """
                m.ROWID IN (
                    SELECT r.message FROM recipients r \
                    JOIN addresses ra ON ra.ROWID = r.address \
                    WHERE ra.address LIKE ? OR ra.comment LIKE ?
                )
                """
            )
            let wildcard = "%\(escapeLikePattern(filters.recipient))%"
            binds.append(.text(wildcard))
            binds.append(.text(wildcard))
        }

        if let start = filters.start {
            whereParts.append("m.date_received >= ?")
            binds.append(.int(Int64(start.timeIntervalSince1970)))
        }
        if let end = filters.end {
            whereParts.append("m.date_received < ?")
            binds.append(.int(Int64(end.timeIntervalSince1970)))
        }

        if let extraWhere {
            whereParts.append(extraWhere)
            binds.append(contentsOf: extraBind)
        }

        let sql = """
            SELECT
                m.ROWID,
                COALESCE(gd.message_id_header, ''),
                a.address,
                a.comment,
                COALESCE(m.subject_prefix, ''),
                s.subject,
                m.date_received,
                mb.url,
                COALESCE(sm.summary, '')
            FROM messages m
            JOIN subjects s ON s.ROWID = m.subject
            JOIN addresses a ON a.ROWID = m.sender
            JOIN mailboxes mb ON mb.ROWID = m.mailbox
            LEFT JOIN message_global_data gd ON gd.ROWID = m.global_message_id
            LEFT JOIN summaries sm ON sm.ROWID = m.summary
            WHERE \(whereParts.joined(separator: " AND "))
            ORDER BY m.date_received DESC
            LIMIT ?
            """

        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK, let stmt else {
            let msg = String(cString: sqlite3_errmsg(db))
            log.error("Mail envelope prepare failed: \(msg, privacy: .public)")
            throw MailEnvelopeError.queryFailed(msg)
        }
        defer { sqlite3_finalize(stmt) }

        var pos: Int32 = 1
        for value in binds {
            bindValue(value, to: stmt, at: pos)
            pos += 1
        }
        sqlite3_bind_int64(stmt, pos, Int64(max(1, filters.limit)))

        var results: [MailEnvelopeRow] = []
        var rowIds: [Int64] = []

        while sqlite3_step(stmt) == SQLITE_ROW {
            let rowId = sqlite3_column_int64(stmt, 0)
            let messageIdHeader = text(stmt, 1)
            let senderAddress = text(stmt, 2)
            let senderComment = text(stmt, 3)
            let subjectPrefix = text(stmt, 4)
            let subject = text(stmt, 5)
            let dateEpoch = sqlite3_column_int64(stmt, 6)
            let mailboxURL = text(stmt, 7)
            let snippet = text(stmt, 8)

            let (mailboxName, accountUUID) = parseMailboxURL(mailboxURL)
            let fullSubject = subjectPrefix.isEmpty ? subject : "\(subjectPrefix) \(subject)"
            let date = dateEpoch > 0
                ? Date(timeIntervalSince1970: TimeInterval(dateEpoch))
                : nil

            results.append(
                MailEnvelopeRow(
                    rowId: rowId,
                    messageIdHeader: messageIdHeader,
                    from: formatAddress(address: senderAddress, comment: senderComment),
                    recipients: "",  // filled in below
                    subject: fullSubject,
                    date: date,
                    mailboxName: mailboxName,
                    mailboxURL: mailboxURL,
                    accountUUID: accountUUID,
                    snippet: snippet
                )
            )
            rowIds.append(rowId)
        }

        if !rowIds.isEmpty {
            let recipientsByRow = try recipientsLocked(rowIds: rowIds)
            for i in 0..<results.count {
                let recips = recipientsByRow[results[i].rowId] ?? ""
                results[i] = MailEnvelopeRow(
                    rowId: results[i].rowId,
                    messageIdHeader: results[i].messageIdHeader,
                    from: results[i].from,
                    recipients: recips,
                    subject: results[i].subject,
                    date: results[i].date,
                    mailboxName: results[i].mailboxName,
                    mailboxURL: results[i].mailboxURL,
                    accountUUID: results[i].accountUUID,
                    snippet: results[i].snippet
                )
            }
        }

        return results
    }

    /// Returns mailbox ROWIDs matching the supplied name/account filters.
    /// Matches case-insensitively against the decoded final path component of
    /// the mailbox URL for `mailboxName`, and against the URL host/authority
    /// for `accountUUID`.
    private func matchingMailboxIdsLocked(
        mailboxName: String,
        accountUUID: String
    ) throws -> [Int64] {
        guard let db else { throw MailEnvelopeError.accessDenied }
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, "SELECT ROWID, url FROM mailboxes", -1, &stmt, nil)
            == SQLITE_OK,
            let stmt
        else {
            throw MailEnvelopeError.queryFailed(
                String(cString: sqlite3_errmsg(db))
            )
        }
        defer { sqlite3_finalize(stmt) }

        let targetMailbox = mailboxName.isEmpty ? nil : mailboxName.lowercased()
        let targetAccount = accountUUID.isEmpty ? nil : accountUUID.lowercased()
        var ids: [Int64] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            let rowId = sqlite3_column_int64(stmt, 0)
            let url = text(stmt, 1)
            let (mbName, acctUUID) = parseMailboxURL(url)
            if let targetMailbox, mbName.lowercased() != targetMailbox {
                continue
            }
            if let targetAccount, acctUUID.lowercased() != targetAccount {
                continue
            }
            ids.append(rowId)
        }
        return ids
    }

    private func recipientsLocked(rowIds: [Int64]) throws -> [Int64: String] {
        guard let db else { throw MailEnvelopeError.accessDenied }
        guard !rowIds.isEmpty else { return [:] }

        let placeholders = Array(repeating: "?", count: rowIds.count).joined(separator: ",")
        let sql = """
            SELECT r.message, r.type, ra.address, ra.comment
            FROM recipients r
            JOIN addresses ra ON ra.ROWID = r.address
            WHERE r.message IN (\(placeholders))
            ORDER BY r.message, r.position
            """
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK, let stmt else {
            throw MailEnvelopeError.queryFailed(String(cString: sqlite3_errmsg(db)))
        }
        defer { sqlite3_finalize(stmt) }

        var pos: Int32 = 1
        for rowId in rowIds {
            sqlite3_bind_int64(stmt, pos, rowId)
            pos += 1
        }

        var buckets: [Int64: (to: [String], cc: [String], bcc: [String])] = [:]
        while sqlite3_step(stmt) == SQLITE_ROW {
            let msg = sqlite3_column_int64(stmt, 0)
            let type = Int(sqlite3_column_int(stmt, 1))
            let address = text(stmt, 2)
            let comment = text(stmt, 3)
            let display = formatAddress(address: address, comment: comment)
            var entry = buckets[msg] ?? (to: [], cc: [], bcc: [])
            switch type {
            case recipientTypeTo: entry.to.append(display)
            case recipientTypeCc: entry.cc.append(display)
            case recipientTypeBcc: entry.bcc.append(display)
            default: entry.to.append(display)
            }
            buckets[msg] = entry
        }

        var joined: [Int64: String] = [:]
        for (rowId, parts) in buckets {
            let combined = (parts.to + parts.cc + parts.bcc).joined(separator: ", ")
            joined[rowId] = combined
        }
        return joined
    }

    // MARK: - SQLite helpers

    private func openDatabaseLocked() throws {
        if let url = try? resolveBookmarkURL() {
            if url.startAccessingSecurityScopedResource() {
                let dbPath = resolveEnvelopeDatabasePath(for: url)
                do {
                    try openDatabaseAtPathLocked(dbPath, securityScopedURL: url)
                    return
                } catch {
                    url.stopAccessingSecurityScopedResource()
                }
            }
        }
        if let path = findDefaultEnvelopePath(),
            FileManager.default.isReadableFile(atPath: path)
        {
            try openDatabaseAtPathLocked(path, securityScopedURL: nil)
            return
        }
        throw MailEnvelopeError.accessDenied
    }

    private func openDatabaseAtPathLocked(
        _ path: String,
        securityScopedURL: URL?
    ) throws {
        var handle: OpaquePointer?
        let flags = SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX | SQLITE_OPEN_URI
        // Use URI form with `mode=ro` so SQLite treats the DB as read-only and
        // never tries to acquire write locks Mail.app holds. We do NOT use
        // immutable=1 because we want to see Mail.app's WAL-journaled updates
        // to the envelope index.
        let uriPath = encodeForSQLiteURI(path)
        let uri = "file:\(uriPath)?mode=ro"
        let rc = sqlite3_open_v2(uri, &handle, flags, nil)
        guard rc == SQLITE_OK, let handle else {
            let msg = handle.flatMap { String(cString: sqlite3_errmsg($0)) } ?? "unknown"
            if let handle { sqlite3_close(handle) }
            throw MailEnvelopeError.openFailed(rc, msg)
        }
        // Short busy timeout in case Mail.app briefly holds a write lock.
        sqlite3_busy_timeout(handle, 500)

        // TCC denies reads on ~/Library/Mail without Full Disk Access, but
        // sqlite3_open_v2 doesn't actually touch the file, so a failure
        // won't surface until the first real query. Probe now so we can
        // reject the default path and try the bookmark/picker fallback.
        var probe: OpaquePointer?
        let probeRc = sqlite3_prepare_v2(
            handle,
            "SELECT 1 FROM sqlite_master LIMIT 1",
            -1,
            &probe,
            nil
        )
        if probeRc == SQLITE_OK, let probe {
            _ = sqlite3_step(probe)
        }
        sqlite3_finalize(probe)
        if probeRc != SQLITE_OK {
            let msg = String(cString: sqlite3_errmsg(handle))
            sqlite3_close(handle)
            throw MailEnvelopeError.openFailed(probeRc, msg)
        }

        db = handle
        openedPath = path
        activeSecurityScopedURL = securityScopedURL
        log.debug("Opened Mail envelope at \(path, privacy: .public)")
    }

    private func closeDB() {
        queue.sync { closeDBLocked() }
    }

    private func closeDBLocked() {
        if let db {
            sqlite3_close(db)
        }
        db = nil
        openedPath = nil
        if let url = activeSecurityScopedURL {
            url.stopAccessingSecurityScopedResource()
        }
        activeSecurityScopedURL = nil
    }

    private func bindValue(_ value: BindValue, to stmt: OpaquePointer, at index: Int32) {
        switch value {
        case .text(let s):
            sqlite3_bind_text(stmt, index, s, -1, SQLITE_TRANSIENT_DESTRUCTOR)
        case .int(let i):
            sqlite3_bind_int64(stmt, index, i)
        }
    }

    private func text(_ stmt: OpaquePointer, _ column: Int32) -> String {
        guard let cString = sqlite3_column_text(stmt, column) else { return "" }
        return String(cString: cString)
    }

    // MARK: - Envelope path discovery

    private func findDefaultEnvelopePath() -> String? {
        let fm = FileManager.default
        // Prefer the newest V-directory. We try a small descending window
        // instead of enumerating contentsOfDirectory, which requires FDA on
        // ~/Library/Mail itself.
        for v in stride(from: 30, through: 1, by: -1) {
            let path = "\(defaultMailRoot)/V\(v)/MailData/Envelope Index"
            if fm.isReadableFile(atPath: path) { return path }
        }
        return nil
    }

    // MARK: - Bookmark / file-picker fallback

    /// Figure out where `Envelope Index` lives given a bookmarked URL. The
    /// bookmark may point directly at the file (legacy scope) or at the
    /// enclosing `MailData` directory (current scope). `hasDirectoryPath`
    /// only reflects the URL string, so fall back to a filesystem probe.
    private func resolveEnvelopeDatabasePath(for url: URL) -> String {
        var isDir: ObjCBool = false
        if FileManager.default.fileExists(atPath: url.path, isDirectory: &isDir),
            isDir.boolValue
        {
            return url.appendingPathComponent("Envelope Index", isDirectory: false)
                .path
        }
        return url.path
    }

    private func resolveBookmarkURL() throws -> URL {
        guard let data = UserDefaults.standard.data(forKey: envelopeBookmarkKey) else {
            throw MailEnvelopeError.accessDenied
        }
        var isStale = false
        let url = try URL(
            resolvingBookmarkData: data,
            options: .withSecurityScope,
            relativeTo: nil,
            bookmarkDataIsStale: &isStale
        )
        return url
    }

    private func storeBookmark(for url: URL) {
        do {
            let data = try url.bookmarkData(
                options: .securityScopeAllowOnlyReadAccess,
                includingResourceValuesForKeys: nil,
                relativeTo: nil
            )
            UserDefaults.standard.set(data, forKey: envelopeBookmarkKey)
        } catch {
            log.error("Failed to store Mail envelope bookmark: \(error.localizedDescription)")
        }
    }

    @MainActor
    private func showAccessAlert() async -> Bool {
        let alert = NSAlert()
        alert.messageText = "Mail Data Access Required"
        alert.informativeText = """
            To search Mail fast, iMCP needs to read Mail's envelope index.

            In the next screen, select the `MailData` folder \
            (inside ~/Library/Mail/V10/) and click "Grant Access". \
            Selecting the folder gives SQLite read access to the envelope \
            index together with its WAL/SHM sidecar files.
            """
        alert.alertStyle = .informational
        alert.addButton(withTitle: "Continue")
        alert.addButton(withTitle: "Cancel")
        return alert.runModal() == .alertFirstButtonReturn
    }

    @MainActor
    private func showFilePicker() async throws -> URL {
        let panel = NSOpenPanel()
        panel.delegate = self
        panel.message = "Please select Mail's `MailData` folder"
        panel.prompt = "Grant Access"
        panel.directoryURL = URL(fileURLWithPath: defaultMailRoot)
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.showsHiddenFiles = true
        guard panel.runModal() == .OK,
            let url = panel.url,
            url.lastPathComponent == "MailData"
        else {
            throw MailEnvelopeError.userDeclinedAccess
        }
        return url
    }

    func panel(_ sender: Any, shouldEnable url: URL) -> Bool {
        // Let the user drill into any directory; the `MailData` gate is
        // enforced after the panel closes.
        return url.hasDirectoryPath
    }
}

// MARK: - URL / display helpers

/// Parses a Mail.app mailbox URL (e.g.
/// `imap://784E358B-.../%5BGmail%5D/INBOX`) into a human-readable mailbox name
/// plus the account UUID. Returns empty strings for unknown schemes rather
/// than throwing — queries must still be runnable even if we can't parse.
private func parseMailboxURL(_ url: String) -> (mailboxName: String, accountUUID: String) {
    guard let components = URLComponents(string: url) else {
        return ("", "")
    }
    let accountUUID = components.host ?? ""
    // The path starts with "/"; percent-decoded it's the mailbox name, which
    // may contain slashes (e.g. "[Gmail]/Вся почта") for nested mailboxes.
    var path = components.percentEncodedPath
    if path.hasPrefix("/") { path.removeFirst() }
    let decoded = path.removingPercentEncoding ?? path
    return (decoded, accountUUID)
}

private func formatAddress(address: String, comment: String) -> String {
    if comment.isEmpty { return address }
    return "\(comment) <\(address)>"
}

private func escapeLikePattern(_ input: String) -> String {
    // Escape SQLite LIKE wildcards (_ and %) plus our escape char.
    var out = ""
    out.reserveCapacity(input.count)
    for ch in input {
        switch ch {
        case "\\", "_", "%": out.append("\\"); out.append(ch)
        default: out.append(ch)
        }
    }
    return out
}

private func encodeForSQLiteURI(_ path: String) -> String {
    // SQLite's URI filename parser treats `?`, `#` specially and needs
    // percent-encoding for them. Spaces must also be encoded. Leading slash
    // stays literal (file:/absolute/path).
    let allowed = CharacterSet(
        charactersIn:
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~/"
    )
    return path.addingPercentEncoding(withAllowedCharacters: allowed) ?? path
}
