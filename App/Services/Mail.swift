import AppKit
import Carbon
import Foundation
import JSONSchema
import OSLog

private let log = Logger.service("mail")

private let defaultSearchLimit = 30
private let maxSearchLimit = 500

extension NSAppleEventDescriptor {
    // AppleScript's `missing value` is a descriptor whose type is cMissingValue
    // ('msng') with zero bytes of data. Passing `data: nil` returns nil, so we
    // must pass an empty Data() instead.
    fileprivate static func mailMissingValue() -> NSAppleEventDescriptor {
        return NSAppleEventDescriptor(
            descriptorType: DescType(cMissingValue),
            data: Data()
        ) ?? NSAppleEventDescriptor.null()
    }
}

final class MailService: NSObject, @unchecked Sendable, Service {
    static let shared = MailService()

    private let scriptQueue = DispatchQueue(label: "com.baltak.imcp-my.mail-script")
    private var cachedScript: NSAppleScript?

    private let accountMappingLock = NSLock()
    private var cachedAccountMapping: [(uuid: String, name: String)]?

    private struct UncheckedBox<T>: @unchecked Sendable { let value: T }

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
        // Eagerly grant access to Mail's envelope index too so the user sees
        // both TCC prompts (AppleEvents automation + sandboxed file scope) at
        // toggle time instead of being surprised on first tool call.
        try await MailEnvelopeDatabase.shared.activate()
    }

    var tools: [Tool] {
        Tool(
            name: "mail_search",
            description: """
                Search Mail messages by sender, recipient, subject, body, \
                date range, mailbox, or account. Reads Mail.app's local \
                envelope index directly, so most queries run in \
                milliseconds across the full mailbox history. By default \
                the `body` filter matches against the cached body snippet; \
                pass `full_body_match: true` together with at least one \
                narrowing filter (sender/recipient/subject/mailbox/account/ \
                date range) to scan each candidate message's full body via \
                AppleScript (slow — seconds-per-mailbox scale). Result rows \
                include `read` and `flagged` when the envelope index \
                exposes those columns. The returned `id` is the envelope- \
                index row id — pass it back as the `id` parameter of \
                `mail_fetch_sanitized` (orchestrator-safe), `mail_classify`, \
                or `mail_fetch_dangerous` (raw, subagent-only).
                """,
            inputSchema: .object(
                properties: [
                    "sender": .string(
                        description: "Match substring in sender name or email address"
                    ),
                    "recipient": .string(
                        description: "Match substring in to/cc/bcc recipient addresses"
                    ),
                    "subject": .string(
                        description: "Match substring in subject"
                    ),
                    "body": .string(
                        description:
                            "Match substring in body. By default matches the cached snippet only; see `full_body_match`."
                    ),
                    "full_body_match": .boolean(
                        description:
                            "When true, `body` is matched against the fetched full body (slow). Requires at least one narrowing filter.",
                        default: .bool(false)
                    ),
                    "mailbox": .string(
                        description: "Restrict to mailbox with this name (e.g. INBOX, Sent)"
                    ),
                    "account": .string(
                        description: "Restrict to account with this name"
                    ),
                    "unread_only": .boolean(
                        description:
                            "When true, return only unread messages. Requires envelope index with a read column.",
                        default: .bool(false)
                    ),
                    "flagged_only": .boolean(
                        description:
                            "When true, return only flagged messages. Requires envelope index with a flagged column.",
                        default: .bool(false)
                    ),
                    "start": .string(
                        description:
                            "Start of the date range (inclusive). If timezone is omitted, local time is assumed. Date-only uses local midnight.",
                        format: .dateTime
                    ),
                    "end": .string(
                        description:
                            "End of the date range (exclusive). If timezone is omitted, local time is assumed. Date-only uses local midnight.",
                        format: .dateTime
                    ),
                    "limit": .integer(
                        description: "Maximum messages to return",
                        default: .int(defaultSearchLimit)
                    ),
                ],
                additionalProperties: false
            ),
            annotations: .init(
                title: "Search Mail",
                readOnlyHint: true,
                openWorldHint: false
            )
        ) { arguments in
            try await self.activate()
            try await MailEnvelopeDatabase.shared.activate()

            let sender = arguments["sender"]?.stringValue ?? ""
            let recipient = arguments["recipient"]?.stringValue ?? ""
            let subject = arguments["subject"]?.stringValue ?? ""
            let body = arguments["body"]?.stringValue ?? ""
            let fullBodyMatch = arguments["full_body_match"]?.boolValue ?? false
            let mailbox = arguments["mailbox"]?.stringValue ?? ""
            let account = arguments["account"]?.stringValue ?? ""
            let unreadOnly = arguments["unread_only"]?.boolValue ?? false
            let flaggedOnly = arguments["flagged_only"]?.boolValue ?? false

            let limit = min(
                max(arguments["limit"]?.intValue ?? defaultSearchLimit, 1),
                maxSearchLimit
            )

            let hasDateFilter = arguments["start"]?.stringValue != nil
                || arguments["end"]?.stringValue != nil
            let hasNarrowingFilter = !sender.isEmpty || !recipient.isEmpty
                || !subject.isEmpty || !mailbox.isEmpty || !account.isEmpty
                || hasDateFilter

            if fullBodyMatch {
                guard !body.isEmpty else {
                    throw MailError.invalidArgument(
                        "`full_body_match` requires a non-empty `body` filter."
                    )
                }
                guard hasNarrowingFilter else {
                    throw MailError.invalidArgument(
                        "`full_body_match` requires at least one narrowing filter: sender, recipient, subject, mailbox, account, start, or end."
                    )
                }
            }

            if unreadOnly && !MailEnvelopeDatabase.shared.supportsReadFlag {
                throw MailError.invalidArgument(
                    "This macOS version's Envelope Index does not expose a read column."
                )
            }
            if flaggedOnly && !MailEnvelopeDatabase.shared.supportsFlaggedFlag {
                throw MailError.invalidArgument(
                    "This macOS version's Envelope Index does not expose a flagged column."
                )
            }

            var filters = MailEnvelopeFilters()
            filters.sender = sender
            filters.recipient = recipient
            filters.subject = subject
            // When full_body_match is requested, skip the snippet filter —
            // we'll scan full bodies after the narrowed query returns.
            filters.snippet = fullBodyMatch ? "" : body
            filters.mailboxName = mailbox
            filters.unreadOnly = unreadOnly
            filters.flaggedOnly = flaggedOnly
            // full_body_match oversamples so the post-filter can whittle
            // down to the requested limit without running a second DB
            // query per page.
            filters.limit = fullBodyMatch ? min(max(limit * 10, 100), maxSearchLimit) : limit

            // Resolve `account` (which may be a display name OR a UUID) to the
            // UUID stored in the envelope index. Bail with an empty list if
            // the caller passed a name that matches no known account, so we
            // don't silently widen the query.
            let mapping = try await self.accountMapping()
            let uuidToName = Dictionary(
                mapping.map { ($0.uuid, $0.name) },
                uniquingKeysWith: { first, _ in first }
            )
            if !account.isEmpty {
                if let match = mapping.first(where: {
                    $0.name.caseInsensitiveCompare(account) == .orderedSame
                }) {
                    filters.accountUUID = match.uuid
                } else if mapping.contains(where: {
                    $0.uuid.caseInsensitiveCompare(account) == .orderedSame
                }) {
                    filters.accountUUID = account
                } else {
                    return Value.array([])
                }
            }

            if let startString = arguments["start"]?.stringValue,
                let parsed = ISO8601DateFormatter.parsedLenientISO8601Date(
                    fromISO8601String: startString
                )
            {
                filters.start = Calendar.current.normalizedStartDate(
                    from: parsed.date,
                    isDateOnly: parsed.isDateOnly
                )
            }
            if let endString = arguments["end"]?.stringValue,
                let parsed = ISO8601DateFormatter.parsedLenientISO8601Date(
                    fromISO8601String: endString
                )
            {
                filters.end = Calendar.current.normalizedEndDate(
                    from: parsed.date,
                    isDateOnly: parsed.isDateOnly
                )
            }

            var rows = try MailEnvelopeDatabase.shared.search(filters)

            if fullBodyMatch {
                log.info("mail_search: full_body_match across \(rows.count) candidate(s)")
                let needle = body.lowercased()
                var matched: [MailEnvelopeRow] = []
                for row in rows {
                    if matched.count >= limit { break }
                    let normalizedMsgId = row.messageIdHeader
                        .trimmingCharacters(in: .whitespacesAndNewlines)
                        .trimmingCharacters(in: CharacterSet(charactersIn: "<>"))
                    let bodyDescriptor: NSAppleEventDescriptor
                    do {
                        bodyDescriptor = try await self.runHandler(
                            "readMessageBody",
                            arguments: [
                                NSAppleEventDescriptor(string: String(row.rowId)),
                                NSAppleEventDescriptor(string: normalizedMsgId),
                            ]
                        )
                    } catch {
                        continue
                    }
                    let rawBody = bodyDescriptor.stringValue ?? ""
                    if rawBody.lowercased().contains(needle) {
                        matched.append(row)
                    }
                }
                rows = matched
                log.info("mail_search: full_body_match matched \(rows.count) message(s)")
            }

            let isoFormatter = ISO8601DateFormatter()
            isoFormatter.formatOptions = [.withInternetDateTime]
            let values: [Value] = rows.map { row in
                let accountName = uuidToName[row.accountUUID] ?? row.accountUUID
                let dateString = row.date.map { isoFormatter.string(from: $0) } ?? ""
                var obj: [String: Value] = [
                    "id": .string(String(row.rowId)),
                    "messageId": .string(row.messageIdHeader),
                    "from": .string(row.from),
                    "recipients": .string(row.recipients),
                    "subject": .string(row.subject),
                    "date": .string(dateString),
                    "mailbox": .string(row.mailboxName),
                    "account": .string(accountName),
                    "snippet": .string(row.snippet),
                ]
                if let read = row.read { obj["read"] = .bool(read) }
                if let flagged = row.flagged { obj["flagged"] = .bool(flagged) }
                return .object(obj)
            }
            return Value.array(values)
        }

        Tool(
            name: "mail_fetch_dangerous",
            description: """
                ⚠ DANGEROUS — returns the raw, attacker-controlled body, full \
                headers blob, and attachment metadata of a single message. The \
                response can carry prompt-injection payloads, embedded \
                credentials, magic links, tracking URLs, and zero-width \
                steganography. Confine to a narrow subagent that does NOT feed \
                its output back into a privileged orchestrator. For \
                orchestrator-safe access use mail_fetch_sanitized or \
                mail_classify.

                Identify the message by Mail.app id or Message-ID header, \
                returning full headers, plain-text body, and attachment metadata. \
                Attachment bytes are never inlined; when include_attachments is \
                true, attachments are saved to a temporary directory and their \
                paths are returned. Response includes `read` and `flagged` when \
                the envelope index exposes those columns.
                """,
            inputSchema: .object(
                properties: [
                    "id": .string(
                        description:
                            "Mail.app-local message id (integer, as returned by mail_search)"
                    ),
                    "message_id": .string(
                        description:
                            "RFC 5322 Message-ID header value, including angle brackets if present"
                    ),
                    "include_attachments": .boolean(
                        description:
                            "When true, save attachments to a temp directory and return their paths",
                        default: .bool(false)
                    ),
                ],
                additionalProperties: false
            ),
            annotations: .init(
                title: "Fetch Mail Message",
                readOnlyHint: true,
                openWorldHint: false
            )
        ) { arguments in
            try await self.activate()
            let localId = arguments["id"]?.stringValue ?? ""
            let messageIdHeader = arguments["message_id"]?.stringValue ?? ""
            let includeAttachments = arguments["include_attachments"]?.boolValue ?? false

            let (envelopeRow, fields) = try await self.fetchDecodedMessageInternal(
                localId: localId,
                messageIdHeader: messageIdHeader,
                includeAttachments: includeAttachments
            )
            // Merge read/flagged from the envelope index when available.
            var merged = fields
            if let row = envelopeRow {
                if let read = row.read { merged["read"] = .bool(read) }
                if let flagged = row.flagged { merged["flagged"] = .bool(flagged) }
            }
            return Value.object(merged)
        }

        Tool(
            name: "mail_fetch_sanitized",
            description: """
                Safe-by-construction variant of mail_fetch_dangerous for use in \
                top-level agent contexts. Returns the same message but with \
                the body run through MailSanitizer: HTML stripped (SwiftSoup), \
                URLs neutralized to `[link: <domain>]`, secrets/OTPs/JWTs/api \
                keys redacted, zero-width chars stripped, and the body capped \
                at `max_chars`. The raw `headers` blob is dropped (only the \
                envelope headers come back as named fields), `bcc` is dropped \
                (Mail's scripting interface does not return it reliably), and \
                attachment metadata is sanitized (no `path`, no bytes on disk, \
                MIME type allowlisted).
                """,
            inputSchema: .object(
                properties: [
                    "id": .string(
                        description:
                            "Mail.app-local message id (integer, as returned by mail_search)"
                    ),
                    "message_id": .string(
                        description:
                            "RFC 5322 Message-ID header value, including angle brackets if present"
                    ),
                    "max_chars": .integer(
                        description:
                            "Maximum sanitized body length in characters (clamped to [500, 50000]); default 10000",
                        default: .int(MailSanitizer.defaultMaxChars)
                    ),
                ],
                additionalProperties: false
            ),
            annotations: .init(
                title: "Fetch Mail Message (Sanitized)",
                readOnlyHint: true,
                openWorldHint: false
            )
        ) { arguments in
            try await self.activate()
            let localId = arguments["id"]?.stringValue ?? ""
            let messageIdHeader = arguments["message_id"]?.stringValue ?? ""
            let requestedMax = arguments["max_chars"]?.intValue
                ?? MailSanitizer.defaultMaxChars
            let maxChars = MailSanitizer.clampMaxChars(requestedMax)

            let (envelopeRow, fields) = try await self.fetchDecodedMessageInternal(
                localId: localId,
                messageIdHeader: messageIdHeader,
                includeAttachments: false
            )
            return Value.object(self.buildSanitizedMessage(
                fields: fields,
                envelopeRow: envelopeRow,
                maxChars: maxChars
            ))
        }

        Tool(
            name: "mail_classify",
            description: """
                Schema-locked classification of a message. Returns ONLY \
                envelope metadata (from, to, subject, date, messageId, \
                inReplyTo, references), a coarse `classification` enum \
                (personal / transactional / marketing / automated / \
                notification / unknown), `extracted` signals (senderDomain, \
                linkCount, hasAttachments, attachmentCount, hasOtpOrCode, \
                hasMagicLink, bodyLength), plus `isHuman` and \
                `lowEngagement` flags. All keys are camelCase. The response \
                is guaranteed to never contain `body`, `content`, `raw`, \
                `excerpt`, `summary`, or `headers` fields — safe to expose \
                to a top-level orchestrator agent. If you need any prose \
                from the body (sentence preview, sender intent, etc.) call \
                `mail_fetch_sanitized` from the body-reader subagent — body \
                prose can carry prompt-injection that this tool deliberately \
                does not return.
                """,
            inputSchema: .object(
                properties: [
                    "id": .string(
                        description:
                            "Mail.app-local message id (integer, as returned by mail_search)"
                    ),
                    "message_id": .string(
                        description:
                            "RFC 5322 Message-ID header value, including angle brackets if present"
                    ),
                ],
                additionalProperties: false
            ),
            annotations: .init(
                title: "Classify Mail Message",
                readOnlyHint: true,
                openWorldHint: false
            )
        ) { arguments in
            try await self.activate()
            let localId = arguments["id"]?.stringValue ?? ""
            let messageIdHeader = arguments["message_id"]?.stringValue ?? ""

            let (_, fields) = try await self.fetchDecodedMessageInternal(
                localId: localId,
                messageIdHeader: messageIdHeader,
                includeAttachments: false
            )
            return self.classifyMessage(fields: fields)
        }

        Tool(
            name: "mail_send",
            description: """
                Compose and send a message via Mail.app using the user's default \
                outgoing account. Attachments are referenced by absolute \
                filesystem path.
                """,
            inputSchema: .object(
                properties: [
                    "to": .array(
                        description: "To addresses",
                        items: .string()
                    ),
                    "cc": .array(
                        description: "Cc addresses",
                        items: .string()
                    ),
                    "bcc": .array(
                        description: "Bcc addresses",
                        items: .string()
                    ),
                    "subject": .string(description: "Message subject"),
                    "body": .string(description: "Message body"),
                    "isHTML": .boolean(
                        description:
                            "Hint that body is HTML. Currently sent as plain text; see docs.",
                        default: .bool(false)
                    ),
                    "attachments": .array(
                        description: "Absolute filesystem paths to attach",
                        items: .string()
                    ),
                ],
                required: ["to", "subject", "body"],
                additionalProperties: false
            ),
            annotations: .init(
                title: "Send Mail",
                destructiveHint: true,
                openWorldHint: true
            )
        ) { arguments in
            try await self.activate()

            let toList = arguments["to"]?.arrayValue?.compactMap { $0.stringValue } ?? []
            let ccList = arguments["cc"]?.arrayValue?.compactMap { $0.stringValue } ?? []
            let bccList = arguments["bcc"]?.arrayValue?.compactMap { $0.stringValue } ?? []
            let subject = arguments["subject"]?.stringValue ?? ""
            let body = arguments["body"]?.stringValue ?? ""
            let isHTML = arguments["isHTML"]?.boolValue ?? false
            let attachmentPaths =
                arguments["attachments"]?.arrayValue?.compactMap { $0.stringValue } ?? []

            guard !toList.isEmpty else {
                throw MailError.invalidArgument("`to` must contain at least one address.")
            }

            for path in attachmentPaths {
                guard FileManager.default.fileExists(atPath: path) else {
                    throw MailError.invalidArgument("Attachment not found: \(path)")
                }
            }

            func stringList(_ items: [String]) -> NSAppleEventDescriptor {
                let list = NSAppleEventDescriptor.list()
                for (offset, item) in items.enumerated() {
                    list.insert(NSAppleEventDescriptor(string: item), at: offset + 1)
                }
                return list
            }

            let result = try await self.runHandler(
                "sendMessage",
                arguments: [
                    NSAppleEventDescriptor(string: subject),
                    NSAppleEventDescriptor(string: body),
                    stringList(toList),
                    stringList(ccList),
                    stringList(bccList),
                    NSAppleEventDescriptor(boolean: isHTML),
                    stringList(attachmentPaths),
                ]
            )

            let status = result.stringValue ?? "sent"
            return Value.object([
                "status": .string(status),
                "to": .array(toList.map { .string($0) }),
                "subject": .string(subject),
            ])
        }

        Tool(
            name: "mail_threads",
            description: """
                Return every message in the same conversation as the \
                source message, newest-first. Drafts and trashed \
                messages are excluded (mirrors Mail.app's conversation \
                view). Identify the source by envelope rowid (`id`) or \
                Message-ID header. When Mail's envelope index exposes a \
                conversation id, results come from the index directly; \
                otherwise a References/In-Reply-To header walk \
                reconstructs the thread at best effort.
                """,
            inputSchema: .object(
                properties: [
                    "id": .string(
                        description:
                            "Envelope-index rowid (as returned by mail_search)"
                    ),
                    "message_id": .string(
                        description:
                            "RFC 5322 Message-ID header value (angle brackets optional)"
                    ),
                    "limit": .integer(
                        description: "Maximum messages to return",
                        default: .int(50)
                    ),
                ],
                additionalProperties: false
            ),
            annotations: .init(
                title: "List Mail Thread",
                readOnlyHint: true,
                openWorldHint: false
            )
        ) { arguments in
            try await self.activate()
            try await MailEnvelopeDatabase.shared.activate()

            let localId = arguments["id"]?.stringValue ?? ""
            let messageIdHeader = arguments["message_id"]?.stringValue ?? ""
            let limit = min(max(arguments["limit"]?.intValue ?? 50, 1), maxSearchLimit)

            guard !localId.isEmpty || !messageIdHeader.isEmpty else {
                throw MailError.invalidArgument(
                    "Provide either `id` or `message_id` to identify the message."
                )
            }

            var sourceRow: MailEnvelopeRow?
            if let rowId = Int64(localId), rowId > 0 {
                sourceRow = try? MailEnvelopeDatabase.shared.findMessage(byRowId: rowId)
            }
            if sourceRow == nil, !messageIdHeader.isEmpty {
                let trimmed = messageIdHeader
                    .trimmingCharacters(in: .whitespacesAndNewlines)
                    .trimmingCharacters(in: CharacterSet(charactersIn: "<>"))
                sourceRow = try? MailEnvelopeDatabase.shared.findMessage(
                    byMessageIdHeader: trimmed
                )
            }
            guard let source = sourceRow else {
                return Value.array([])
            }

            var rows: [MailEnvelopeRow] = []
            if let convId = source.conversationId {
                rows = (try? MailEnvelopeDatabase.shared.findThread(
                    conversationId: convId,
                    limit: limit,
                    excludeDraftsAndTrash: true
                )) ?? []
            }

            if rows.isEmpty {
                log.info(
                    "mail_threads: conversation_id unavailable; using header-walk fallback"
                )
                rows = try await self.threadByHeaderWalk(source: source, limit: limit)
            }

            let mapping = try await self.accountMapping()
            let uuidToName = Dictionary(
                mapping.map { ($0.uuid, $0.name) },
                uniquingKeysWith: { first, _ in first }
            )
            let isoFormatter = ISO8601DateFormatter()
            isoFormatter.formatOptions = [.withInternetDateTime]
            let values: [Value] = rows.map { row in
                let accountName = uuidToName[row.accountUUID] ?? row.accountUUID
                let dateString = row.date.map { isoFormatter.string(from: $0) } ?? ""
                return .object([
                    "id": .string(String(row.rowId)),
                    "messageId": .string(row.messageIdHeader),
                    "from": .string(row.from),
                    "recipients": .string(row.recipients),
                    "subject": .string(row.subject),
                    "date": .string(dateString),
                    "mailbox": .string(row.mailboxName),
                    "account": .string(accountName),
                    "snippet": .string(row.snippet),
                ])
            }
            return Value.array(values)
        }

        Tool(
            name: "mail_delete",
            description: """
                Move a Mail message to Trash. Identify the message by its \
                envelope rowid (`id` from mail_search) or its Message-ID \
                header. Deletion is reversible via Mail's Trash mailbox.
                """,
            inputSchema: .object(
                properties: [
                    "id": .string(
                        description:
                            "Envelope-index rowid (as returned by mail_search)"
                    ),
                    "message_id": .string(
                        description:
                            "RFC 5322 Message-ID header value (angle brackets optional)"
                    ),
                ],
                additionalProperties: false
            ),
            annotations: .init(
                title: "Delete Mail Message",
                destructiveHint: true,
                openWorldHint: false
            )
        ) { arguments in
            try await self.activate()

            let localId = arguments["id"]?.stringValue ?? ""
            var messageIdHeader = arguments["message_id"]?.stringValue ?? ""

            guard !localId.isEmpty || !messageIdHeader.isEmpty else {
                throw MailError.invalidArgument(
                    "Provide either `id` or `message_id` to identify the message."
                )
            }

            if messageIdHeader.isEmpty, let rowId = Int64(localId) {
                try? await MailEnvelopeDatabase.shared.activate()
                if let envRow = try? MailEnvelopeDatabase.shared.findMessage(byRowId: rowId),
                    !envRow.messageIdHeader.isEmpty
                {
                    messageIdHeader = envRow.messageIdHeader
                }
            }

            let normalizedMessageId = messageIdHeader
                .trimmingCharacters(in: .whitespacesAndNewlines)
                .trimmingCharacters(in: CharacterSet(charactersIn: "<>"))

            let result = try await self.runHandler(
                "deleteMessage",
                arguments: [
                    NSAppleEventDescriptor(string: localId),
                    NSAppleEventDescriptor(string: normalizedMessageId),
                ]
            )
            let status = result.stringValue ?? "deleted"
            return Value.object([
                "status": .string(status),
                "messageId": .string(normalizedMessageId),
            ])
        }

        Tool(
            name: "mail_reply",
            description: """
                Reply to a Mail message, preserving threading headers \
                (In-Reply-To, References) and the `Re:` subject prefix. \
                Identify the source by envelope rowid (`id` from \
                mail_search) or Message-ID header. Set `reply_all` to \
                reply to every recipient of the source; set \
                `send: false` to save the reply as a draft instead.
                """,
            inputSchema: .object(
                properties: [
                    "id": .string(
                        description:
                            "Envelope-index rowid (as returned by mail_search)"
                    ),
                    "message_id": .string(
                        description:
                            "RFC 5322 Message-ID header value (angle brackets optional)"
                    ),
                    "body": .string(description: "Reply body"),
                    "reply_all": .boolean(
                        description: "Reply to every recipient of the source message",
                        default: .bool(false)
                    ),
                    "additional_cc": .array(
                        description: "Extra Cc addresses to add on top of the reply defaults",
                        items: .string()
                    ),
                    "additional_bcc": .array(
                        description: "Extra Bcc addresses to add",
                        items: .string()
                    ),
                    "attachments": .array(
                        description: "Absolute filesystem paths to attach",
                        items: .string()
                    ),
                    "send": .boolean(
                        description: "Send immediately (true) or save as draft (false)",
                        default: .bool(true)
                    ),
                ],
                required: ["body"],
                additionalProperties: false
            ),
            annotations: .init(
                title: "Reply to Mail Message",
                destructiveHint: true,
                openWorldHint: true
            )
        ) { arguments in
            try await self.activate()

            let localId = arguments["id"]?.stringValue ?? ""
            var messageIdHeader = arguments["message_id"]?.stringValue ?? ""
            let body = arguments["body"]?.stringValue ?? ""
            let replyAll = arguments["reply_all"]?.boolValue ?? false
            let additionalCc =
                arguments["additional_cc"]?.arrayValue?.compactMap { $0.stringValue } ?? []
            let additionalBcc =
                arguments["additional_bcc"]?.arrayValue?.compactMap { $0.stringValue } ?? []
            let attachmentPaths =
                arguments["attachments"]?.arrayValue?.compactMap { $0.stringValue } ?? []
            let shouldSend = arguments["send"]?.boolValue ?? true

            guard !localId.isEmpty || !messageIdHeader.isEmpty else {
                throw MailError.invalidArgument(
                    "Provide either `id` or `message_id` to identify the message."
                )
            }

            for path in attachmentPaths {
                guard FileManager.default.fileExists(atPath: path) else {
                    throw MailError.invalidArgument("Attachment not found: \(path)")
                }
            }

            if messageIdHeader.isEmpty, let rowId = Int64(localId) {
                try? await MailEnvelopeDatabase.shared.activate()
                if let envRow = try? MailEnvelopeDatabase.shared.findMessage(byRowId: rowId),
                    !envRow.messageIdHeader.isEmpty
                {
                    messageIdHeader = envRow.messageIdHeader
                }
            }

            let normalizedMessageId = messageIdHeader
                .trimmingCharacters(in: .whitespacesAndNewlines)
                .trimmingCharacters(in: CharacterSet(charactersIn: "<>"))

            func stringList(_ items: [String]) -> NSAppleEventDescriptor {
                let list = NSAppleEventDescriptor.list()
                for (offset, item) in items.enumerated() {
                    list.insert(NSAppleEventDescriptor(string: item), at: offset + 1)
                }
                return list
            }

            let result = try await self.runHandler(
                "replyMessage",
                arguments: [
                    NSAppleEventDescriptor(string: localId),
                    NSAppleEventDescriptor(string: normalizedMessageId),
                    NSAppleEventDescriptor(string: body),
                    NSAppleEventDescriptor(boolean: replyAll),
                    stringList(additionalCc),
                    stringList(additionalBcc),
                    stringList(attachmentPaths),
                    NSAppleEventDescriptor(boolean: !shouldSend),
                ]
            )

            var status = shouldSend ? "sent" : "saved"
            var subjectOut = ""
            var toOut = ""
            if result.descriptorType == typeAEList {
                status = result.atIndex(1)?.stringValue ?? status
                subjectOut = result.atIndex(2)?.stringValue ?? ""
                toOut = result.atIndex(3)?.stringValue ?? ""
            }
            return Value.object([
                "status": .string(status),
                "subject": .string(subjectOut),
                "to": .string(toOut),
            ])
        }

        Tool(
            name: "mail_forward",
            description: """
                Forward a Mail message, preserving the quoted content \
                and the `Fwd:` subject prefix. Identify the source by \
                envelope rowid (`id` from mail_search) or Message-ID \
                header. Set `send: false` to save the forward as a \
                draft instead.
                """,
            inputSchema: .object(
                properties: [
                    "id": .string(
                        description:
                            "Envelope-index rowid (as returned by mail_search)"
                    ),
                    "message_id": .string(
                        description:
                            "RFC 5322 Message-ID header value (angle brackets optional)"
                    ),
                    "to": .array(
                        description: "To addresses",
                        items: .string()
                    ),
                    "cc": .array(
                        description: "Cc addresses",
                        items: .string()
                    ),
                    "bcc": .array(
                        description: "Bcc addresses",
                        items: .string()
                    ),
                    "body": .string(
                        description:
                            "Preface added above the forwarded content. May be empty."
                    ),
                    "attachments": .array(
                        description: "Absolute filesystem paths to attach",
                        items: .string()
                    ),
                    "send": .boolean(
                        description: "Send immediately (true) or save as draft (false)",
                        default: .bool(true)
                    ),
                ],
                required: ["to"],
                additionalProperties: false
            ),
            annotations: .init(
                title: "Forward Mail Message",
                destructiveHint: true,
                openWorldHint: true
            )
        ) { arguments in
            try await self.activate()

            let localId = arguments["id"]?.stringValue ?? ""
            var messageIdHeader = arguments["message_id"]?.stringValue ?? ""
            let toList = arguments["to"]?.arrayValue?.compactMap { $0.stringValue } ?? []
            let ccList = arguments["cc"]?.arrayValue?.compactMap { $0.stringValue } ?? []
            let bccList = arguments["bcc"]?.arrayValue?.compactMap { $0.stringValue } ?? []
            let body = arguments["body"]?.stringValue ?? ""
            let attachmentPaths =
                arguments["attachments"]?.arrayValue?.compactMap { $0.stringValue } ?? []
            let shouldSend = arguments["send"]?.boolValue ?? true

            guard !localId.isEmpty || !messageIdHeader.isEmpty else {
                throw MailError.invalidArgument(
                    "Provide either `id` or `message_id` to identify the message."
                )
            }
            guard !toList.isEmpty else {
                throw MailError.invalidArgument("`to` must contain at least one address.")
            }
            for path in attachmentPaths {
                guard FileManager.default.fileExists(atPath: path) else {
                    throw MailError.invalidArgument("Attachment not found: \(path)")
                }
            }

            if messageIdHeader.isEmpty, let rowId = Int64(localId) {
                try? await MailEnvelopeDatabase.shared.activate()
                if let envRow = try? MailEnvelopeDatabase.shared.findMessage(byRowId: rowId),
                    !envRow.messageIdHeader.isEmpty
                {
                    messageIdHeader = envRow.messageIdHeader
                }
            }

            let normalizedMessageId = messageIdHeader
                .trimmingCharacters(in: .whitespacesAndNewlines)
                .trimmingCharacters(in: CharacterSet(charactersIn: "<>"))

            func stringList(_ items: [String]) -> NSAppleEventDescriptor {
                let list = NSAppleEventDescriptor.list()
                for (offset, item) in items.enumerated() {
                    list.insert(NSAppleEventDescriptor(string: item), at: offset + 1)
                }
                return list
            }

            let result = try await self.runHandler(
                "forwardMessage",
                arguments: [
                    NSAppleEventDescriptor(string: localId),
                    NSAppleEventDescriptor(string: normalizedMessageId),
                    NSAppleEventDescriptor(string: body),
                    stringList(toList),
                    stringList(ccList),
                    stringList(bccList),
                    stringList(attachmentPaths),
                    NSAppleEventDescriptor(boolean: !shouldSend),
                ]
            )

            var status = shouldSend ? "sent" : "saved"
            var subjectOut = ""
            var toOut = ""
            if result.descriptorType == typeAEList {
                status = result.atIndex(1)?.stringValue ?? status
                subjectOut = result.atIndex(2)?.stringValue ?? ""
                toOut = result.atIndex(3)?.stringValue ?? ""
            }
            return Value.object([
                "status": .string(status),
                "subject": .string(subjectOut),
                "to": .string(toOut),
            ])
        }

        Tool(
            name: "mail_move",
            description: """
                Move a Mail message to a different mailbox. Identify the \
                source by envelope rowid (`id` from mail_search) or \
                Message-ID header. When the target mailbox belongs to a \
                different account than the source, pass `account` to \
                disambiguate; otherwise the source's account is used.
                """,
            inputSchema: .object(
                properties: [
                    "id": .string(
                        description:
                            "Envelope-index rowid (as returned by mail_search)"
                    ),
                    "message_id": .string(
                        description:
                            "RFC 5322 Message-ID header value (angle brackets optional)"
                    ),
                    "mailbox": .string(
                        description:
                            "Target mailbox name (as listed by mail_list_mailboxes)"
                    ),
                    "account": .string(
                        description:
                            "Target account name; defaults to the source message's account"
                    ),
                ],
                required: ["mailbox"],
                additionalProperties: false
            ),
            annotations: .init(
                title: "Move Mail Message",
                destructiveHint: true,
                openWorldHint: false
            )
        ) { arguments in
            try await self.activate()

            let localId = arguments["id"]?.stringValue ?? ""
            var messageIdHeader = arguments["message_id"]?.stringValue ?? ""
            let mailboxName = arguments["mailbox"]?.stringValue ?? ""
            let accountName = arguments["account"]?.stringValue ?? ""

            guard !localId.isEmpty || !messageIdHeader.isEmpty else {
                throw MailError.invalidArgument(
                    "Provide either `id` or `message_id` to identify the message."
                )
            }
            guard !mailboxName.isEmpty else {
                throw MailError.invalidArgument("`mailbox` must be provided.")
            }

            if messageIdHeader.isEmpty, let rowId = Int64(localId) {
                try? await MailEnvelopeDatabase.shared.activate()
                if let envRow = try? MailEnvelopeDatabase.shared.findMessage(byRowId: rowId),
                    !envRow.messageIdHeader.isEmpty
                {
                    messageIdHeader = envRow.messageIdHeader
                }
            }

            let normalizedMessageId = messageIdHeader
                .trimmingCharacters(in: .whitespacesAndNewlines)
                .trimmingCharacters(in: CharacterSet(charactersIn: "<>"))

            let result = try await self.runHandler(
                "moveMessage",
                arguments: [
                    NSAppleEventDescriptor(string: localId),
                    NSAppleEventDescriptor(string: normalizedMessageId),
                    NSAppleEventDescriptor(string: mailboxName),
                    NSAppleEventDescriptor(string: accountName),
                ]
            )

            var status = "moved"
            var mailboxOut = mailboxName
            var accountOut = accountName
            if result.descriptorType == typeAEList {
                status = result.atIndex(1)?.stringValue ?? "moved"
                mailboxOut = result.atIndex(2)?.stringValue ?? mailboxName
                accountOut = result.atIndex(3)?.stringValue ?? accountName
            }
            return Value.object([
                "status": .string(status),
                "mailbox": .string(mailboxOut),
                "account": .string(accountOut),
            ])
        }

        Tool(
            name: "mail_mark_read",
            description: """
                Mark a Mail message as read or unread. Identify by \
                envelope rowid (`id` from mail_search) or Message-ID \
                header. Pass `read: false` to mark unread.
                """,
            inputSchema: .object(
                properties: [
                    "id": .string(
                        description:
                            "Envelope-index rowid (as returned by mail_search)"
                    ),
                    "message_id": .string(
                        description:
                            "RFC 5322 Message-ID header value (angle brackets optional)"
                    ),
                    "read": .boolean(
                        description: "Mark read (true) or unread (false)",
                        default: .bool(true)
                    ),
                ],
                additionalProperties: false
            ),
            annotations: .init(
                title: "Mark Mail Read/Unread",
                readOnlyHint: false,
                destructiveHint: false,
                openWorldHint: false
            )
        ) { arguments in
            try await self.activate()

            let localId = arguments["id"]?.stringValue ?? ""
            var messageIdHeader = arguments["message_id"]?.stringValue ?? ""
            let readState = arguments["read"]?.boolValue ?? true

            guard !localId.isEmpty || !messageIdHeader.isEmpty else {
                throw MailError.invalidArgument(
                    "Provide either `id` or `message_id` to identify the message."
                )
            }

            if messageIdHeader.isEmpty, let rowId = Int64(localId) {
                try? await MailEnvelopeDatabase.shared.activate()
                if let envRow = try? MailEnvelopeDatabase.shared.findMessage(byRowId: rowId),
                    !envRow.messageIdHeader.isEmpty
                {
                    messageIdHeader = envRow.messageIdHeader
                }
            }

            let normalizedMessageId = messageIdHeader
                .trimmingCharacters(in: .whitespacesAndNewlines)
                .trimmingCharacters(in: CharacterSet(charactersIn: "<>"))

            _ = try await self.runHandler(
                "markRead",
                arguments: [
                    NSAppleEventDescriptor(string: localId),
                    NSAppleEventDescriptor(string: normalizedMessageId),
                    NSAppleEventDescriptor(boolean: readState),
                ]
            )

            return Value.object([
                "status": .string("updated"),
                "read": .bool(readState),
            ])
        }

        Tool(
            name: "mail_attachments_fetch_dangerous",
            description: """
                ⚠ DANGEROUS — returns the raw, attacker-controlled attachment \
                filename (which can carry prompt-injection payloads), the \
                advertised MIME type (also attacker-controlled), AND writes \
                the attachment bytes to a filesystem `path` the agent learns. \
                A subsequent file-read by any tool will pull the attacker- \
                controlled bytes into agent context. Confine to a narrow \
                subagent that does NOT feed its outputs back into a privileged \
                orchestrator. For orchestrator-safe attachment enumeration use \
                mail_attachments_list_sanitized.

                Fetch attachment metadata and save attachment bytes to \
                disk for a single message — without loading the message \
                body. Use this when you want to process attachments \
                without paying for the full body read. Identify by \
                envelope rowid (`id` from mail_search) or Message-ID \
                header. When `output_dir` is omitted, a per-call temp \
                directory is created.
                """,
            inputSchema: .object(
                properties: [
                    "id": .string(
                        description:
                            "Envelope-index rowid (as returned by mail_search)"
                    ),
                    "message_id": .string(
                        description:
                            "RFC 5322 Message-ID header value (angle brackets optional)"
                    ),
                    "output_dir": .string(
                        description:
                            "Absolute directory path to save attachments into; created if missing"
                    ),
                ],
                additionalProperties: false
            ),
            annotations: .init(
                title: "Fetch Mail Attachments",
                readOnlyHint: true,
                openWorldHint: false
            )
        ) { arguments in
            try await self.activate()

            let localId = arguments["id"]?.stringValue ?? ""
            var messageIdHeader = arguments["message_id"]?.stringValue ?? ""
            let outputDir = arguments["output_dir"]?.stringValue ?? ""

            guard !localId.isEmpty || !messageIdHeader.isEmpty else {
                throw MailError.invalidArgument(
                    "Provide either `id` or `message_id` to identify the message."
                )
            }

            if messageIdHeader.isEmpty, let rowId = Int64(localId) {
                try? await MailEnvelopeDatabase.shared.activate()
                if let envRow = try? MailEnvelopeDatabase.shared.findMessage(byRowId: rowId),
                    !envRow.messageIdHeader.isEmpty
                {
                    messageIdHeader = envRow.messageIdHeader
                }
            }

            let normalizedMessageId = messageIdHeader
                .trimmingCharacters(in: .whitespacesAndNewlines)
                .trimmingCharacters(in: CharacterSet(charactersIn: "<>"))

            let targetDir: String
            if outputDir.isEmpty {
                let dir = FileManager.default.temporaryDirectory
                    .appendingPathComponent("iMCP-MY-Mail-\(UUID().uuidString)", isDirectory: true)
                try FileManager.default.createDirectory(
                    at: dir,
                    withIntermediateDirectories: true,
                    attributes: nil
                )
                targetDir = dir.path
            } else {
                try FileManager.default.createDirectory(
                    atPath: outputDir,
                    withIntermediateDirectories: true,
                    attributes: nil
                )
                targetDir = outputDir
            }

            let result = try await self.runHandler(
                "fetchAttachmentsOnly",
                arguments: [
                    NSAppleEventDescriptor(string: localId),
                    NSAppleEventDescriptor(string: normalizedMessageId),
                    NSAppleEventDescriptor(string: targetDir),
                ]
            )

            var messageIdOut = normalizedMessageId
            var attachments: [Value] = []
            if result.descriptorType == typeAEList, result.numberOfItems >= 2 {
                messageIdOut = result.atIndex(1)?.stringValue ?? normalizedMessageId
                if let attListDescriptor = result.atIndex(2),
                    attListDescriptor.descriptorType == typeAEList
                {
                    let n = attListDescriptor.numberOfItems
                    if n > 0 {
                        for i in 1...n {
                            guard let row = attListDescriptor.atIndex(i),
                                row.descriptorType == typeAEList
                            else { continue }
                            func field(_ index: Int) -> String {
                                guard index <= row.numberOfItems,
                                    let item = row.atIndex(index)
                                else { return "" }
                                return item.stringValue ?? ""
                            }
                            var entry: [String: Value] = [
                                "name": .string(field(1)),
                                "size": .string(field(2)),
                                "mimeType": .string(field(3)),
                            ]
                            let savedPath = field(4)
                            if !savedPath.isEmpty {
                                entry["path"] = .string(savedPath)
                            }
                            attachments.append(.object(entry))
                        }
                    }
                }
            }

            return Value.object([
                "messageId": .string(messageIdOut),
                "attachments": .array(attachments),
            ])
        }

        Tool(
            name: "mail_attachments_list_sanitized",
            description: """
                Safe-by-construction variant of \
                mail_attachments_fetch_dangerous for use in top-level agent \
                contexts. Enumerates attachments without writing their bytes \
                to disk and without returning a `path`. Each attachment's \
                `name` is sanitized (HTML-stripped, zero-width / control \
                chars stripped, length-capped at 128 chars), and `mimeType` \
                is allowlisted (unknown types collapse to \
                `application/octet-stream`).
                """,
            inputSchema: .object(
                properties: [
                    "id": .string(
                        description:
                            "Envelope-index rowid (as returned by mail_search)"
                    ),
                    "message_id": .string(
                        description:
                            "RFC 5322 Message-ID header value (angle brackets optional)"
                    ),
                ],
                additionalProperties: false
            ),
            annotations: .init(
                title: "List Mail Attachments (Sanitized)",
                readOnlyHint: true,
                openWorldHint: false
            )
        ) { arguments in
            try await self.activate()

            let localId = arguments["id"]?.stringValue ?? ""
            var messageIdHeader = arguments["message_id"]?.stringValue ?? ""

            guard !localId.isEmpty || !messageIdHeader.isEmpty else {
                throw MailError.invalidArgument(
                    "Provide either `id` or `message_id` to identify the message."
                )
            }

            if messageIdHeader.isEmpty, let rowId = Int64(localId) {
                try? await MailEnvelopeDatabase.shared.activate()
                if let envRow = try? MailEnvelopeDatabase.shared.findMessage(byRowId: rowId),
                    !envRow.messageIdHeader.isEmpty
                {
                    messageIdHeader = envRow.messageIdHeader
                }
            }

            let normalizedMessageId = messageIdHeader
                .trimmingCharacters(in: .whitespacesAndNewlines)
                .trimmingCharacters(in: CharacterSet(charactersIn: "<>"))

            // Empty targetDir tells the AppleScript handler to skip the save.
            let result = try await self.runHandler(
                "fetchAttachmentsOnly",
                arguments: [
                    NSAppleEventDescriptor(string: localId),
                    NSAppleEventDescriptor(string: normalizedMessageId),
                    NSAppleEventDescriptor(string: ""),
                ]
            )

            var messageIdOut = normalizedMessageId
            var attachments: [Value] = []
            if result.descriptorType == typeAEList, result.numberOfItems >= 2 {
                messageIdOut = result.atIndex(1)?.stringValue ?? normalizedMessageId
                if let attListDescriptor = result.atIndex(2),
                    attListDescriptor.descriptorType == typeAEList
                {
                    let n = attListDescriptor.numberOfItems
                    if n > 0 {
                        for i in 1...n {
                            guard let row = attListDescriptor.atIndex(i),
                                row.descriptorType == typeAEList
                            else { continue }
                            func field(_ index: Int) -> String {
                                guard index <= row.numberOfItems,
                                    let item = row.atIndex(index)
                                else { return "" }
                                return item.stringValue ?? ""
                            }
                            // Intentionally no `path` — this tool never writes
                            // bytes to disk, so it has no path to expose.
                            let entry: [String: Value] = [
                                "name": .string(MailSanitizer.sanitizeAttachmentName(field(1))),
                                "size": .string(field(2)),
                                "mimeType": .string(MailSanitizer.normalizeMimeType(field(3))),
                            ]
                            attachments.append(.object(entry))
                        }
                    }
                }
            }
            return Value.object([
                "messageId": .string(MailSanitizer.sanitizeShortHeader(messageIdOut)),
                "count": .int(attachments.count),
                "attachments": .array(attachments),
            ])
        }

        Tool(
            name: "mail_unsubscribe",
            description: """
                Unsubscribe from a message using its RFC 2369 \
                `List-Unsubscribe` header. When the sender advertises RFC \
                8058 one-click (`List-Unsubscribe-Post: \
                List-Unsubscribe=One-Click`), this POSTs to the HTTPS URL \
                so the user is unsubscribed without leaving iMCP-MY. \
                Otherwise the `mailto:` variant is dispatched through \
                Mail.app. If the message only exposes a non-one-click \
                HTTPS URL, the URL is returned for the user to visit \
                manually (it usually opens a confirmation page). Identify \
                the message by envelope rowid (`id` from mail_search) or \
                Message-ID header. Set `dry_run` to inspect the \
                advertised endpoints without executing.
                """,
            inputSchema: .object(
                properties: [
                    "id": .string(
                        description:
                            "Envelope-index rowid (as returned by mail_search)"
                    ),
                    "message_id": .string(
                        description:
                            "RFC 5322 Message-ID header value (angle brackets optional)"
                    ),
                    "dry_run": .boolean(
                        description:
                            "Return the parsed unsubscribe endpoints without executing",
                        default: .bool(false)
                    ),
                ],
                additionalProperties: false
            ),
            annotations: .init(
                title: "Unsubscribe from Sender",
                destructiveHint: true,
                openWorldHint: true
            )
        ) { arguments in
            try await self.activate()

            let localId = arguments["id"]?.stringValue ?? ""
            var messageIdHeader = arguments["message_id"]?.stringValue ?? ""
            let dryRun = arguments["dry_run"]?.boolValue ?? false

            guard !localId.isEmpty || !messageIdHeader.isEmpty else {
                throw MailError.invalidArgument(
                    "Provide either `id` or `message_id` to identify the message."
                )
            }

            if messageIdHeader.isEmpty, let rowId = Int64(localId) {
                try? await MailEnvelopeDatabase.shared.activate()
                if let envRow = try? MailEnvelopeDatabase.shared.findMessage(byRowId: rowId),
                    !envRow.messageIdHeader.isEmpty
                {
                    messageIdHeader = envRow.messageIdHeader
                }
            }

            let normalizedMessageId = messageIdHeader
                .trimmingCharacters(in: .whitespacesAndNewlines)
                .trimmingCharacters(in: CharacterSet(charactersIn: "<>"))

            let headersDescriptor = try await self.runHandler(
                "readMessageHeaders",
                arguments: [
                    NSAppleEventDescriptor(string: localId),
                    NSAppleEventDescriptor(string: normalizedMessageId),
                ]
            )
            let rawHeaders = headersDescriptor.stringValue ?? ""
            let parsed = Self.parseUnsubscribeHeaders(rawHeaders)
            guard let listUnsubscribe = parsed.listUnsubscribe,
                !listUnsubscribe.isEmpty
            else {
                throw MailError.invalidArgument(
                    "Message has no `List-Unsubscribe` header."
                )
            }

            let uris = Self.extractAngleBracketURIs(listUnsubscribe)
            let httpsURLs = uris.compactMap { URL(string: $0) }.filter {
                ($0.scheme?.lowercased() == "https")
            }
            let mailtoURIs = uris.filter { $0.lowercased().hasPrefix("mailto:") }
            let isOneClick = (parsed.post ?? "").lowercased()
                .replacingOccurrences(of: " ", with: "")
                .contains("list-unsubscribe=one-click")

            if dryRun {
                return Value.object([
                    "dryRun": .bool(true),
                    "listUnsubscribe": .string(listUnsubscribe),
                    "listUnsubscribePost": .string(parsed.post ?? ""),
                    "httpsURLs": .array(httpsURLs.map { .string($0.absoluteString) }),
                    "mailtoURIs": .array(mailtoURIs.map { .string($0) }),
                    "oneClickEligible": .bool(isOneClick && !httpsURLs.isEmpty),
                ])
            }

            if isOneClick, let url = httpsURLs.first {
                let httpStatus = try await Self.performOneClickUnsubscribe(url: url)
                let ok = (200..<300).contains(httpStatus)
                return Value.object([
                    "status": .string(ok ? "unsubscribed" : "http_error"),
                    "method": .string("https-one-click"),
                    "url": .string(url.absoluteString),
                    "httpStatus": .int(httpStatus),
                ])
            }

            if let mailto = mailtoURIs.first,
                let parsedMailto = Self.parseMailtoURI(mailto)
            {
                let subject =
                    parsedMailto.subject.isEmpty ? "unsubscribe" : parsedMailto.subject
                let body =
                    parsedMailto.body.isEmpty ? "unsubscribe" : parsedMailto.body
                let toList = NSAppleEventDescriptor.list()
                toList.insert(NSAppleEventDescriptor(string: parsedMailto.to), at: 1)
                _ = try await self.runHandler(
                    "sendMessage",
                    arguments: [
                        NSAppleEventDescriptor(string: subject),
                        NSAppleEventDescriptor(string: body),
                        toList,
                        NSAppleEventDescriptor.list(),
                        NSAppleEventDescriptor.list(),
                        NSAppleEventDescriptor(boolean: false),
                        NSAppleEventDescriptor.list(),
                    ]
                )
                return Value.object([
                    "status": .string("unsubscribe_requested"),
                    "method": .string("mailto"),
                    "to": .string(parsedMailto.to),
                    "subject": .string(subject),
                ])
            }

            if let url = httpsURLs.first {
                return Value.object([
                    "status": .string("manual_confirmation_required"),
                    "method": .string("manual-url"),
                    "url": .string(url.absoluteString),
                    "note": .string(
                        "Sender did not advertise RFC 8058 one-click. Open the URL to complete unsubscribe."
                    ),
                ])
            }

            throw MailError.invalidArgument(
                "List-Unsubscribe header present but contained no usable https:// or mailto: URI."
            )
        }

        Tool(
            name: "mail_list_mailboxes",
            description: "List Mail accounts and their mailboxes",
            inputSchema: .object(properties: [:], additionalProperties: false),
            annotations: .init(
                title: "List Mail Mailboxes",
                readOnlyHint: true,
                openWorldHint: false
            )
        ) { _ in
            try await self.activate()

            let result = try await self.runHandler("listMailboxes", arguments: [])
            return Value.array(self.decodeMailboxList(result))
        }
    }

    // MARK: - Account mapping

    /// Returns cached `(accountUUID, displayName)` pairs for every Mail
    /// account, populated on first call by invoking the AppleScript
    /// `listMailboxes` handler. The UUID is Mail.app's internal account id,
    /// which matches the host component of mailbox URLs stored in the
    /// envelope index — so it can be used to translate envelope results back
    /// to human-readable account names.
    fileprivate func accountMapping() async throws -> [(uuid: String, name: String)] {
        if let cached = accountMappingLock.withLock({ cachedAccountMapping }) {
            return cached
        }
        let result = try await runHandler("listMailboxes", arguments: [])
        let mapping = Self.decodeAccountMappingRows(result)
        accountMappingLock.withLock { cachedAccountMapping = mapping }
        return mapping
    }

    private static func decodeAccountMappingRows(
        _ descriptor: NSAppleEventDescriptor
    ) -> [(uuid: String, name: String)] {
        guard descriptor.descriptorType == typeAEList else { return [] }
        let count = descriptor.numberOfItems
        guard count > 0 else { return [] }
        var mapping: [(uuid: String, name: String)] = []
        mapping.reserveCapacity(count)
        for i in 1...count {
            guard let row = descriptor.atIndex(i),
                row.descriptorType == typeAEList
            else { continue }
            let name = row.atIndex(1)?.stringValue ?? ""
            let idString = row.atIndex(2)?.stringValue ?? ""
            if !idString.isEmpty {
                mapping.append((idString, name))
            }
        }
        return mapping
    }

    // MARK: - Thread reconstruction

    /// Walk the source message's References / In-Reply-To headers to
    /// reconstruct the thread without relying on Mail's envelope
    /// conversation_id column. Drafts and trashed results are filtered by
    /// mailbox name so callers get the same subset Mail.app's conversation
    /// view would show.
    fileprivate func threadByHeaderWalk(
        source: MailEnvelopeRow,
        limit: Int
    ) async throws -> [MailEnvelopeRow] {
        let normalizedMessageId = source.messageIdHeader
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .trimmingCharacters(in: CharacterSet(charactersIn: "<>"))
        let headersDescriptor = try await runHandler(
            "readMessageHeaders",
            arguments: [
                NSAppleEventDescriptor(string: String(source.rowId)),
                NSAppleEventDescriptor(string: normalizedMessageId),
            ]
        )
        let rawHeaders = headersDescriptor.stringValue ?? ""

        let normalized = rawHeaders.replacingOccurrences(of: "\r\n", with: "\n")
        var unfolded: [String] = []
        for line in normalized.components(separatedBy: "\n") {
            if let first = line.first, (first == " " || first == "\t"),
                !unfolded.isEmpty
            {
                unfolded[unfolded.count - 1] +=
                    " " + line.trimmingCharacters(in: .whitespaces)
            } else {
                unfolded.append(line)
            }
        }

        var collected: [String] = []
        for line in unfolded {
            guard let colon = line.firstIndex(of: ":") else { continue }
            let name = line[..<colon].trimmingCharacters(in: .whitespaces).lowercased()
            if name == "references" || name == "in-reply-to" {
                let value = String(line[line.index(after: colon)...])
                    .trimmingCharacters(in: .whitespaces)
                collected.append(contentsOf: Self.extractAngleBracketURIs(value))
            }
        }
        if !normalizedMessageId.isEmpty {
            collected.append(normalizedMessageId)
        }

        let uniqueIds = Set(
            collected.map {
                $0.trimmingCharacters(in: .whitespacesAndNewlines)
                    .trimmingCharacters(in: CharacterSet(charactersIn: "<>"))
            }
        ).filter { !$0.isEmpty }

        var seenRowIds = Set<Int64>()
        var rows: [MailEnvelopeRow] = []
        for id in uniqueIds {
            guard
                let row = try? MailEnvelopeDatabase.shared.findMessage(
                    byMessageIdHeader: id
                )
            else { continue }
            if seenRowIds.contains(row.rowId) { continue }
            if Self.isDraftOrTrashMailboxName(row.mailboxName) { continue }
            seenRowIds.insert(row.rowId)
            rows.append(row)
        }

        if !seenRowIds.contains(source.rowId),
            !Self.isDraftOrTrashMailboxName(source.mailboxName)
        {
            rows.append(source)
        }

        rows.sort { ($0.date ?? Date.distantPast) > ($1.date ?? Date.distantPast) }
        if rows.count > limit {
            rows = Array(rows.prefix(limit))
        }
        return rows
    }

    fileprivate static func isDraftOrTrashMailboxName(_ name: String) -> Bool {
        let lower = name.lowercased()
        if lower == "drafts" || lower == "trash"
            || lower == "deleted items" || lower == "deleted messages"
            || lower == "bin"
        {
            return true
        }
        if lower.hasPrefix("[gmail]/drafts")
            || lower.hasPrefix("[gmail]/trash")
            || lower.hasPrefix("[gmail]/bin")
        {
            return true
        }
        return false
    }

    // MARK: - List-Unsubscribe parsing

    fileprivate static func parseUnsubscribeHeaders(
        _ rawHeaders: String
    ) -> (listUnsubscribe: String?, post: String?) {
        let normalized = rawHeaders.replacingOccurrences(of: "\r\n", with: "\n")
        var unfolded: [String] = []
        for line in normalized.components(separatedBy: "\n") {
            if let first = line.first, (first == " " || first == "\t"),
                !unfolded.isEmpty
            {
                unfolded[unfolded.count - 1] +=
                    " " + line.trimmingCharacters(in: .whitespaces)
            } else {
                unfolded.append(line)
            }
        }
        var listUnsubscribe: String?
        var post: String?
        for line in unfolded {
            guard let colon = line.firstIndex(of: ":") else { continue }
            let name = line[..<colon].trimmingCharacters(in: .whitespaces).lowercased()
            let value = String(line[line.index(after: colon)...])
                .trimmingCharacters(in: .whitespaces)
            switch name {
            case "list-unsubscribe": listUnsubscribe = value
            case "list-unsubscribe-post": post = value
            default: break
            }
        }
        return (listUnsubscribe, post)
    }

    fileprivate static func extractAngleBracketURIs(_ value: String) -> [String] {
        var result: [String] = []
        var current = ""
        var inside = false
        for ch in value {
            if ch == "<" {
                inside = true
                current = ""
            } else if ch == ">" {
                inside = false
                let trimmed = current.trimmingCharacters(in: .whitespaces)
                if !trimmed.isEmpty { result.append(trimmed) }
            } else if inside {
                current.append(ch)
            }
        }
        return result
    }

    fileprivate static func parseMailtoURI(
        _ uri: String
    ) -> (to: String, subject: String, body: String)? {
        guard let comps = URLComponents(string: uri),
            comps.scheme?.lowercased() == "mailto"
        else { return nil }
        let toAddr = comps.path.trimmingCharacters(in: .whitespaces)
        guard !toAddr.isEmpty else { return nil }
        var subject = ""
        var body = ""
        for item in comps.queryItems ?? [] {
            switch item.name.lowercased() {
            case "subject": subject = item.value ?? ""
            case "body": body = item.value ?? ""
            default: break
            }
        }
        return (toAddr, subject, body)
    }

    fileprivate static func performOneClickUnsubscribe(url: URL) async throws -> Int {
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue(
            "application/x-www-form-urlencoded",
            forHTTPHeaderField: "Content-Type"
        )
        request.httpBody = Data("List-Unsubscribe=One-Click".utf8)
        request.timeoutInterval = 15
        let (_, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw MailError.scriptExecutionFailed(
                code: 0,
                message: "Unsubscribe POST returned no HTTP response"
            )
        }
        return http.statusCode
    }

    // MARK: - Descriptor decoding

    fileprivate func decodeMailboxList(_ descriptor: NSAppleEventDescriptor) -> [Value] {
        guard descriptor.descriptorType == typeAEList else { return [] }
        let count = descriptor.numberOfItems
        guard count > 0 else { return [] }
        var accounts: [Value] = []
        accounts.reserveCapacity(count)
        for i in 1...count {
            guard let row = descriptor.atIndex(i),
                row.descriptorType == typeAEList
            else { continue }
            let name = row.atIndex(1)?.stringValue ?? ""
            let idString = row.atIndex(2)?.stringValue ?? ""
            let mailboxesDescriptor = row.atIndex(3) ?? .list()
            var mailboxNames: [Value] = []
            if mailboxesDescriptor.descriptorType == typeAEList {
                let boxCount = mailboxesDescriptor.numberOfItems
                if boxCount > 0 {
                    for j in 1...boxCount {
                        if let item = mailboxesDescriptor.atIndex(j),
                            let mailboxName = item.stringValue
                        {
                            mailboxNames.append(.string(mailboxName))
                        }
                    }
                }
            }
            accounts.append(
                .object([
                    "name": .string(name),
                    "id": .string(idString),
                    "mailboxes": .array(mailboxNames),
                ])
            )
        }
        return accounts
    }

    fileprivate func decodeFetchedMessage(_ descriptor: NSAppleEventDescriptor) -> Value? {
        guard descriptor.descriptorType == typeAEList else { return nil }
        let n = descriptor.numberOfItems
        guard n >= 13 else { return nil }

        func str(_ index: Int) -> String {
            guard index <= n, let item = descriptor.atIndex(index) else { return "" }
            return item.stringValue ?? ""
        }

        var attachments: [Value] = []
        if let attachmentsDescriptor = descriptor.atIndex(14),
            attachmentsDescriptor.descriptorType == typeAEList
        {
            let count = attachmentsDescriptor.numberOfItems
            if count > 0 {
                for i in 1...count {
                    guard let row = attachmentsDescriptor.atIndex(i),
                        row.descriptorType == typeAEList
                    else { continue }
                    func field(_ index: Int) -> String {
                        guard index <= row.numberOfItems,
                            let item = row.atIndex(index)
                        else { return "" }
                        return item.stringValue ?? ""
                    }
                    var entry: [String: Value] = [
                        "name": .string(field(1)),
                        "size": .string(field(2)),
                        "mimeType": .string(field(3)),
                    ]
                    let savedPath = field(4)
                    if !savedPath.isEmpty {
                        entry["path"] = .string(savedPath)
                    }
                    attachments.append(.object(entry))
                }
            }
        }

        return .object([
            "id": .string(str(1)),
            "messageId": .string(str(2)),
            "subject": .string(str(3)),
            "from": .string(str(4)),
            "to": .string(str(5)),
            "cc": .string(str(6)),
            "bcc": .string(str(7)),
            "replyTo": .string(str(8)),
            "date": .string(str(9)),
            "mailbox": .string(str(10)),
            "account": .string(str(11)),
            "headers": .string(str(12)),
            "body": .string(str(13)),
            "attachments": .array(attachments),
        ])
    }

    // MARK: - Shared message-fetch helper

    /// Resolves an envelope row, runs the AppleScript fetch handler, and
    /// returns the decoded fields plus the envelope row so each fetch-style
    /// tool (`mail_fetch_dangerous`, `mail_fetch_sanitized`, `mail_classify`)
    /// shares one implementation of the lookup + AppleScript pipeline.
    fileprivate func fetchDecodedMessageInternal(
        localId: String,
        messageIdHeader: String,
        includeAttachments: Bool
    ) async throws -> (envelopeRow: MailEnvelopeRow?, fields: [String: Value]) {
        guard !localId.isEmpty || !messageIdHeader.isEmpty else {
            throw MailError.invalidArgument(
                "Provide either `id` or `message_id` to identify the message."
            )
        }

        var msgIdHeader = messageIdHeader
        var envelopeRow: MailEnvelopeRow?
        if let rowId = Int64(localId) {
            try? await MailEnvelopeDatabase.shared.activate()
            envelopeRow = try? MailEnvelopeDatabase.shared.findMessage(byRowId: rowId)
            if msgIdHeader.isEmpty,
                let env = envelopeRow, !env.messageIdHeader.isEmpty
            {
                msgIdHeader = env.messageIdHeader
            }
        }
        if envelopeRow == nil, !msgIdHeader.isEmpty {
            let trimmed = msgIdHeader
                .trimmingCharacters(in: .whitespacesAndNewlines)
                .trimmingCharacters(in: CharacterSet(charactersIn: "<>"))
            try? await MailEnvelopeDatabase.shared.activate()
            envelopeRow = try? MailEnvelopeDatabase.shared.findMessage(
                byMessageIdHeader: trimmed
            )
        }

        let attachmentDir: String
        if includeAttachments {
            let dir = FileManager.default.temporaryDirectory
                .appendingPathComponent(
                    "iMCP-MY-Mail-\(UUID().uuidString)", isDirectory: true)
            try FileManager.default.createDirectory(
                at: dir,
                withIntermediateDirectories: true,
                attributes: nil
            )
            attachmentDir = dir.path
        } else {
            attachmentDir = ""
        }

        let normalizedMessageId = msgIdHeader
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .trimmingCharacters(in: CharacterSet(charactersIn: "<>"))

        let result = try await self.runHandler(
            "fetchMessage",
            arguments: [
                NSAppleEventDescriptor(string: localId),
                NSAppleEventDescriptor(string: normalizedMessageId),
                NSAppleEventDescriptor(boolean: includeAttachments),
                NSAppleEventDescriptor(string: attachmentDir),
            ]
        )

        guard let fetched = self.decodeFetchedMessage(result),
            case let .object(fields) = fetched
        else {
            throw MailError.scriptExecutionFailed(
                code: 0,
                message: "Message not found"
            )
        }
        return (envelopeRow, fields)
    }

    // MARK: - Sanitized projections of the decoded message

    /// Builds the response payload for `mail_fetch_sanitized`. Drops the
    /// `headers` blob and `bcc` field, sanitizes attachment metadata, and
    /// runs the body through `MailSanitizer.sanitizeBody`. Never includes
    /// an attachment `path`.
    fileprivate func buildSanitizedMessage(
        fields: [String: Value],
        envelopeRow: MailEnvelopeRow?,
        maxChars: Int
    ) -> [String: Value] {
        let rawBody = fields["body"]?.stringValue ?? ""
        let sanitized = MailSanitizer.sanitizeBody(rawBody, maxChars: maxChars)

        var safeAttachments: [Value] = []
        if case let .array(rawAttachments) = (fields["attachments"] ?? .null) {
            for entry in rawAttachments {
                guard case let .object(attDict) = entry else { continue }
                let entry: [String: Value] = [
                    "name": .string(MailSanitizer.sanitizeAttachmentName(
                        attDict["name"]?.stringValue ?? ""
                    )),
                    "size": .string(attDict["size"]?.stringValue ?? "0"),
                    "mimeType": .string(MailSanitizer.normalizeMimeType(
                        attDict["mimeType"]?.stringValue ?? ""
                    )),
                ]
                safeAttachments.append(.object(entry))
            }
        }

        // Each envelope field is attacker-controlled too, not just `body`.
        // Sanitize them through the same pipeline before they reach the
        // orchestrator: subjects through full body-style cleansing (codes /
        // links / secrets / OTPs all show up in subjects), addresses through
        // HTML+zero-width strip with cap (URL strip would mangle email
        // addresses), short headers through HTML+zero-width+control strip
        // with cap.
        let rawString: ([String: Value], String) -> String = { fields, key in
            return fields[key]?.stringValue ?? ""
        }
        var out: [String: Value] = [
            "id": .string(MailSanitizer.sanitizeShortHeader(rawString(fields, "id"))),
            "messageId": .string(MailSanitizer.sanitizeShortHeader(rawString(fields, "messageId"))),
            "subject": .string(MailSanitizer.sanitizeSubject(rawString(fields, "subject"))),
            "from": .string(MailSanitizer.sanitizeAddressField(rawString(fields, "from"))),
            "to": .string(MailSanitizer.sanitizeAddressField(rawString(fields, "to"))),
            "cc": .string(MailSanitizer.sanitizeAddressField(rawString(fields, "cc"))),
            "replyTo": .string(MailSanitizer.sanitizeAddressField(rawString(fields, "replyTo"))),
            "date": .string(MailSanitizer.sanitizeShortHeader(rawString(fields, "date"))),
            "mailbox": .string(MailSanitizer.sanitizeShortHeader(rawString(fields, "mailbox"))),
            "account": .string(MailSanitizer.sanitizeShortHeader(rawString(fields, "account"))),
            "body": .string(sanitized.text),
            "truncated": .bool(sanitized.truncated),
            "originalLength": .int(sanitized.originalLength),
            "redactionsApplied": .array(sanitized.redactionsApplied.map { .string($0) }),
            "attachments": .array(safeAttachments),
            "attachmentCount": .int(safeAttachments.count),
        ]
        if let row = envelopeRow {
            if let read = row.read { out["read"] = .bool(read) }
            if let flagged = row.flagged { out["flagged"] = .bool(flagged) }
        }
        // NOTE: `headers` (raw blob) and `bcc` are intentionally absent —
        // both are attacker-controlled and Bcc isn't exposed reliably anyway.
        return out
    }

    /// Builds the response payload for `mail_classify`. Returns the
    /// schema-locked `MailClassification` struct so the JSON output cannot
    /// accidentally include `body`/`content`/`headers` fields.
    fileprivate func classifyMessage(fields: [String: Value]) -> MailClassification {
        let rawBody = fields["body"]?.stringValue ?? ""
        let headersBlock = fields["headers"]?.stringValue ?? ""
        let sanitized = MailSanitizer.sanitizeBody(
            rawBody, maxChars: MailSanitizer.maxMaxChars
        )
        let attachmentCount: Int = {
            if case let .array(arr) = (fields["attachments"] ?? .null) { return arr.count }
            return 0
        }()
        return MailSanitizer.classify(
            messageId: fields["messageId"]?.stringValue ?? "",
            from: fields["from"]?.stringValue ?? "",
            to: fields["to"]?.stringValue ?? "",
            subject: fields["subject"]?.stringValue ?? "",
            date: fields["date"]?.stringValue ?? "",
            headersBlock: headersBlock,
            sanitizedBody: sanitized.text,
            attachmentCount: attachmentCount
        )
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
                    Privacy & Security → Automation and allow iMCP-MY to control Mail.
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
        #"""
        on probeAuthorization()
            tell application "Mail"
                count of accounts
            end tell
            return true
        end probeAuthorization

        on isoDate(d)
            if d is missing value then return ""
            set y to year of d as integer
            set mo to (month of d as integer)
            set dd to day of d as integer
            set h to hours of d as integer
            set mi to minutes of d as integer
            set s to seconds of d as integer
            return (my zpad(y, 4)) & "-" & (my zpad(mo, 2)) & "-" & ¬
                (my zpad(dd, 2)) & "T" & (my zpad(h, 2)) & ":" & ¬
                (my zpad(mi, 2)) & ":" & (my zpad(s, 2))
        end isoDate

        on zpad(n, w)
            set s to (n as integer) as text
            repeat while (count of s) < w
                set s to "0" & s
            end repeat
            return s
        end zpad

        on joinAddresses(recipientList)
            set parts to {}
            try
                repeat with r in recipientList
                    try
                        set end of parts to (address of r as text)
                    end try
                end repeat
            end try
            set AppleScript's text item delimiters to ", "
            set joined to parts as text
            set AppleScript's text item delimiters to ""
            return joined
        end joinAddresses

        on findMessageById(idNum)
            tell application "Mail"
                repeat with acct in accounts
                    repeat with mb in mailboxes of acct
                        try
                            set candidate to first message of mb whose id is idNum
                            return {candidate, acct, mb}
                        end try
                    end repeat
                end repeat
            end tell
            return missing value
        end findMessageById

        on findMessageByMessageId(msgIdHeader)
            tell application "Mail"
                repeat with acct in accounts
                    repeat with mb in mailboxes of acct
                        try
                            set candidate to first message of mb whose message id is msgIdHeader
                            return {candidate, acct, mb}
                        end try
                    end repeat
                end repeat
            end tell
            return missing value
        end findMessageByMessageId

        on saveAttachment(att, dirPath, fname)
            try
                set fullPath to dirPath & "/" & fname
                tell application "Mail"
                    save att in (POSIX file fullPath)
                end tell
                return fullPath
            on error errMsg number errNum
                return ""
            end try
        end saveAttachment

        on fetchMessage(messageLocalId, messageIdHeader, includeAttachments, attachmentDir)
            set located to missing value
            if messageLocalId is not "" then
                try
                    set idNum to messageLocalId as integer
                    set located to my findMessageById(idNum)
                end try
            end if
            if located is missing value and messageIdHeader is not "" then
                set located to my findMessageByMessageId(messageIdHeader)
            end if
            if located is missing value then return missing value

            set targetMsg to item 1 of located
            set targetAcct to item 2 of located
            set targetBox to item 3 of located

            set msgLocalId to ""
            set msgIdHeaderVal to ""
            set subjText to ""
            set fromText to ""
            set toText to ""
            set ccText to ""
            set bccText to ""
            set replyToText to ""
            set dateIso to ""
            set mbName to ""
            set acctName to ""
            set allHeadersText to ""
            set bodyText to ""
            set attList to {}

            tell application "Mail"
                try
                    set msgLocalId to id of targetMsg as text
                end try
                try
                    set msgIdHeaderVal to message id of targetMsg as text
                end try
                try
                    set subjText to subject of targetMsg as text
                end try
                try
                    set fromText to sender of targetMsg as text
                end try
                try
                    set toText to my joinAddresses(to recipients of targetMsg)
                end try
                try
                    set ccText to my joinAddresses(cc recipients of targetMsg)
                end try
                try
                    set bccText to my joinAddresses(bcc recipients of targetMsg)
                end try
                try
                    set replyToText to reply to of targetMsg as text
                end try
                try
                    set msgDate to date received of targetMsg
                    set dateIso to my isoDate(msgDate)
                end try
                try
                    set mbName to name of targetBox as text
                end try
                try
                    set acctName to name of targetAcct as text
                end try
                try
                    set allHeadersText to all headers of targetMsg as text
                end try
                try
                    set bodyText to content of targetMsg as text
                end try

                try
                    repeat with att in mail attachments of targetMsg
                        set attName to ""
                        try
                            set attName to name of att as text
                        end try
                        set attSize to "0"
                        try
                            set attSize to (file size of att) as text
                        end try
                        set attMime to ""
                        try
                            set attMime to MIME type of att as text
                        end try
                        set savedPath to ""
                        if includeAttachments and attachmentDir is not "" and attName is not "" then
                            set savedPath to my saveAttachment(att, attachmentDir, attName)
                        end if
                        set end of attList to {attName, attSize, attMime, savedPath}
                    end repeat
                end try
            end tell

            return {msgLocalId, msgIdHeaderVal, subjText, fromText, toText, ccText, bccText, replyToText, dateIso, mbName, acctName, allHeadersText, bodyText, attList}
        end fetchMessage

        on sendMessage(subjectText, bodyText, toAddrs, ccAddrs, bccAddrs, isHTML, attachmentPaths)
            tell application "Mail"
                set newMsg to make new outgoing message with properties {subject:subjectText, content:bodyText, visible:false}
                tell newMsg
                    repeat with addr in toAddrs
                        make new to recipient at end of to recipients with properties {address:(addr as text)}
                    end repeat
                    repeat with addr in ccAddrs
                        make new cc recipient at end of cc recipients with properties {address:(addr as text)}
                    end repeat
                    repeat with addr in bccAddrs
                        make new bcc recipient at end of bcc recipients with properties {address:(addr as text)}
                    end repeat
                end tell
                repeat with p in attachmentPaths
                    try
                        tell content of newMsg
                            make new attachment with properties {file name:(POSIX file (p as text))} at after last paragraph
                        end tell
                    end try
                end repeat
                send newMsg
            end tell
            return "sent"
        end sendMessage

        on deleteMessage(messageLocalId, messageIdHeader)
            set located to missing value
            if messageLocalId is not "" then
                try
                    set idNum to messageLocalId as integer
                    set located to my findMessageById(idNum)
                end try
            end if
            if located is missing value and messageIdHeader is not "" then
                set located to my findMessageByMessageId(messageIdHeader)
            end if
            if located is missing value then
                error "Message not found" number -1700
            end if
            set targetMsg to item 1 of located
            tell application "Mail"
                delete targetMsg
            end tell
            return "deleted"
        end deleteMessage

        on readMessageHeaders(messageLocalId, messageIdHeader)
            set located to missing value
            if messageLocalId is not "" then
                try
                    set idNum to messageLocalId as integer
                    set located to my findMessageById(idNum)
                end try
            end if
            if located is missing value and messageIdHeader is not "" then
                set located to my findMessageByMessageId(messageIdHeader)
            end if
            if located is missing value then
                error "Message not found" number -1700
            end if
            set targetMsg to item 1 of located
            set allHeadersText to ""
            tell application "Mail"
                try
                    set allHeadersText to all headers of targetMsg as text
                end try
            end tell
            return allHeadersText
        end readMessageHeaders

        on listMailboxes()
            set acctList to {}
            tell application "Mail"
                repeat with acct in accounts
                    set acctName to ""
                    try
                        set acctName to name of acct as text
                    end try
                    set acctId to ""
                    try
                        set acctId to id of acct as text
                    end try
                    set mbNames to {}
                    try
                        repeat with mb in mailboxes of acct
                            try
                                set end of mbNames to (name of mb as text)
                            end try
                        end repeat
                    end try
                    set end of acctList to {acctName, acctId, mbNames}
                end repeat
            end tell
            return acctList
        end listMailboxes

        on replyMessage(messageLocalId, messageIdHeader, bodyText, replyAll, additionalCc, additionalBcc, attachmentPaths, saveOnly)
            set located to missing value
            if messageLocalId is not "" then
                try
                    set idNum to messageLocalId as integer
                    set located to my findMessageById(idNum)
                end try
            end if
            if located is missing value and messageIdHeader is not "" then
                set located to my findMessageByMessageId(messageIdHeader)
            end if
            if located is missing value then
                error "Message not found" number -1700
            end if
            set targetMsg to item 1 of located
            tell application "Mail"
                if replyAll then
                    set replyMsg to reply targetMsg opening window no with reply to all
                else
                    set replyMsg to reply targetMsg opening window no
                end if
                set existingBody to ""
                try
                    set existingBody to content of replyMsg as text
                end try
                set content of replyMsg to bodyText & return & existingBody
                tell replyMsg
                    repeat with addr in additionalCc
                        make new cc recipient at end of cc recipients with properties {address:(addr as text)}
                    end repeat
                    repeat with addr in additionalBcc
                        make new bcc recipient at end of bcc recipients with properties {address:(addr as text)}
                    end repeat
                end tell
                repeat with p in attachmentPaths
                    try
                        tell content of replyMsg
                            make new attachment with properties {file name:(POSIX file (p as text))} at after last paragraph
                        end tell
                    end try
                end repeat
                set subjText to ""
                set toJoined to ""
                try
                    set subjText to subject of replyMsg as text
                end try
                try
                    set toJoined to my joinAddresses(to recipients of replyMsg)
                end try
                if saveOnly then
                    save replyMsg
                    return {"saved", subjText, toJoined}
                else
                    send replyMsg
                    return {"sent", subjText, toJoined}
                end if
            end tell
        end replyMessage

        on forwardMessage(messageLocalId, messageIdHeader, bodyText, toAddrs, ccAddrs, bccAddrs, attachmentPaths, saveOnly)
            set located to missing value
            if messageLocalId is not "" then
                try
                    set idNum to messageLocalId as integer
                    set located to my findMessageById(idNum)
                end try
            end if
            if located is missing value and messageIdHeader is not "" then
                set located to my findMessageByMessageId(messageIdHeader)
            end if
            if located is missing value then
                error "Message not found" number -1700
            end if
            set targetMsg to item 1 of located
            tell application "Mail"
                set fwdMsg to forward targetMsg opening window no
                set existingBody to ""
                try
                    set existingBody to content of fwdMsg as text
                end try
                if bodyText is not "" then
                    set content of fwdMsg to bodyText & return & existingBody
                end if
                tell fwdMsg
                    repeat with addr in toAddrs
                        make new to recipient at end of to recipients with properties {address:(addr as text)}
                    end repeat
                    repeat with addr in ccAddrs
                        make new cc recipient at end of cc recipients with properties {address:(addr as text)}
                    end repeat
                    repeat with addr in bccAddrs
                        make new bcc recipient at end of bcc recipients with properties {address:(addr as text)}
                    end repeat
                end tell
                repeat with p in attachmentPaths
                    try
                        tell content of fwdMsg
                            make new attachment with properties {file name:(POSIX file (p as text))} at after last paragraph
                        end tell
                    end try
                end repeat
                set subjText to ""
                set toJoined to ""
                try
                    set subjText to subject of fwdMsg as text
                end try
                try
                    set toJoined to my joinAddresses(to recipients of fwdMsg)
                end try
                if saveOnly then
                    save fwdMsg
                    return {"saved", subjText, toJoined}
                else
                    send fwdMsg
                    return {"sent", subjText, toJoined}
                end if
            end tell
        end forwardMessage

        on moveMessage(messageLocalId, messageIdHeader, targetMailboxName, targetAccountName)
            set located to missing value
            if messageLocalId is not "" then
                try
                    set idNum to messageLocalId as integer
                    set located to my findMessageById(idNum)
                end try
            end if
            if located is missing value and messageIdHeader is not "" then
                set located to my findMessageByMessageId(messageIdHeader)
            end if
            if located is missing value then
                error "Message not found" number -1700
            end if
            set targetMsg to item 1 of located
            set sourceAcct to item 2 of located
            set movedMailboxName to ""
            set movedAccountName to ""
            tell application "Mail"
                if targetAccountName is "" then
                    set targetAcct to sourceAcct
                else
                    set targetAcct to first account whose name is targetAccountName
                end if
                set targetBox to first mailbox of targetAcct whose name is targetMailboxName
                move targetMsg to targetBox
                try
                    set movedMailboxName to name of targetBox as text
                end try
                try
                    set movedAccountName to name of targetAcct as text
                end try
            end tell
            return {"moved", movedMailboxName, movedAccountName}
        end moveMessage

        on markRead(messageLocalId, messageIdHeader, readState)
            set located to missing value
            if messageLocalId is not "" then
                try
                    set idNum to messageLocalId as integer
                    set located to my findMessageById(idNum)
                end try
            end if
            if located is missing value and messageIdHeader is not "" then
                set located to my findMessageByMessageId(messageIdHeader)
            end if
            if located is missing value then
                error "Message not found" number -1700
            end if
            set targetMsg to item 1 of located
            tell application "Mail"
                set read status of targetMsg to readState
            end tell
            if readState then
                return {"updated", "read"}
            else
                return {"updated", "unread"}
            end if
        end markRead

        on readMessageBody(messageLocalId, messageIdHeader)
            set located to missing value
            if messageLocalId is not "" then
                try
                    set idNum to messageLocalId as integer
                    set located to my findMessageById(idNum)
                end try
            end if
            if located is missing value and messageIdHeader is not "" then
                set located to my findMessageByMessageId(messageIdHeader)
            end if
            if located is missing value then
                error "Message not found" number -1700
            end if
            set targetMsg to item 1 of located
            set bodyText to ""
            tell application "Mail"
                try
                    set bodyText to content of targetMsg as text
                end try
            end tell
            return bodyText
        end readMessageBody

        on fetchAttachmentsOnly(messageLocalId, messageIdHeader, attachmentDir)
            set located to missing value
            if messageLocalId is not "" then
                try
                    set idNum to messageLocalId as integer
                    set located to my findMessageById(idNum)
                end try
            end if
            if located is missing value and messageIdHeader is not "" then
                set located to my findMessageByMessageId(messageIdHeader)
            end if
            if located is missing value then
                error "Message not found" number -1700
            end if
            set targetMsg to item 1 of located
            set msgIdHeaderVal to ""
            set attList to {}
            tell application "Mail"
                try
                    set msgIdHeaderVal to message id of targetMsg as text
                end try
                try
                    repeat with att in mail attachments of targetMsg
                        set attName to ""
                        try
                            set attName to name of att as text
                        end try
                        set attSize to "0"
                        try
                            set attSize to (file size of att) as text
                        end try
                        set attMime to ""
                        try
                            set attMime to MIME type of att as text
                        end try
                        set savedPath to ""
                        if attName is not "" and attachmentDir is not "" then
                            set savedPath to my saveAttachment(att, attachmentDir, attName)
                        end if
                        set end of attList to {attName, attSize, attMime, savedPath}
                    end repeat
                end try
            end tell
            return {msgIdHeaderVal, attList}
        end fetchAttachmentsOnly
        """#
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
        let argsBox = UncheckedBox(value: arguments)
        return try await withCheckedThrowingContinuation { continuation in
            scriptQueue.async {
                do {
                    let script = try self.loadScript()
                    let params = NSAppleEventDescriptor.list()
                    for (offset, descriptor) in argsBox.value.enumerated() {
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
