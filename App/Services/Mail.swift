import AppKit
import Carbon
import Foundation
import JSONSchema
import OSLog

private let log = Logger.service("mail")

private let defaultSearchLimit = 30
private let maxSearchLimit = 500

extension NSAppleEventDescriptor {
    // AppleScript "missing value" marker: descriptor of type 'msng' with no data.
    fileprivate static func mailMissingValue() -> NSAppleEventDescriptor {
        return NSAppleEventDescriptor(
            descriptorType: DescType(cMissingValue),
            data: nil
        ) ?? NSAppleEventDescriptor.null()
    }
}

final class MailService: NSObject, @unchecked Sendable, Service {
    static let shared = MailService()

    private let scriptQueue = DispatchQueue(label: "me.mattt.iMCP.mail-script")
    private var cachedScript: NSAppleScript?

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
    }

    var tools: [Tool] {
        Tool(
            name: "mail_search",
            description: """
                Search Mail messages by sender, recipient, subject, body text, \
                date range, mailbox, or account. Returns message metadata. Note: \
                body-text matches scan messages individually and may be slow on \
                large mailboxes — restrict with mailbox/account/date/limit when \
                possible.
                """,
            inputSchema: .object(
                properties: [
                    "sender": .string(
                        description: "Match substring in sender name or email address"
                    ),
                    "recipient": .string(
                        description: "Match substring in to/cc recipient addresses"
                    ),
                    "subject": .string(
                        description: "Match substring in subject"
                    ),
                    "body": .string(
                        description: "Match substring in message body"
                    ),
                    "mailbox": .string(
                        description: "Restrict to mailbox with this name"
                    ),
                    "account": .string(
                        description: "Restrict to account with this name"
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

            let sender = arguments["sender"]?.stringValue ?? ""
            let recipient = arguments["recipient"]?.stringValue ?? ""
            let subject = arguments["subject"]?.stringValue ?? ""
            let body = arguments["body"]?.stringValue ?? ""
            let mailbox = arguments["mailbox"]?.stringValue ?? ""
            let account = arguments["account"]?.stringValue ?? ""

            let limit = min(
                max(arguments["limit"]?.intValue ?? defaultSearchLimit, 1),
                maxSearchLimit
            )

            let startDescriptor: NSAppleEventDescriptor
            if let startString = arguments["start"]?.stringValue,
                let parsed = ISO8601DateFormatter.parsedLenientISO8601Date(
                    fromISO8601String: startString
                )
            {
                let normalized = Calendar.current.normalizedStartDate(
                    from: parsed.date,
                    isDateOnly: parsed.isDateOnly
                )
                startDescriptor = NSAppleEventDescriptor(date: normalized)
            } else {
                startDescriptor = .mailMissingValue()
            }

            let endDescriptor: NSAppleEventDescriptor
            if let endString = arguments["end"]?.stringValue,
                let parsed = ISO8601DateFormatter.parsedLenientISO8601Date(
                    fromISO8601String: endString
                )
            {
                let normalized = Calendar.current.normalizedEndDate(
                    from: parsed.date,
                    isDateOnly: parsed.isDateOnly
                )
                endDescriptor = NSAppleEventDescriptor(date: normalized)
            } else {
                endDescriptor = .mailMissingValue()
            }

            let result = try await self.runHandler(
                "searchMessages",
                arguments: [
                    NSAppleEventDescriptor(string: sender),
                    NSAppleEventDescriptor(string: recipient),
                    NSAppleEventDescriptor(string: subject),
                    NSAppleEventDescriptor(string: body),
                    NSAppleEventDescriptor(string: mailbox),
                    NSAppleEventDescriptor(string: account),
                    startDescriptor,
                    endDescriptor,
                    NSAppleEventDescriptor(int32: Int32(limit)),
                ]
            )

            return Value.array(self.decodeMessageRows(result))
        }

        Tool(
            name: "mail_fetch",
            description: """
                Fetch a single Mail message by Mail.app id or Message-ID header, \
                returning full headers, plain-text body, and attachment metadata. \
                Attachment bytes are never inlined; when include_attachments is \
                true, attachments are saved to a temporary directory and their \
                paths are returned.
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

            guard !localId.isEmpty || !messageIdHeader.isEmpty else {
                throw MailError.invalidArgument(
                    "Provide either `id` or `message_id` to identify the message."
                )
            }

            let attachmentDir: String
            if includeAttachments {
                let dir = FileManager.default.temporaryDirectory
                    .appendingPathComponent("iMCP-Mail-\(UUID().uuidString)", isDirectory: true)
                try FileManager.default.createDirectory(
                    at: dir,
                    withIntermediateDirectories: true,
                    attributes: nil
                )
                attachmentDir = dir.path
            } else {
                attachmentDir = ""
            }

            let result = try await self.runHandler(
                "fetchMessage",
                arguments: [
                    NSAppleEventDescriptor(string: localId),
                    NSAppleEventDescriptor(string: messageIdHeader),
                    NSAppleEventDescriptor(boolean: includeAttachments),
                    NSAppleEventDescriptor(string: attachmentDir),
                ]
            )

            guard let fetched = self.decodeFetchedMessage(result) else {
                throw MailError.scriptExecutionFailed(
                    code: 0,
                    message: "Message not found"
                )
            }
            return fetched
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

    // MARK: - Descriptor decoding

    fileprivate func decodeMessageRows(_ descriptor: NSAppleEventDescriptor) -> [Value] {
        guard descriptor.descriptorType == typeAEList else { return [] }
        let count = descriptor.numberOfItems
        guard count > 0 else { return [] }
        var items: [Value] = []
        items.reserveCapacity(count)
        for i in 1...count {
            guard let row = descriptor.atIndex(i) else { continue }
            items.append(Self.decodeMessageRow(row))
        }
        return items
    }

    private static func decodeMessageRow(_ row: NSAppleEventDescriptor) -> Value {
        func field(_ index: Int) -> String {
            guard index <= row.numberOfItems,
                let item = row.atIndex(index)
            else { return "" }
            return item.stringValue ?? ""
        }
        return .object([
            "id": .string(field(1)),
            "messageId": .string(field(2)),
            "from": .string(field(3)),
            "recipients": .string(field(4)),
            "subject": .string(field(5)),
            "date": .string(field(6)),
            "mailbox": .string(field(7)),
            "account": .string(field(8)),
            "snippet": .string(field(9)),
        ])
    }

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

        on snippetOf(rawBody)
            if rawBody is missing value then return ""
            try
                set asText to rawBody as text
            on error
                return ""
            end try
            if (count of asText) > 240 then
                return (text 1 thru 240 of asText)
            else
                return asText
            end if
        end snippetOf

        on mailboxMatches(mb, mailboxName)
            if mailboxName is "" then return true
            try
                return (name of mb as text) is mailboxName
            on error
                return false
            end try
        end mailboxMatches

        on searchMessages(senderQuery, recipientQuery, subjectQuery, bodyQuery, ¬
            mailboxName, accountName, startDate, endDate, maxCount)
            set foundResults to {}
            tell application "Mail"
                repeat with acct in accounts
                    if (count of foundResults) ≥ maxCount then exit repeat
                    set acctName to ""
                    try
                        set acctName to name of acct as text
                    end try
                    if (accountName is "") or (acctName is accountName) then
                        repeat with mb in mailboxes of acct
                            if (count of foundResults) ≥ maxCount then exit repeat
                            if my mailboxMatches(mb, mailboxName) then
                                set mbName to ""
                                try
                                    set mbName to name of mb as text
                                end try
                                set candidateMessages to missing value
                                try
                                    if (startDate is not missing value) and (endDate is not missing value) then
                                        set candidateMessages to (messages of mb whose date received ≥ startDate and date received < endDate)
                                    else if startDate is not missing value then
                                        set candidateMessages to (messages of mb whose date received ≥ startDate)
                                    else if endDate is not missing value then
                                        set candidateMessages to (messages of mb whose date received < endDate)
                                    else
                                        set candidateMessages to messages of mb
                                    end if
                                on error
                                    set candidateMessages to messages of mb
                                end try
                                if candidateMessages is missing value then
                                    set candidateMessages to {}
                                end if
                                repeat with msg in candidateMessages
                                    if (count of foundResults) ≥ maxCount then exit repeat
                                    try
                                        set keepIt to true
                                        set subjText to ""
                                        set senderText to ""
                                        set msgDate to missing value
                                        try
                                            set msgDate to date received of msg
                                        end try
                                        try
                                            set subjText to subject of msg as text
                                        end try
                                        try
                                            set senderText to sender of msg as text
                                        end try
                                        if (startDate is not missing value) and ((msgDate is missing value) or (msgDate < startDate)) then set keepIt to false
                                        if keepIt and (endDate is not missing value) and ((msgDate is missing value) or (msgDate ≥ endDate)) then set keepIt to false
                                        if keepIt and (senderQuery is not "") and (senderText does not contain senderQuery) then set keepIt to false
                                        if keepIt and (subjectQuery is not "") and (subjText does not contain subjectQuery) then set keepIt to false
                                        set recipText to ""
                                        if keepIt and (recipientQuery is not "") then
                                            set toText to ""
                                            set ccText to ""
                                            try
                                                set toText to my joinAddresses(to recipients of msg)
                                            end try
                                            try
                                                set ccText to my joinAddresses(cc recipients of msg)
                                            end try
                                            if toText is not "" and ccText is not "" then
                                                set recipText to toText & ", " & ccText
                                            else
                                                set recipText to toText & ccText
                                            end if
                                            if recipText does not contain recipientQuery then set keepIt to false
                                        else if keepIt then
                                            set toText to ""
                                            set ccText to ""
                                            try
                                                set toText to my joinAddresses(to recipients of msg)
                                            end try
                                            try
                                                set ccText to my joinAddresses(cc recipients of msg)
                                            end try
                                            if toText is not "" and ccText is not "" then
                                                set recipText to toText & ", " & ccText
                                            else
                                                set recipText to toText & ccText
                                            end if
                                        end if
                                        set bodyText to ""
                                        if keepIt and (bodyQuery is not "") then
                                            try
                                                set bodyText to content of msg as text
                                            end try
                                            if bodyText does not contain bodyQuery then set keepIt to false
                                        end if
                                        if keepIt then
                                            set snipText to ""
                                            if bodyText is not "" then
                                                set snipText to my snippetOf(bodyText)
                                            else
                                                try
                                                    set snipText to my snippetOf(content of msg)
                                                end try
                                            end if
                                            set msgIdHeader to ""
                                            try
                                                set msgIdHeader to message id of msg as text
                                            end try
                                            set dateIso to ""
                                            if msgDate is not missing value then
                                                set dateIso to my isoDate(msgDate)
                                            end if
                                            set msgLocalId to ""
                                            try
                                                set msgLocalId to id of msg as text
                                            end try
                                            set end of foundResults to {msgLocalId, msgIdHeader, senderText, recipText, subjText, dateIso, mbName, acctName, snipText}
                                        end if
                                    end try
                                end repeat
                            end if
                        end repeat
                    end if
                end repeat
            end tell
            return foundResults
        end searchMessages

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
