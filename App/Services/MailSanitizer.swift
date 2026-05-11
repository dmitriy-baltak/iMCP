import Foundation
import SwiftSoup

// Pure-Swift sanitization + classification helpers used by mail_fetch_sanitized,
// mail_classify, and mail_attachments_list_sanitized. Has no dependency on
// AppleScript, MCP, or any other app module — testable in isolation via
// Tests/SanitizerTests/.

struct SanitizedBody: Equatable {
    var text: String
    var truncated: Bool
    var originalLength: Int
    var redactionsApplied: [String]
}

struct ExtractedSignals: Codable, Equatable {
    let senderDomain: String
    let linkCount: Int
    let hasAttachments: Bool
    let attachmentCount: Int
    let hasOtpOrCode: Bool
    let hasMagicLink: Bool
    let bodyLength: Int
}

struct MailClassification: Codable, Equatable {
    let messageId: String
    let from: String
    let to: String
    let subject: String
    let date: String
    let inReplyTo: String?
    let references: [String]
    let classification: String
    let extracted: ExtractedSignals
    let isHuman: Bool
    let lowEngagement: Bool
}

enum MailSanitizer {

    static let defaultMaxChars: Int = 10_000
    static let minMaxChars: Int = 500
    static let maxMaxChars: Int = 50_000
    static let attachmentNameMaxChars: Int = 128
    static let subjectMaxChars: Int = 500
    static let addressFieldMaxChars: Int = 1_024
    static let shortHeaderMaxChars: Int = 512

    static func clampMaxChars(_ requested: Int) -> Int {
        return min(max(requested, minMaxChars), maxMaxChars)
    }

    // MARK: - Body sanitization pipeline

    static func sanitizeBody(_ raw: String, maxChars: Int) -> SanitizedBody {
        let originalLength = raw.count
        var redactions: [String] = []

        var text = stripHTML(raw)
        text = stripZeroWidth(text)

        let (urlText, urlRedacted) = neutralizeURLs(text)
        text = urlText
        if urlRedacted { redactions.append("url") }

        let (secretText, secretLabels) = redactSecrets(text)
        text = secretText
        redactions.append(contentsOf: secretLabels)

        let (otpText, otpLabel) = redactOTPs(text)
        text = otpText
        if let label = otpLabel { redactions.append(label) }

        text = collapseWhitespace(text)
        let (capped, truncated) = capLength(text, max: clampMaxChars(maxChars))

        return SanitizedBody(
            text: capped,
            truncated: truncated,
            originalLength: originalLength,
            redactionsApplied: redactions
        )
    }

    // MARK: - HTML stripping (SwiftSoup)

    // Tags whose contents must be dropped along with the tag itself, because
    // they're either non-rendering (script/style/noscript/head/title/meta/link)
    // or load attacker-controlled foreign content (iframe/object/embed).
    private static let nonRenderingSelector = "script, style, noscript, head, title, meta, link, iframe, object, embed"

    // Matches a complete `<script>…</script>` (or style/noscript/iframe…) block
    // INCLUDING its contents. Run before SwiftSoup so attacker tricks like
    // `<scr<script>ipt>alert(1)</script>` — which HTML5 parser-recovery
    // mangles — get their inner script body stripped first.
    private static let dangerousElementBlockRegex: NSRegularExpression = {
        let pattern = #"(?is)<(script|style|noscript|iframe|object|embed|head|title)\b[^>]*>.*?</\1\s*>"#
        return try! NSRegularExpression(pattern: pattern, options: [])
    }()

    // Upper bound on iteration of the strip+decode loop. An attacker who
    // wraps `<script>` in N levels of `&amp;`-encoding needs N passes to
    // unwrap. 25 is well beyond any plausible benign nesting; pathological
    // inputs hit the cap and then get the defensive final pass below.
    private static let stripHTMLMaxIterations = 25

    static func stripHTML(_ s: String) -> String {
        // Fast path: no markup means nothing to do.
        guard s.contains("<") || s.contains("&") else { return s }
        var current = s
        var stable = false
        // Iterate: entity decoding can reveal new tags (e.g. `&lt;script&gt;`
        // becomes literal `<script>` after one pass through SwiftSoup), so
        // each pass may unwrap one entity layer. Loop until stable or cap.
        for _ in 0..<stripHTMLMaxIterations {
            let next = stripHTMLOnce(current)
            if next == current { stable = true; break }
            current = next
        }
        // Defense in depth. Two failure modes the loop alone doesn't cover:
        //   1. The loop hit the cap with markup still being unwrapped
        //      (pathological deep nesting like 60 levels of `&amp;`).
        //   2. The loop *stabilized* on a state with no literal `<` but
        //      still containing entity-encoded markup
        //      (`&amp;amp;…amp;lt;script&amp;…&gt;steal()&amp;…&gt;`).
        //      SwiftSoup decodes one entity layer per pass, so deep enough
        //      encoding can stabilize while still encoding tag content.
        // Either way: aggressively unwrap *every* remaining entity layer
        // independent of SwiftSoup's pass behavior, then run the regex
        // strip passes. Idempotent on already-clean input.
        if !stable || containsMarkupOrEntity(current) {
            current = aggressivelyDecodeEntities(current)
            current = stripDangerousBlocks(current)
            current = conservativeHTMLTagStrip(current)
        }
        return current
    }

    // Detects either literal `<` or any HTML entity reference like `&amp;`,
    // `&#39;`, `&#x27;`. We deliberately allow stray `&` (e.g. `Tom & Jerry`).
    private static let markupEntityRegex: NSRegularExpression = {
        try! NSRegularExpression(pattern: #"&(?:[a-zA-Z]+|#[0-9]+|#x[0-9a-fA-F]+);"#, options: [])
    }()

    private static func containsMarkupOrEntity(_ s: String) -> Bool {
        if s.contains("<") { return true }
        let nsString = s as NSString
        return markupEntityRegex.firstMatch(
            in: s, options: [],
            range: NSRange(location: 0, length: nsString.length)
        ) != nil
    }

    // Repeatedly applies SwiftSoup's `Entities.unescape` (which decodes one
    // layer per call) until the text stabilizes or 100 iterations elapse —
    // enough headroom for any plausible adversarial nesting. Falls back to
    // the input on parser error.
    private static func aggressivelyDecodeEntities(_ s: String) -> String {
        var current = s
        for _ in 0..<100 {
            guard let next = try? Entities.unescape(current) else { break }
            if next == current { break }
            current = next
        }
        return current
    }

    private static func stripHTMLOnce(_ s: String) -> String {
        // Step 1: regex-strip whole dangerous blocks so their text body
        // (`alert(1)`, CSS rules, raw scripts) is dropped along with the tag.
        let nsString = s as NSString
        let preprocessed = dangerousElementBlockRegex.stringByReplacingMatches(
            in: s,
            options: [],
            range: NSRange(location: 0, length: nsString.length),
            withTemplate: ""
        )
        // Step 2: SwiftSoup parses the surviving HTML, we drop the same set
        // of elements again (in case any unbalanced tags survived the regex),
        // then `.text()` gives us the rendered text content. `.text()`
        // automatically decodes HTML entities — which is why this whole
        // function loops outside.
        do {
            let doc = try SwiftSoup.parseBodyFragment(preprocessed)
            try doc.select(nonRenderingSelector).remove()
            return try doc.text()
        } catch {
            return preprocessed.replacingOccurrences(
                of: "<[^>]+>", with: "", options: .regularExpression
            )
        }
    }

    // MARK: - Zero-width / invisible char stripping

    private static let zeroWidthScalars: Set<Unicode.Scalar> = [
        Unicode.Scalar(0x200B)!, // ZERO WIDTH SPACE
        Unicode.Scalar(0x200C)!, // ZERO WIDTH NON-JOINER
        Unicode.Scalar(0x200D)!, // ZERO WIDTH JOINER
        Unicode.Scalar(0x2060)!, // WORD JOINER
        Unicode.Scalar(0xFEFF)!, // ZERO WIDTH NO-BREAK SPACE / BOM
        Unicode.Scalar(0x180E)!, // MONGOLIAN VOWEL SEPARATOR
    ]

    static func stripZeroWidth(_ s: String) -> String {
        var out = String.UnicodeScalarView()
        out.reserveCapacity(s.unicodeScalars.count)
        for scalar in s.unicodeScalars where !zeroWidthScalars.contains(scalar) {
            out.append(scalar)
        }
        return String(out)
    }

    // MARK: - URL neutralization

    private static let urlDetector: NSDataDetector = {
        // swiftlint:disable:next force_try
        try! NSDataDetector(types: NSTextCheckingResult.CheckingType.link.rawValue)
    }()

    /// Replaces every URL with a `[link: <host>]` / `[email: <domain>]` /
    /// `[link: <scheme>]` placeholder. Returns the rewritten string and a
    /// flag indicating whether any rewriting occurred.
    static func neutralizeURLs(_ s: String) -> (String, Bool) {
        let nsString = s as NSString
        let matches = urlDetector.matches(
            in: s,
            range: NSRange(location: 0, length: nsString.length)
        )
        guard !matches.isEmpty else { return (s, false) }

        let result = NSMutableString(string: nsString)
        // Replace from the tail so earlier ranges stay valid.
        for match in matches.reversed() {
            let original = nsString.substring(with: match.range)
            let placeholder = placeholder(for: original, url: match.url)
            result.replaceCharacters(in: match.range, with: placeholder)
        }
        return (result as String, true)
    }

    private static func placeholder(for raw: String, url: URL?) -> String {
        guard let url = url else { return "[link]" }
        let scheme = (url.scheme ?? "").lowercased()
        switch scheme {
        case "http", "https":
            let host = url.host?.lowercased() ?? "unknown"
            return "[link: \(registrableDomain(host))]"
        case "mailto":
            // url.host is nil for mailto; parse the path for the domain.
            let addr = url.absoluteString
                .replacingOccurrences(of: "mailto:", with: "")
                .split(separator: "?").first.map(String.init) ?? ""
            let domain = addr.split(separator: "@").last.map(String.init) ?? "unknown"
            return "[email: \(domain.lowercased())]"
        case "":
            // NSDataDetector occasionally yields raw URLs without a scheme —
            // be conservative and bracket the host portion of the raw text.
            let host = raw.split(separator: "/").first.map(String.init) ?? raw
            return "[link: \(host.lowercased())]"
        default:
            return "[link: \(scheme)]"
        }
    }

    private static func registrableDomain(_ host: String) -> String {
        // Crude eTLD+1: take the last two labels. Good enough to hide
        // tracker-specific subdomains ("track.evil.com" → "evil.com")
        // without bringing in the full Public Suffix List.
        let labels = host.split(separator: ".")
        guard labels.count >= 2 else { return host }
        return labels.suffix(2).joined(separator: ".")
    }

    // MARK: - Secret redaction (uses vendored SecretPatterns)

    /// Returns the redacted text and the set of pattern labels that fired.
    static func redactSecrets(_ s: String) -> (String, [String]) {
        var text = s
        var firedLabels: [String] = []
        for pattern in SecretPatterns.all {
            let nsString = text as NSString
            let range = NSRange(location: 0, length: nsString.length)
            let matchCount = pattern.regex.numberOfMatches(
                in: text, options: [], range: range
            )
            if matchCount > 0 {
                firedLabels.append(pattern.label)
                text = pattern.regex.stringByReplacingMatches(
                    in: text,
                    options: [],
                    range: range,
                    withTemplate: NSRegularExpression.escapedTemplate(for: pattern.replacement)
                )
            }
        }
        return (text, firedLabels)
    }

    // MARK: - OTP redaction (email-specific, not credential-shaped)

    // Pattern A: ambiguous context word + a OTP-suffix word (code | password
    // | pin). The qualifier disambiguates from generic uses (`source code`,
    // `user password`, `pin location`); the suffix word covers the common
    // phrasings — `verification code`, `one-time password`, `temporary pin`,
    // `single-use code`, etc. — followed within 30 chars by the digits.
    private static let otpContextCodeRegex: NSRegularExpression = {
        let pattern = #"(?i)((?:verification|confirmation|security|access|one[ \-]?time|single[ \-]?use|temporary)[ \t]+(?:code|password|pin)[^\n]{0,30}?)\b\d{4,8}\b"#
        return try! NSRegularExpression(pattern: pattern, options: [])
    }()

    // Pattern B: standalone-meaningful trigger words that are themselves the
    // OTP context (no " code" suffix needed). Matches `OTP: 4829`,
    // `passcode 1234`, `2FA — 482915`, `verification: 9999`, etc. The
    // `[^\w\n]{1,10}?` separator allows colons / spaces / dashes but stops
    // at the next word, so "OTP for John 4829" / "PIN factory 1234" don't
    // false-trigger.
    private static let otpStandaloneRegex: NSRegularExpression = {
        let pattern = #"(?i)\b((?:otp|passcode|pass\s?code|pin|2fa|mfa|verification|confirmation)\b[^\w\n]{1,10}?)\b\d{4,8}\b"#
        return try! NSRegularExpression(pattern: pattern, options: [])
    }()

    private static let otpContextSignalRegex: NSRegularExpression = {
        let pattern = #"(?i)(verification|confirmation|otp|passcode|2fa|two[ \-]?factor)"#
        return try! NSRegularExpression(pattern: pattern, options: [])
    }()

    private static let standalone6DigitRegex: NSRegularExpression = {
        try! NSRegularExpression(pattern: #"\b\d{6}\b"#, options: [])
    }()

    /// Returns redacted text and a label ("otp") if any redaction happened.
    static func redactOTPs(_ s: String) -> (String, String?) {
        var text = s
        var didRedact = false

        // Pass 1: ambiguous context word + " code" + digits.
        let nsA = text as NSString
        let nextA = otpContextCodeRegex.stringByReplacingMatches(
            in: text, options: [],
            range: NSRange(location: 0, length: nsA.length),
            withTemplate: "$1[redacted: otp]"
        )
        if nextA != text {
            didRedact = true
            text = nextA
        }

        // Pass 2: standalone-meaningful trigger (OTP / passcode / PIN / 2fa /
        // mfa / verification / confirmation) + separator + digits.
        let nsB = text as NSString
        let nextB = otpStandaloneRegex.stringByReplacingMatches(
            in: text, options: [],
            range: NSRange(location: 0, length: nsB.length),
            withTemplate: "$1[redacted: otp]"
        )
        if nextB != text {
            didRedact = true
            text = nextB
        }

        // Pass 3: fallback — only if the body talks about codes/2FA somewhere,
        // redact remaining bare 6-digit strings. Guards against zip codes etc.
        let signalNS = text as NSString
        let signalRange = NSRange(location: 0, length: signalNS.length)
        if otpContextSignalRegex.firstMatch(in: text, options: [], range: signalRange) != nil {
            let after = standalone6DigitRegex.stringByReplacingMatches(
                in: text, options: [],
                range: signalRange,
                withTemplate: "[redacted: otp]"
            )
            if after != text {
                text = after
                didRedact = true
            }
        }

        return (text, didRedact ? "otp" : nil)
    }

    // MARK: - Whitespace + length cap

    private static let multiNewlineRegex: NSRegularExpression = {
        try! NSRegularExpression(pattern: #"\n{3,}"#, options: [])
    }()

    private static let multiSpaceRegex: NSRegularExpression = {
        // Spaces and tabs only — preserve newlines for paragraph structure.
        try! NSRegularExpression(pattern: #"[ \t]{2,}"#, options: [])
    }()

    static func collapseWhitespace(_ s: String) -> String {
        let nsString = s as NSString
        var out = multiNewlineRegex.stringByReplacingMatches(
            in: s,
            options: [],
            range: NSRange(location: 0, length: nsString.length),
            withTemplate: "\n\n"
        )
        let outNS = out as NSString
        out = multiSpaceRegex.stringByReplacingMatches(
            in: out,
            options: [],
            range: NSRange(location: 0, length: outNS.length),
            withTemplate: " "
        )
        return out.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    static func capLength(_ s: String, max: Int) -> (text: String, truncated: Bool) {
        guard s.count > max else { return (s, false) }
        let head = String(s.prefix(max))
        let dropped = s.count - max
        return ("\(head)\n[truncated: \(dropped) chars]", true)
    }

    // MARK: - Attachment helpers

    // MARK: - Envelope-field sanitization

    /// Subject-style sanitization for the `subject` envelope field.
    /// Subjects routinely carry verification codes, magic links, and
    /// attacker-controlled prose — same threat model as the body, so we
    /// run the full body pipeline (HTML / zero-width / URL / secrets /
    /// OTPs) but with a tighter cap.
    static func sanitizeSubject(_ raw: String) -> String {
        let sanitized = sanitizeBody(raw, maxChars: subjectMaxChars)
        return sanitized.text
    }

    /// Address-field sanitization for `from` / `to` / `cc` / `bcc` /
    /// `replyTo`. Strips HTML tags and zero-width chars, replaces controls
    /// with spaces, collapses runs, length-caps. Does NOT neutralize
    /// URLs (would mangle the embedded email addresses) and does NOT
    /// redact secrets (false-positive risk on long structured strings).
    ///
    /// Uses a *conservative* regex tag-strip rather than the full HTML
    /// parser: an email address like `<bob@example.com>` looks like a tag
    /// to SwiftSoup and gets eaten whole. The regex only matches `<TAG>`
    /// / `</TAG>` where `TAG` starts with a letter and contains only
    /// letters and digits, so legitimate angle-addressed emails survive.
    static func sanitizeAddressField(_ raw: String) -> String {
        var s = stripDangerousBlocks(raw)
        s = conservativeHTMLTagStrip(s)
        s = stripZeroWidth(s)
        s = replaceControlCharsWithSpace(s)
        s = s.replacingOccurrences(
            of: #"[ \t]{2,}"#, with: " ", options: .regularExpression
        )
        s = s.trimmingCharacters(in: .whitespacesAndNewlines)
        if s.count > addressFieldMaxChars {
            s = String(s.prefix(addressFieldMaxChars - 1)) + "…"
        }
        return s
    }

    private static let conservativeHTMLTagRegex: NSRegularExpression = {
        // Matches `<tag>`, `<tag attr=val>`, `</tag>` where `tag` is purely
        // alphanumeric (real HTML tags). Email addresses like
        // `<bob@example.com>` contain `@` and `.` so they don't match.
        let pattern = #"</?[A-Za-z][A-Za-z0-9]*(?:\s[^>]*)?>"#
        return try! NSRegularExpression(pattern: pattern, options: [])
    }()

    private static func conservativeHTMLTagStrip(_ s: String) -> String {
        let nsString = s as NSString
        return conservativeHTMLTagRegex.stringByReplacingMatches(
            in: s, options: [],
            range: NSRange(location: 0, length: nsString.length),
            withTemplate: ""
        )
    }

    private static func stripDangerousBlocks(_ s: String) -> String {
        let nsString = s as NSString
        return dangerousElementBlockRegex.stringByReplacingMatches(
            in: s, options: [],
            range: NSRange(location: 0, length: nsString.length),
            withTemplate: ""
        )
    }

    /// Short-header sanitization for `messageId` / `inReplyTo` /
    /// `references` items / `date` / `mailbox` / `account` / `id`.
    /// Conservative HTML tag-strip (preserves `<addr@domain>` style
    /// Message-IDs) + zero-width strip + control strip + cap. No URL or
    /// secret redaction (these fields aren't free-form prose).
    static func sanitizeShortHeader(_ raw: String) -> String {
        var s = stripDangerousBlocks(raw)
        s = conservativeHTMLTagStrip(s)
        s = stripZeroWidth(s)
        s = replaceControlCharsWithSpace(s)
        s = s.replacingOccurrences(
            of: #"\s+"#, with: " ", options: .regularExpression
        )
        s = s.trimmingCharacters(in: .whitespacesAndNewlines)
        if s.count > shortHeaderMaxChars {
            s = String(s.prefix(shortHeaderMaxChars - 1)) + "…"
        }
        return s
    }

    private static func replaceControlCharsWithSpace(_ s: String) -> String {
        return String(String.UnicodeScalarView(s.unicodeScalars.map { scalar in
            CharacterSet.controlCharacters.contains(scalar)
                ? Unicode.Scalar(0x20)! : scalar
        }))
    }

    static func sanitizeAttachmentName(_ raw: String) -> String {
        var s = stripHTML(raw)
        s = stripZeroWidth(s)
        // Replace every control character (incl. CR/LF, tabs, BEL) with a
        // space — they must not span lines or carry escape sequences, but
        // we don't want to fuse adjacent words like "report\tname" into
        // "reportname".
        s = replaceControlCharsWithSpace(s)
        // Collapse internal whitespace runs to a single space.
        s = s.replacingOccurrences(
            of: #"\s+"#, with: " ", options: .regularExpression
        )
        s = s.trimmingCharacters(in: .whitespaces)
        if s.count > attachmentNameMaxChars {
            let head = String(s.prefix(attachmentNameMaxChars - 1))
            s = head + "…"
        }
        return s.isEmpty ? "[unnamed-attachment]" : s
    }

    private static let allowedMimeTypes: Set<String> = [
        "text/plain", "text/html", "text/csv", "text/calendar", "text/markdown",
        "image/jpeg", "image/png", "image/gif", "image/webp", "image/heic", "image/heif",
        "application/pdf",
        "application/msword",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.ms-excel",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.ms-powerpoint",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "application/zip", "application/json", "application/xml",
        "message/rfc822",
    ]

    static func normalizeMimeType(_ raw: String) -> String {
        let s = raw.lowercased().trimmingCharacters(in: .whitespacesAndNewlines)
        return allowedMimeTypes.contains(s) ? s : "application/octet-stream"
    }

    // MARK: - Classification

    static func classify(
        messageId: String,
        from: String,
        to: String,
        subject: String,
        date: String,
        headersBlock: String,
        sanitizedBody: String,
        attachmentCount: Int
    ) -> MailClassification {
        let headers = MailHeaderParser.parse(headersBlock)
        let rawInReplyTo = headers.first("in-reply-to")?
            .trimmingCharacters(in: CharacterSet(charactersIn: "<>"))
        let rawReferences = (headers.first("references") ?? "")
            .split(whereSeparator: { $0.isWhitespace })
            .map { $0.trimmingCharacters(in: CharacterSet(charactersIn: "<>")) }
            .filter { !$0.isEmpty }

        // Sanitize each envelope field BEFORE storing — otherwise the
        // structurally-locked schema would still pass attacker-controlled
        // text (subject prose, display-name HTML, zero-width steg in
        // Message-IDs) straight to the orchestrator.
        let safeMessageId = sanitizeShortHeader(messageId)
        let safeFrom = sanitizeAddressField(from)
        let safeTo = sanitizeAddressField(to)
        let safeSubject = sanitizeSubject(subject)
        let safeDate = sanitizeShortHeader(date)
        let safeInReplyTo = rawInReplyTo.map(sanitizeShortHeader)
        let safeReferences = rawReferences.map(sanitizeShortHeader)

        // Heuristics still look at the raw `from`/`subject` for sender-domain
        // extraction and marketing-keyword matching — sanitization is
        // idempotent and structure-preserving for these fields, so the
        // sanitized values are safe to pass to the heuristics too.
        let isHuman = computeIsHuman(from: safeFrom, headers: headers)
        let linkCount = countLinkPlaceholders(in: sanitizedBody)
        let lowEngagement = computeLowEngagement(
            isHuman: isHuman, headers: headers, linkCount: linkCount
        )
        let hasOtpOrCode = sanitizedBody.contains("[redacted: otp]")
            || safeSubject.contains("[redacted: otp]")
        let hasMagicLink = detectMagicLink(in: sanitizedBody, subject: safeSubject)
        let classification = computeClassification(
            isHuman: isHuman,
            lowEngagement: lowEngagement,
            subject: safeSubject,
            body: sanitizedBody
        )

        let extracted = ExtractedSignals(
            senderDomain: senderDomain(from: safeFrom),
            linkCount: linkCount,
            hasAttachments: attachmentCount > 0,
            attachmentCount: attachmentCount,
            hasOtpOrCode: hasOtpOrCode,
            hasMagicLink: hasMagicLink,
            bodyLength: sanitizedBody.count
        )

        return MailClassification(
            messageId: safeMessageId,
            from: safeFrom,
            to: safeTo,
            subject: safeSubject,
            date: safeDate,
            inReplyTo: (safeInReplyTo?.isEmpty ?? true) ? nil : safeInReplyTo,
            references: safeReferences,
            classification: classification,
            extracted: extracted,
            isHuman: isHuman,
            lowEngagement: lowEngagement
        )
    }

    // MARK: - Classification helpers

    private static let nonHumanFromRegex: NSRegularExpression = {
        let pattern = #"(?i)(no[ \-]?reply|donotreply|do_not_reply|noreply|notifications?|automated|mailer[ \-]?daemon|postmaster|bounces?|news(?:letter)?)@"#
        return try! NSRegularExpression(pattern: pattern, options: [])
    }()

    private static func computeIsHuman(
        from: String, headers: MailHeaderParser
    ) -> Bool {
        if matches(nonHumanFromRegex, in: from) { return false }
        if let autoSubmitted = headers.first("auto-submitted")?
            .lowercased().trimmingCharacters(in: .whitespaces),
           autoSubmitted != "no", !autoSubmitted.isEmpty {
            return false
        }
        if let precedence = headers.first("precedence")?.lowercased(),
           precedence.contains("bulk") || precedence.contains("list") || precedence.contains("junk") {
            return false
        }
        return true
    }

    private static func computeLowEngagement(
        isHuman: Bool, headers: MailHeaderParser, linkCount: Int
    ) -> Bool {
        if headers.first("list-unsubscribe") != nil { return true }
        if let precedence = headers.first("precedence")?.lowercased(),
           precedence.contains("bulk") {
            return true
        }
        if linkCount >= 5 && !isHuman { return true }
        return false
    }

    private static let marketingSubjectRegex: NSRegularExpression = {
        let pattern = #"(?i)(%[ ]?off|sale\b|deal\b|discount|save \d|free shipping|limited time|exclusive offer|coupon)"#
        return try! NSRegularExpression(pattern: pattern, options: [])
    }()

    private static let transactionalRegex: NSRegularExpression = {
        let pattern = #"(?i)(receipt|invoice\b|order #|order confirmation|booking|reservation|password|verification|otp|2fa|two[ \-]?factor|payment received|shipping confirmation)"#
        return try! NSRegularExpression(pattern: pattern, options: [])
    }()

    private static func computeClassification(
        isHuman: Bool, lowEngagement: Bool, subject: String, body: String
    ) -> String {
        let combined = subject + "\n" + body
        let isTransactional = matches(transactionalRegex, in: combined)
        if isTransactional && !isHuman { return "transactional" }
        if lowEngagement && matches(marketingSubjectRegex, in: subject) {
            return "marketing"
        }
        if lowEngagement { return "notification" }
        if !isHuman { return "automated" }
        if isHuman { return "personal" }
        return "unknown"
    }

    private static func countLinkPlaceholders(in body: String) -> Int {
        let pattern = #"\[link: [^\]]+\]"#
        guard let regex = try? NSRegularExpression(pattern: pattern, options: []) else {
            return 0
        }
        let nsString = body as NSString
        return regex.numberOfMatches(
            in: body, options: [], range: NSRange(location: 0, length: nsString.length)
        )
    }

    private static let magicLinkSubjectRegex: NSRegularExpression = {
        let pattern = #"(?i)(reset your password|sign[ \-]?in link|magic link|verify your|confirm your|complete your sign|finish setting up)"#
        return try! NSRegularExpression(pattern: pattern, options: [])
    }()

    private static func detectMagicLink(in body: String, subject: String) -> Bool {
        if matches(magicLinkSubjectRegex, in: subject) { return true }
        // Heuristic: the body mentions "click" near a link placeholder.
        let lower = body.lowercased()
        if lower.contains("click") && body.contains("[link:") { return true }
        if lower.contains("reset your password") { return true }
        return false
    }

    private static func senderDomain(from: String) -> String {
        // Pull the @domain out of "Name <addr@domain>" or bare "addr@domain".
        let scanner = Scanner(string: from)
        scanner.charactersToBeSkipped = nil
        var addr = from
        if let openIdx = from.lastIndex(of: "<"),
           let closeIdx = from.lastIndex(of: ">"),
           openIdx < closeIdx {
            addr = String(from[from.index(after: openIdx)..<closeIdx])
        }
        let parts = addr.split(separator: "@")
        guard let domain = parts.last, parts.count >= 2 else { return "" }
        _ = scanner
        return domain.lowercased().trimmingCharacters(in: .whitespaces)
    }

    // MARK: - small helper

    private static func matches(_ regex: NSRegularExpression, in s: String) -> Bool {
        let nsString = s as NSString
        return regex.firstMatch(
            in: s, options: [], range: NSRange(location: 0, length: nsString.length)
        ) != nil
    }
}

// MARK: - Header parsing (RFC 5322 unfolded)

struct MailHeaderParser {
    private let map: [String: [String]]   // lowercased name → values

    static func parse(_ block: String) -> MailHeaderParser {
        // Unfold continuation lines (RFC 5322 §2.2.3): a line beginning with
        // whitespace continues the prior header. Then split into name/value
        // on the first colon.
        var unfolded: [String] = []
        for line in block.replacingOccurrences(of: "\r\n", with: "\n").split(separator: "\n", omittingEmptySubsequences: false) {
            if let first = line.first, first == " " || first == "\t",
               !unfolded.isEmpty {
                unfolded[unfolded.count - 1] += " " + line.trimmingCharacters(in: .whitespaces)
            } else {
                unfolded.append(String(line))
            }
        }

        var byName: [String: [String]] = [:]
        for header in unfolded {
            guard let colon = header.firstIndex(of: ":") else { continue }
            let name = header[..<colon].lowercased().trimmingCharacters(in: .whitespaces)
            let value = header[header.index(after: colon)...]
                .trimmingCharacters(in: .whitespaces)
            guard !name.isEmpty else { continue }
            byName[name, default: []].append(value)
        }
        return MailHeaderParser(map: byName)
    }

    func first(_ name: String) -> String? {
        return map[name.lowercased()]?.first
    }

    func all(_ name: String) -> [String] {
        return map[name.lowercased()] ?? []
    }
}
