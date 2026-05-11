import XCTest
@testable import MailSanitizer

final class ClassifierTests: XCTestCase {

    // Helper: parse a fixture that has headers + blank line + body, classify it.
    private func classifyFixture(_ name: String) throws -> MailClassification {
        let url = try XCTUnwrap(Bundle.module.url(
            forResource: name, withExtension: "txt", subdirectory: "Fixtures"
        ))
        let raw = try String(contentsOf: url, encoding: .utf8)
        let (headersBlock, body) = splitHeadersAndBody(raw)
        let parsed = MailHeaderParser.parse(headersBlock)
        let sanitized = MailSanitizer.sanitizeBody(body, maxChars: 10_000)
        return MailSanitizer.classify(
            messageId: parsed.first("message-id") ?? "msg-\(name)",
            from: parsed.first("from") ?? "",
            to: parsed.first("to") ?? "",
            subject: parsed.first("subject") ?? "",
            date: parsed.first("date") ?? "",
            headersBlock: headersBlock,
            sanitizedBody: sanitized.text,
            attachmentCount: 0
        )
    }

    private func splitHeadersAndBody(_ raw: String) -> (String, String) {
        if let range = raw.range(of: "\n\n") {
            return (String(raw[..<range.lowerBound]), String(raw[range.upperBound...]))
        }
        return (raw, "")
    }

    // MARK: - isHuman / lowEngagement

    func test_noReplyFrom_marksIsHumanFalse() throws {
        let result = try classifyFixture("automated_notification")
        XCTAssertFalse(result.isHuman)
    }

    func test_listUnsubscribeHeader_marksLowEngagementTrue() throws {
        let result = try classifyFixture("marketing_email")
        XCTAssertTrue(result.lowEngagement)
    }

    func test_personalEmail_classifiedPersonal_andIsHuman() throws {
        let result = try classifyFixture("personal_email")
        XCTAssertEqual(result.classification, "personal")
        XCTAssertTrue(result.isHuman)
        XCTAssertFalse(result.lowEngagement)
    }

    func test_personalEmail_referencesParsed() throws {
        let result = try classifyFixture("personal_email")
        XCTAssertEqual(result.references.count, 2)
        XCTAssertEqual(result.references[0], "abcd1234@example.com")
        XCTAssertEqual(result.inReplyTo, "abcd1234@example.com")
    }

    func test_marketingEmail_classifiedMarketing() throws {
        let result = try classifyFixture("marketing_email")
        XCTAssertEqual(result.classification, "marketing")
    }

    func test_otpEmail_classifiedTransactional_andHasOtpFlag() throws {
        let result = try classifyFixture("transactional_otp")
        XCTAssertEqual(result.classification, "transactional")
        XCTAssertTrue(result.extracted.hasOtpOrCode)
        XCTAssertFalse(result.isHuman)
    }

    // MARK: - extracted signals

    func test_senderDomain_extractedFromAngleAddress() {
        let result = MailSanitizer.classify(
            messageId: "x",
            from: "Acme <noreply@acme.example>",
            to: "u@example.com",
            subject: "hi",
            date: "",
            headersBlock: "",
            sanitizedBody: "",
            attachmentCount: 0
        )
        XCTAssertEqual(result.extracted.senderDomain, "acme.example")
    }

    func test_senderDomain_extractedFromBareAddress() {
        let result = MailSanitizer.classify(
            messageId: "x",
            from: "alice@example.com",
            to: "u@example.com",
            subject: "hi",
            date: "",
            headersBlock: "",
            sanitizedBody: "",
            attachmentCount: 0
        )
        XCTAssertEqual(result.extracted.senderDomain, "example.com")
    }

    func test_attachmentSignals_reflectInputs() {
        let result = MailSanitizer.classify(
            messageId: "x", from: "a@b.example", to: "c@d.example",
            subject: "hi", date: "", headersBlock: "",
            sanitizedBody: "see attached",
            attachmentCount: 3
        )
        XCTAssertTrue(result.extracted.hasAttachments)
        XCTAssertEqual(result.extracted.attachmentCount, 3)
    }

    // MARK: - Schema enforcement (the structural guarantee)

    func test_classification_outputJson_doesNotContainBodyField() throws {
        let result = try classifyFixture("transactional_otp")
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(result)
        let json = try XCTUnwrap(String(data: data, encoding: .utf8))
        for forbidden in [
            "\"body\"", "\"content\"", "\"raw\"", "\"excerpt\"",
            "\"headers\"", "\"summary\"",
        ] {
            XCTAssertFalse(
                json.contains(forbidden),
                "classification JSON must not contain \(forbidden); got: \(json)"
            )
        }
    }

    func test_classification_outputJson_doesNotLeakBodyProse() {
        // Body prose — including injection prose — must NEVER round-trip
        // into the classification response, because the structural sanitizer
        // doesn't filter semantic content. Use a unique canary token in the
        // body that cannot appear in any envelope field, and assert it's
        // absent from the JSON. This is the regression test for the
        // body-derived-summary leak.
        let canary = "MAIL-CLASSIFY-CANARY-Q9X-DO-NOT-LEAK"
        let body = """
        \(canary). Hello team, the project deadline is moved.
        Please confirm by tomorrow.
        """
        let result = MailSanitizer.classify(
            messageId: "x@example.com",
            from: "alice@example.com",
            to: "bob@example.com",
            subject: "Project update",
            date: "Wed, 11 May 2026 10:00:00 +0000",
            headersBlock: "",
            sanitizedBody: body,
            attachmentCount: 0
        )
        let data = try! JSONEncoder().encode(result)
        let json = String(data: data, encoding: .utf8)!
        XCTAssertFalse(
            json.contains(canary),
            "body content leaked into classification JSON: \(json)"
        )
        // And second canary in the body's first sentence — this is exactly
        // the slot the old `summary` field was drawn from.
        let injection = "PROSE-INJECTION-IGNORE-PREVIOUS-TOKEN-7K"
        let body2 = "\(injection). Click below to reset your password."
        let result2 = MailSanitizer.classify(
            messageId: "y@example.com",
            from: "noreply@securebank.example",
            to: "u@example.com",
            subject: "Password reset",
            date: "Wed, 11 May 2026 10:00:00 +0000",
            headersBlock: "",
            sanitizedBody: body2,
            attachmentCount: 0
        )
        let data2 = try! JSONEncoder().encode(result2)
        let json2 = String(data: data2, encoding: .utf8)!
        XCTAssertFalse(
            json2.contains(injection),
            "first-sentence prose leaked into classify JSON: \(json2)"
        )
    }

    func test_classification_outputJson_keysMatchToolDescription() throws {
        // The mail_classify tool description advertises camelCase keys.
        // Pin every documented key so a Swift-side rename or an accidental
        // CodingKeys override can't silently drift the JSON shape away from
        // what callers were told to expect. Use the personal_email fixture
        // because it exercises every documented field including the optional
        // `inReplyTo` and the `references` array.
        let result = try classifyFixture("personal_email")
        let data = try JSONEncoder().encode(result)
        let json = try XCTUnwrap(String(data: data, encoding: .utf8))
        let topLevel = [
            "messageId", "from", "to", "subject", "date",
            "inReplyTo", "references", "classification", "extracted",
            "isHuman", "lowEngagement",
        ]
        let extractedKeys = [
            "senderDomain", "linkCount", "hasAttachments", "attachmentCount",
            "hasOtpOrCode", "hasMagicLink", "bodyLength",
        ]
        for key in topLevel + extractedKeys {
            XCTAssertTrue(
                json.contains("\"\(key)\""),
                "documented key '\(key)' missing from classify JSON: \(json)"
            )
        }
        // And the snake_case forms the description used to (incorrectly) advertise
        // must NOT appear — that bug is exactly what this test is pinning.
        let snakeBugs = [
            "has_otp_or_code", "has_magic_link", "link_count",
            "has_attachments", "attachment_count", "sender_domain",
            "body_length", "is_human", "low_engagement", "in_reply_to",
        ]
        for key in snakeBugs {
            XCTAssertFalse(
                json.contains(key),
                "snake_case key '\(key)' must not appear in classify JSON: \(json)"
            )
        }
    }

    func test_extractedHasOtpOrCode_doesNotIncludeOtpValue() throws {
        let result = try classifyFixture("transactional_otp")
        let data = try JSONEncoder().encode(result)
        let json = try XCTUnwrap(String(data: data, encoding: .utf8))
        XCTAssertFalse(
            json.contains("482915"),
            "OTP digits leaked into classification JSON: \(json)"
        )
        XCTAssertTrue(result.extracted.hasOtpOrCode)
    }

    // MARK: - magic link detection

    func test_magicLink_detectedFromResetPasswordSubject() throws {
        let result = MailSanitizer.classify(
            messageId: "x", from: "noreply@a.example", to: "u@b.example",
            subject: "Reset your password", date: "", headersBlock: "",
            sanitizedBody: "Click [link: a.example] to reset.", attachmentCount: 0
        )
        XCTAssertTrue(result.extracted.hasMagicLink)
    }

    // MARK: - Envelope-field sanitization in classify()

    func test_classify_subjectIsSanitized_otpInSubjectRedacted() {
        let result = MailSanitizer.classify(
            messageId: "x",
            from: "bank@example.com",
            to: "u@example.com",
            subject: "Your verification code: 482915",
            date: "",
            headersBlock: "",
            sanitizedBody: "",
            attachmentCount: 0
        )
        XCTAssertFalse(result.subject.contains("482915"))
        XCTAssertTrue(result.subject.contains("[redacted: otp]"))
        XCTAssertTrue(result.extracted.hasOtpOrCode)
    }

    func test_classify_fromFieldHtmlAndZeroWidthStripped() {
        let result = MailSanitizer.classify(
            messageId: "x",
            from: "<script>alert(1)</script>Bob \u{200B}<bob@example.com>",
            to: "u@example.com",
            subject: "hi",
            date: "",
            headersBlock: "",
            sanitizedBody: "",
            attachmentCount: 0
        )
        XCTAssertFalse(result.from.contains("<script"))
        XCTAssertFalse(result.from.contains("\u{200B}"))
        XCTAssertTrue(result.from.contains("bob@example.com"))
        // senderDomain extraction still works on the sanitized address.
        XCTAssertEqual(result.extracted.senderDomain, "example.com")
    }

    func test_classify_messageIdSanitized() {
        let result = MailSanitizer.classify(
            messageId: "<script>x</script>abc\u{200B}def@example.com",
            from: "a@b.example",
            to: "c@d.example",
            subject: "hi",
            date: "",
            headersBlock: "",
            sanitizedBody: "",
            attachmentCount: 0
        )
        XCTAssertFalse(result.messageId.contains("<script"))
        XCTAssertFalse(result.messageId.contains("\u{200B}"))
    }

    func test_classify_referencesArrayItemsSanitized() {
        let headers = """
        References: <abc\u{200B}@example.com> <\u{FEFF}def@example.com>
        """
        let result = MailSanitizer.classify(
            messageId: "x",
            from: "a@b.example",
            to: "c@d.example",
            subject: "hi",
            date: "",
            headersBlock: headers,
            sanitizedBody: "",
            attachmentCount: 0
        )
        XCTAssertEqual(result.references.count, 2)
        for ref in result.references {
            XCTAssertFalse(ref.contains("\u{200B}"))
            XCTAssertFalse(ref.contains("\u{FEFF}"))
        }
    }

    // MARK: - Header parser

    func test_headerParser_unfoldsContinuationLines() {
        let block = """
        Subject: a long
         subject value
        From: alice@example.com
        """
        let p = MailHeaderParser.parse(block)
        XCTAssertEqual(p.first("subject"), "a long subject value")
        XCTAssertEqual(p.first("from"), "alice@example.com")
    }
}
