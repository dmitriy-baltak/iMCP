import XCTest
@testable import MailSanitizer

final class MailSanitizerTests: XCTestCase {

    // MARK: - Fixture loading

    func loadFixture(_ name: String) throws -> String {
        let url = try XCTUnwrap(
            Bundle.module.url(
                forResource: name,
                withExtension: nil,
                subdirectory: "Fixtures"
            ),
            "Missing fixture \(name)"
        )
        return try String(contentsOf: url, encoding: .utf8)
    }

    // MARK: - Documenting the threat model

    func test_ignorePreviousInstructions_isReturnedAsLiteralText() throws {
        // The sanitizer does NOT filter prose — only exfiltration channels.
        // Semantic injection is left for the caller to handle (i.e. by not
        // feeding mail_fetch_sanitized output back into a privileged agent).
        let raw = try loadFixture("ignore_previous_instructions.txt")
        let out = MailSanitizer.sanitizeBody(raw, maxChars: 10_000)
        XCTAssertTrue(out.text.contains("Ignore previous instructions"))
        // But the email-address exfil channel inside the prose IS neutralized.
        XCTAssertFalse(out.text.contains("attacker@evil.example"))
        XCTAssertTrue(out.text.contains("[email: evil.example]"))
    }

    // MARK: - HTML stripping (SwiftSoup)

    func test_swiftsoup_stripsScriptAndStyleWithContents() throws {
        let raw = try loadFixture("nested_html_injection.html")
        let stripped = MailSanitizer.stripHTML(raw)
        XCTAssertFalse(stripped.contains("alert"))
        XCTAssertFalse(stripped.contains("<script"))
        XCTAssertFalse(stripped.contains("<style"))
        XCTAssertFalse(stripped.contains("javascript:"))
        XCTAssertTrue(stripped.contains("hello"))
    }

    func test_swiftsoup_handlesNestedTagInjection() throws {
        // <scr<script>ipt> — naive regex yields "<script>" then leaves
        // alert(1) text. The pre-process regex sees the inner <script>…
        // </script> as a complete block and drops it whole.
        let raw = "before <scr<script>ipt>alert('xss')</script> after"
        let stripped = MailSanitizer.stripHTML(raw)
        XCTAssertFalse(stripped.contains("<script"))
        XCTAssertFalse(stripped.contains("alert"))
    }

    func test_swiftsoup_decodesEntitiesAfterTagStripDoesNotResurrectScript() throws {
        let raw = try loadFixture("entity_encoded_script.html")
        let stripped = MailSanitizer.stripHTML(raw)
        // The first SwiftSoup pass turns &lt;script&gt; into <script>; the
        // second iteration must remove that tag before returning.
        XCTAssertFalse(stripped.contains("<script>"),
                       "got: \(stripped)")
        XCTAssertFalse(stripped.contains("steal()"))
        XCTAssertTrue(stripped.contains("Welcome!"))
        XCTAssertTrue(stripped.contains("All set."))
    }

    func test_deeplyEntityEncoded_scriptTagDoesNotSurvive() {
        // Wrap `<script>steal()</script>` in many layers of `&amp;` encoding.
        // Each iteration of stripHTML unwraps one layer; the iteration cap
        // (25) handles up to 25 levels, and any remainder gets killed by
        // the final defensive tag-strip pass.
        var encoded = "<script>steal()</script>"
        for _ in 0..<20 {
            encoded = encoded
                .replacingOccurrences(of: "&", with: "&amp;")
                .replacingOccurrences(of: "<", with: "&lt;")
                .replacingOccurrences(of: ">", with: "&gt;")
        }
        let stripped = MailSanitizer.stripHTML("Hello \(encoded) world")
        XCTAssertFalse(stripped.contains("<script"),
                       "20-deep entity-encoded script tag survived: \(stripped)")
        XCTAssertFalse(stripped.contains("steal()"),
                       "script body survived: \(stripped)")
    }

    func test_pathologicalEntityEncoded_finalStripCatchesSurvivors() {
        // 60 layers — well beyond the 25-iteration cap. With the cap hit,
        // the defensive aggressivelyDecodeEntities + tag-strip pipeline must
        // still neutralize the markup. Crucially, an attacker's payload must
        // not survive in EITHER literal (`<script>`) OR entity-encoded
        // (`&lt;script&gt;`) form — both are violations of the
        // "HTML stripped" guarantee.
        var encoded = "Hello <script>alert(1)</script> world"
        for _ in 0..<60 {
            encoded = encoded
                .replacingOccurrences(of: "&", with: "&amp;")
                .replacingOccurrences(of: "<", with: "&lt;")
                .replacingOccurrences(of: ">", with: "&gt;")
        }
        let stripped = MailSanitizer.stripHTML(encoded)
        XCTAssertFalse(stripped.contains("<script"), "literal tag: \(stripped)")
        XCTAssertFalse(stripped.contains("</script"), "literal tag: \(stripped)")
        XCTAssertFalse(stripped.contains("&lt;script"), "encoded tag: \(stripped)")
        XCTAssertFalse(stripped.contains("&amp;"), "entity layers remain: \(stripped)")
        XCTAssertFalse(stripped.contains("alert(1)"), "script body survived: \(stripped)")
        // Surrounding text is preserved.
        XCTAssertTrue(stripped.contains("Hello"))
        XCTAssertTrue(stripped.contains("world"))
    }

    func test_entityOnlyPayload_noLiteralAngleBracket_isStillNeutralized() {
        // Auditor's scenario: input has NO literal `<` (everything is entity-
        // encoded), so the old `current.contains("<")` guard skipped the
        // defensive pass even though the encoded markup violated the strip
        // guarantee. This test pins the new behavior: containsMarkupOrEntity
        // sees the `&...;` pattern and triggers the decode + strip.
        let raw = "Hello &amp;amp;amp;lt;script&amp;amp;amp;gt;steal()&amp;amp;amp;lt;/script&amp;amp;amp;gt; world"
        let stripped = MailSanitizer.stripHTML(raw)
        XCTAssertFalse(stripped.contains("<script"), "got: \(stripped)")
        XCTAssertFalse(stripped.contains("&lt;script"), "got: \(stripped)")
        XCTAssertFalse(stripped.contains("steal()"), "got: \(stripped)")
        XCTAssertTrue(stripped.contains("Hello"))
        XCTAssertTrue(stripped.contains("world"))
    }

    func test_legitimateAmpersandInText_isNotMistakenForEntity() {
        // Bare `&` (no trailing `entity;`) must not trigger the defensive
        // decode pass, and must survive the strip pipeline intact.
        let raw = "Tom & Jerry are friends."
        let stripped = MailSanitizer.stripHTML(raw)
        XCTAssertTrue(stripped.contains("Tom & Jerry"), "got: \(stripped)")
    }

    func test_legitimateEntityInText_isDecodedSafely() {
        // `&amp;` is a valid entity used in legitimate text. After stripping,
        // it should be human-readable `&` with no security concern.
        let raw = "Tom &amp; Jerry &lt; the others"
        let stripped = MailSanitizer.stripHTML(raw)
        // Either decoded (preferred for readability) or left encoded — both
        // are safe. Just assert no script-like markup snuck through.
        XCTAssertFalse(stripped.contains("<script"))
    }

    func test_stripHTML_preservesBareAngleBracketsInTextLikeMath() {
        // After stripping real HTML, bare `<` / `>` used as math operators
        // must survive — they're not tag-shaped.
        let raw = "Compare: x < 5 && y > 10. Done."
        let stripped = MailSanitizer.stripHTML(raw)
        // SwiftSoup treats `< 5 ` as text since it's not followed by a tag
        // name char; the conservative final strip only removes `<word>`.
        XCTAssertTrue(stripped.contains("x < 5") || stripped.contains("x <5"),
                      "bare math < should survive: \(stripped)")
    }

    func test_stripHTML_passthroughForPlainText() {
        let raw = "Hello there, plain text only."
        XCTAssertEqual(MailSanitizer.stripHTML(raw), raw)
    }

    // MARK: - Zero-width chars

    func test_zeroWidthChars_areStripped() throws {
        let raw = try loadFixture("zero_width_steg.txt")
        let stripped = MailSanitizer.stripZeroWidth(raw)
        XCTAssertEqual(stripped.trimmingCharacters(in: .newlines), "Hello World")
    }

    func test_stripZeroWidth_leavesNormalCharsAlone() {
        let raw = "Hello\nWorld\t!"
        XCTAssertEqual(MailSanitizer.stripZeroWidth(raw), raw)
    }

    // MARK: - URL neutralization

    func test_httpsUrl_neutralizedToBracketLinkHost() {
        let raw = "Visit https://shop.example.com/item/42 today!"
        let (out, did) = MailSanitizer.neutralizeURLs(raw)
        XCTAssertTrue(did)
        XCTAssertEqual(out, "Visit [link: example.com] today!")
    }

    func test_trackingSubdomain_collapsesToRegistrableDomain() {
        let raw = "Click https://track.evilmarketer.example/r/?u=42"
        let (out, _) = MailSanitizer.neutralizeURLs(raw)
        XCTAssertEqual(out, "Click [link: evilmarketer.example]")
    }

    func test_mailtoUrl_neutralizedToBracketEmailDomain() {
        let raw = "Email mailto:bob@example.com please"
        let (out, _) = MailSanitizer.neutralizeURLs(raw)
        XCTAssertTrue(out.contains("[email: example.com]"), "got: \(out)")
    }

    func test_bareEmailAddress_isNeutralized() {
        // NSDataDetector flags bare emails as links too.
        let raw = "Contact me at attacker@evil.example."
        let (out, _) = MailSanitizer.neutralizeURLs(raw)
        XCTAssertTrue(out.contains("[email: evil.example]"))
        XCTAssertFalse(out.contains("attacker@evil.example"))
    }

    func test_noUrl_returnsFalseFlag() {
        let raw = "no links here, just text"
        let (out, did) = MailSanitizer.neutralizeURLs(raw)
        XCTAssertFalse(did)
        XCTAssertEqual(out, raw)
    }

    // MARK: - Length cap

    func test_longBody_isCappedAndMarkedTruncated_canaryAtTailIsAbsent() {
        let body = String(repeating: "lorem ipsum ", count: 5_000) + "CANARY-TAIL"
        let out = MailSanitizer.sanitizeBody(body, maxChars: 1000)
        XCTAssertTrue(out.truncated)
        XCTAssertFalse(out.text.contains("CANARY-TAIL"))
        XCTAssertTrue(out.text.contains("[truncated:"))
    }

    func test_shortBody_isNotTruncated() {
        let body = "small body"
        let out = MailSanitizer.sanitizeBody(body, maxChars: 1000)
        XCTAssertFalse(out.truncated)
        XCTAssertEqual(out.text, "small body")
    }

    func test_maxChars_clampedToValidRange() {
        XCTAssertEqual(MailSanitizer.clampMaxChars(0), MailSanitizer.minMaxChars)
        XCTAssertEqual(MailSanitizer.clampMaxChars(100), MailSanitizer.minMaxChars)
        XCTAssertEqual(MailSanitizer.clampMaxChars(10_000), 10_000)
        XCTAssertEqual(MailSanitizer.clampMaxChars(999_999), MailSanitizer.maxMaxChars)
    }

    // MARK: - End-to-end pipeline

    func test_endToEnd_otpEmail_redactsCode() throws {
        let raw = try loadFixture("otp_email.txt")
        let out = MailSanitizer.sanitizeBody(raw, maxChars: 10_000)
        XCTAssertFalse(out.text.contains("482915"))
        XCTAssertTrue(out.text.contains("[redacted: otp]"))
        XCTAssertTrue(out.redactionsApplied.contains("otp"))
    }

    func test_endToEnd_magicLinkReset_neutralizesLinkAndKeepsContextWords() throws {
        let raw = try loadFixture("magic_link_reset.txt")
        let out = MailSanitizer.sanitizeBody(raw, maxChars: 10_000)
        XCTAssertFalse(out.text.contains("https://"))
        XCTAssertTrue(out.text.contains("[link: example.com]"))
        XCTAssertTrue(out.text.contains("reset your password"))
    }

    // MARK: - Envelope-field sanitizers

    func test_sanitizeSubject_stripsHtmlAndRedactsOtp() {
        let raw = "<b>Your verification code: 482915</b>"
        let out = MailSanitizer.sanitizeSubject(raw)
        XCTAssertFalse(out.contains("<"))
        XCTAssertFalse(out.contains("482915"))
        XCTAssertTrue(out.contains("[redacted: otp]"))
    }

    func test_sanitizeSubject_neutralizesUrl() {
        let raw = "Check https://shop.example.com/sale for 50% off"
        let out = MailSanitizer.sanitizeSubject(raw)
        XCTAssertFalse(out.contains("https://"))
        XCTAssertTrue(out.contains("[link: example.com]"))
    }

    func test_sanitizeSubject_capsAt500() {
        let raw = String(repeating: "x", count: 2000)
        let out = MailSanitizer.sanitizeSubject(raw)
        XCTAssertLessThanOrEqual(out.count, 600)  // 500 + truncation marker
    }

    func test_sanitizeAddressField_stripsHtmlAndZeroWidth_keepsAddress() {
        let raw = "<script>x</script>Bob \u{200B}Smith <bob@example.com>"
        let out = MailSanitizer.sanitizeAddressField(raw)
        XCTAssertFalse(out.contains("<script"))
        XCTAssertFalse(out.contains("\u{200B}"))
        XCTAssertTrue(out.contains("bob@example.com"),
                      "address must survive: \(out)")
    }

    func test_sanitizeAddressField_keepsLiteralAddressNoUrlNeutralization() {
        // Unlike the body pipeline, address fields must NOT be URL-neutralized
        // — otherwise "bob@example.com" becomes "[email: example.com]" and the
        // orchestrator loses the literal address it needs for routing.
        let raw = "alice@example.com, bob@example.com"
        let out = MailSanitizer.sanitizeAddressField(raw)
        XCTAssertTrue(out.contains("alice@example.com"))
        XCTAssertTrue(out.contains("bob@example.com"))
    }

    func test_sanitizeAddressField_lengthCapped() {
        let raw = String(repeating: "a", count: 5000) + "@example.com"
        let out = MailSanitizer.sanitizeAddressField(raw)
        XCTAssertLessThanOrEqual(out.count, MailSanitizer.addressFieldMaxChars)
    }

    func test_sanitizeShortHeader_stripsHtmlZeroWidthAndControl() {
        let raw = "<m>abc\u{200B}d\refgh@example.com</m>"
        let out = MailSanitizer.sanitizeShortHeader(raw)
        XCTAssertFalse(out.contains("<"))
        XCTAssertFalse(out.contains("\u{200B}"))
        XCTAssertFalse(out.contains("\r"))
        XCTAssertTrue(out.contains("abcd"), "got: \(out)")
    }

    func test_sanitizeShortHeader_lengthCapped() {
        let raw = String(repeating: "a", count: 2000)
        let out = MailSanitizer.sanitizeShortHeader(raw)
        XCTAssertLessThanOrEqual(out.count, MailSanitizer.shortHeaderMaxChars)
    }

    func test_sanitizeShortHeader_emptyInputReturnsEmpty() {
        XCTAssertEqual(MailSanitizer.sanitizeShortHeader(""), "")
    }

    func test_endToEnd_trackingUrls_stripsHtmlAndDropsHrefs() throws {
        let raw = try loadFixture("tracking_urls.html")
        let out = MailSanitizer.sanitizeBody(raw, maxChars: 10_000)
        // Visible link text survives.
        XCTAssertTrue(out.text.contains("Click here"))
        XCTAssertTrue(out.text.contains("Unsubscribe"))
        // No HTML, no bare URLs, no tracker domain — hrefs and img srcs
        // never reach the model.
        XCTAssertFalse(out.text.contains("<"))
        XCTAssertFalse(out.text.contains("https://"))
        XCTAssertFalse(out.text.contains("track.evilmarketer.example"))
        XCTAssertFalse(out.text.contains("unsubscribe@target.example"))
    }
}
