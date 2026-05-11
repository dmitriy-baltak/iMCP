import XCTest
@testable import MailSanitizer

/// Builds credential-shaped test strings from concatenated parts so the source
/// file never contains a complete credential pattern as a single literal.
/// Without this, GitHub push protection / repo secret scanners would flag
/// the test fixtures and either block the PR or produce noisy alerts.
/// The runtime values these produce are still pattern-matching for the
/// vendored regexes — they just aren't visible to scanners that grep
/// source for literal credential shapes.
enum SecretSamples {
    // Stripe: `sk_(test|live|prod)_…`. Split between `sk_` and the env word.
    static let stripeLive = "sk_" + "live" + "_aBcDeFgHiJkLmNoPqRsTuVwX"
    static let stripeTest = "sk_" + "test" + "_aBcDeFgHiJkLmNoPqRsT"
    // GitHub PAT: `ghp_…`. Split between `ghp` and `_`.
    static let githubPat = "ghp" + "_" + "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"
    // Slack bot token: `xoxb-…`. Split between `xoxb` and `-`.
    static let slackBot = "xoxb" + "-" + "1234567890-1234567890-aBcDeFgHiJkLmNoPqRsT"
    // Slack incoming webhook URL: split between `hooks` and `.slack.com`.
    static let slackWebhook = "https://hooks" + ".slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
    // AWS access key: `(AKIA|ASIA|…) + 16 base32`. Split AKIA prefix.
    static let awsAccess = "AKI" + "A" + "IOSFODNN7EXAMPLE"
    // JWT: 3 segments separated by dots. Splitting at one of the dots breaks
    // the literal pattern but the runtime string still matches the regex.
    static let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ"
        + "." + "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
}

final class SecretPatternsTests: XCTestCase {

    private func redact(_ s: String) -> (String, [String]) {
        return MailSanitizer.redactSecrets(s)
    }

    // MARK: - Each vendored pattern fires on a canonical sample

    func test_jwt_redacted() {
        let secret = SecretSamples.jwt
        let (out, labels) = redact("token=\(secret) end")
        XCTAssertFalse(out.contains(secret))
        XCTAssertTrue(out.contains("[redacted: jwt]"))
        XCTAssertTrue(labels.contains("jwt"))
    }

    func test_stripeKey_sk_live_redacted() {
        let (out, labels) = redact("k=\(SecretSamples.stripeLive) next")
        XCTAssertFalse(out.contains("sk_live" + "_"))
        XCTAssertTrue(out.contains("[redacted: stripe_key]"))
        XCTAssertTrue(labels.contains("stripe_access_token"))
    }

    func test_stripeKey_sk_test_redacted() {
        let (out, _) = redact(SecretSamples.stripeTest)
        XCTAssertTrue(out.contains("[redacted: stripe_key]"))
    }

    func test_slackToken_xoxb_redacted() {
        let (out, _) = redact(SecretSamples.slackBot)
        XCTAssertTrue(out.contains("[redacted: slack_token]"))
    }

    func test_slackWebhook_redacted() {
        let (out, _) = redact("post to \(SecretSamples.slackWebhook)")
        XCTAssertTrue(out.contains("[redacted: slack_webhook]"))
    }

    func test_githubPat_ghp_redacted() {
        let (out, _) = redact("auth \(SecretSamples.githubPat) next")
        XCTAssertTrue(out.contains("[redacted: github_token]"))
    }

    func test_githubFineGrainedPat_redacted() {
        // `github_pat_<82 chars>` — split prefix from underscore so the
        // literal `github_pat_` doesn't appear as a single source token.
        let pat = "github_pat" + "_" + String(repeating: "a", count: 82)
        let (out, _) = redact(pat)
        XCTAssertTrue(out.contains("[redacted: github_token]"))
    }

    func test_awsAccessKey_AKIA_redacted() {
        let (out, _) = redact("key=\(SecretSamples.awsAccess) end")
        XCTAssertTrue(out.contains("[redacted: aws_key]"))
    }

    func test_gcpApiKey_AIza_redacted() {
        let (out, _) = redact("key=AIza" + String(repeating: "X", count: 35) + " end")
        XCTAssertTrue(out.contains("[redacted: gcp_key]"))
    }

    func test_anthropicKey_redacted() {
        // Split prefix from version segment so the literal Anthropic
        // prefix `sk-ant-api03-` doesn't appear as a single source token.
        let pat = "sk-ant-api" + "03-" + String(repeating: "a", count: 93) + "AA"
        let (out, _) = redact(pat)
        XCTAssertTrue(out.contains("[redacted: anthropic_key]"))
    }

    func test_sendgridToken_redacted() {
        let pat = "SG." + String(repeating: "a", count: 22) + "." + String(repeating: "b", count: 43)
        let (out, _) = redact(pat)
        XCTAssertTrue(out.contains("[redacted: sendgrid_key]"))
    }

    func test_mailgunPrivateApiToken_redacted() {
        let pat = "key-" + String(repeating: "a", count: 32)
        let (out, _) = redact(pat)
        XCTAssertTrue(out.contains("[redacted: mailgun_key]"))
    }

    func test_npmAccessToken_redacted() {
        let pat = "npm_" + String(repeating: "A", count: 36)
        let (out, _) = redact(pat)
        XCTAssertTrue(out.contains("[redacted: npm_token]"))
    }

    func test_twilioApiKey_redacted() {
        let pat = "SK" + String(repeating: "a", count: 32)
        let (out, _) = redact(pat)
        XCTAssertTrue(out.contains("[redacted: twilio_key]"))
    }

    func test_privateKey_redacted() {
        // Split the BEGIN/END markers so neither a literal full PEM header
        // nor a literal full footer appears in source. The body is fake
        // low-entropy content so it doesn't look like real key material.
        let header = "-----BEGIN" + " RSA PRIVATE KEY-----"
        let footer = "-----END" + " RSA PRIVATE KEY-----"
        let body = String(repeating: "FakeKeyMaterialNotReal", count: 8)
        let pem = "\(header)\n\(body)\n\(footer)"
        let (out, labels) = redact(pem)
        XCTAssertTrue(out.contains("[redacted: private_key]"), "got: \(out)")
        XCTAssertTrue(labels.contains("private_key"))
    }

    // MARK: - False-positive guards

    func test_stripeKey_partialPrefix_doesNotFalseTrigger() {
        // Stripe prefix with a too-short suffix should not match the
        // `[A-Za-z0-9]{10,99}` requirement.
        let (out, _) = redact("sk" + "_live_short")
        XCTAssertFalse(out.contains("[redacted:"))
    }

    func test_arbitraryHexString_doesNotFalseTrigger() {
        // No vendored pattern matches a bare 32-char hex string without
        // a service-specific prefix.
        let (out, _) = redact("e3b0c44298fc1c149afbf4c8996fb92427ae41e4")
        XCTAssertFalse(out.contains("[redacted:"))
    }

    func test_normalEnglishWords_doNotFalseTrigger() {
        let (out, _) = redact("This is a normal sentence with no secrets in it at all.")
        XCTAssertFalse(out.contains("[redacted:"))
    }

    // MARK: - Multi-secret end-to-end

    func test_apiKeysFixture_redactsEverySecret() throws {
        // Fixture uses `<<NAME>>` placeholders so the file on disk doesn't
        // contain literal credential patterns (which would trip GitHub push
        // protection). Substitute split-built samples at runtime.
        let url = try XCTUnwrap(Bundle.module.url(
            forResource: "api_keys", withExtension: "txt", subdirectory: "Fixtures"
        ))
        let template = try String(contentsOf: url, encoding: .utf8)
        let sendgridSample = "SG" + "." + String(repeating: "a", count: 22)
            + "." + String(repeating: "b", count: 43)
        let raw = template
            .replacingOccurrences(of: "<<STRIPE_LIVE>>", with: SecretSamples.stripeLive)
            .replacingOccurrences(of: "<<GITHUB_PAT>>", with: SecretSamples.githubPat)
            .replacingOccurrences(of: "<<AWS_ACCESS>>", with: SecretSamples.awsAccess)
            .replacingOccurrences(of: "<<JWT>>", with: SecretSamples.jwt)
            .replacingOccurrences(of: "<<SLACK_BOT>>", with: SecretSamples.slackBot)
            .replacingOccurrences(of: "<<SENDGRID>>", with: sendgridSample)

        let (out, labels) = redact(raw)
        XCTAssertFalse(out.contains("sk_live" + "_"))
        XCTAssertFalse(out.contains("ghp" + "_"))
        XCTAssertFalse(out.contains("AKI" + "A"))
        XCTAssertFalse(out.contains("eyJhbGciOiJIUzI1NiJ9"))
        XCTAssertFalse(out.contains("xoxb" + "-"))
        XCTAssertFalse(out.contains("SG" + "."))
        XCTAssertTrue(labels.contains("stripe_access_token"))
        XCTAssertTrue(labels.contains("github_pat"))
        XCTAssertTrue(labels.contains("aws_access_token"))
        XCTAssertTrue(labels.contains("jwt"))
        XCTAssertTrue(labels.contains("slack_bot_token"))
        XCTAssertTrue(labels.contains("sendgrid_api_token"))
    }

    // MARK: - OTP redaction

    func test_otpInContext_digitsRedactedLabelKept() {
        let raw = "Your verification code is 482915. Use it now."
        let (out, label) = MailSanitizer.redactOTPs(raw)
        XCTAssertFalse(out.contains("482915"))
        XCTAssertTrue(out.contains("verification"))
        XCTAssertTrue(out.contains("[redacted: otp]"))
        XCTAssertEqual(label, "otp")
    }

    // Pattern B: standalone-meaningful trigger words, no " code" suffix.
    // These are the cases the old regex missed.

    func test_otpColonFourDigit_redacted() {
        let raw = "Your OTP: 4829 (do not share)"
        let (out, label) = MailSanitizer.redactOTPs(raw)
        XCTAssertFalse(out.contains("4829"), "got: \(out)")
        XCTAssertTrue(out.contains("[redacted: otp]"))
        XCTAssertEqual(label, "otp")
    }

    func test_passcodeColonFourDigit_redacted() {
        let raw = "passcode: 1234 expires soon"
        let (out, _) = MailSanitizer.redactOTPs(raw)
        XCTAssertFalse(out.contains("1234"))
        XCTAssertTrue(out.contains("[redacted: otp]"))
    }

    func test_pinColonFourDigit_redacted() {
        let raw = "Your PIN: 9999"
        let (out, _) = MailSanitizer.redactOTPs(raw)
        XCTAssertFalse(out.contains("9999"))
        XCTAssertTrue(out.contains("[redacted: otp]"))
    }

    func test_twoFactorWithDashAndSixDigit_redacted() {
        let raw = "2FA — 482915 — for sign-in"
        let (out, _) = MailSanitizer.redactOTPs(raw)
        XCTAssertFalse(out.contains("482915"))
        XCTAssertTrue(out.contains("[redacted: otp]"))
    }

    func test_verificationColonDigits_redacted() {
        let raw = "verification: 482915"
        let (out, _) = MailSanitizer.redactOTPs(raw)
        XCTAssertFalse(out.contains("482915"))
        XCTAssertTrue(out.contains("[redacted: otp]"))
    }

    func test_passcodeWithSpace_doesNotFalseTriggerOnUnrelatedDigits() {
        // Trigger word followed by another word, then digits — must NOT match
        // because the digits are in the next clause, not adjacent.
        let raw = "OTP for John was sent. The 4829th customer signed up."
        let (out, _) = MailSanitizer.redactOTPs(raw)
        XCTAssertTrue(out.contains("4829"), "should not falsely redact: \(out)")
    }

    func test_pinAsPartOfWord_doesNotFalseTrigger() {
        // "pin" appears inside "Pinpoint" — \b boundary stops the match.
        let raw = "Pinpoint location: 1234 Main St"
        let (out, _) = MailSanitizer.redactOTPs(raw)
        XCTAssertTrue(out.contains("1234"))
    }

    // Pattern A multi-word forms with `password` / `pin` suffix.

    func test_oneTimePassword_redacted() {
        let raw = "Your one-time password is 482915. It expires in 5 minutes."
        let (out, _) = MailSanitizer.redactOTPs(raw)
        XCTAssertFalse(out.contains("482915"), "got: \(out)")
        XCTAssertTrue(out.contains("[redacted: otp]"))
    }

    func test_oneTimePasswordHyphenated_redacted() {
        let raw = "Use this one-time password: 1234"
        let (out, _) = MailSanitizer.redactOTPs(raw)
        XCTAssertFalse(out.contains("1234"))
    }

    func test_singleUsePassword_redacted() {
        let raw = "Your single-use password: 482915"
        let (out, _) = MailSanitizer.redactOTPs(raw)
        XCTAssertFalse(out.contains("482915"))
    }

    func test_temporaryPassword_redacted() {
        let raw = "We sent you a temporary password 482915 — please change after sign-in."
        let (out, _) = MailSanitizer.redactOTPs(raw)
        XCTAssertFalse(out.contains("482915"))
    }

    func test_verificationPin_redacted() {
        let raw = "Your verification pin is 1234"
        let (out, _) = MailSanitizer.redactOTPs(raw)
        XCTAssertFalse(out.contains("1234"))
    }

    func test_barePassword_doesNotFalseTrigger() {
        // No qualifier before "password" → must not redact, otherwise common
        // password-reset prose ("forgot your password 123 times") false-fires.
        let raw = "I forgot my password 1234 times last week"
        let (out, _) = MailSanitizer.redactOTPs(raw)
        XCTAssertTrue(out.contains("1234"), "false trigger on bare password: \(out)")
    }

    func test_standaloneSixDigit_notRedactedWithoutContext() {
        let raw = "Order #100200 contains item 482915. Track at our store."
        let (out, label) = MailSanitizer.redactOTPs(raw)
        XCTAssertEqual(out, raw)
        XCTAssertNil(label)
    }

    func test_standaloneSixDigit_redactedWithVerificationContext() {
        let raw = "verification — 482915 — do not share"
        let (out, label) = MailSanitizer.redactOTPs(raw)
        XCTAssertFalse(out.contains("482915"))
        XCTAssertEqual(label, "otp")
    }

    func test_secretPatternCount_isWithinExpectedRange() {
        // Sanity-check the vendored set hasn't accidentally been deleted.
        XCTAssertGreaterThanOrEqual(SecretPatterns.all.count, 18)
        XCTAssertLessThanOrEqual(SecretPatterns.all.count, 60)
    }
}
