// Vendored secret-detection regexes used by MailSanitizer.redactSecrets().
//
// Source:    https://github.com/gitleaks/gitleaks
// File:      config/gitleaks.toml
// Upstream:  8863af47d64c3681422523e36837957c74d4af4b (sync 2026-05-11)
// License:   MIT (https://github.com/gitleaks/gitleaks/blob/master/LICENSE)
// Refresh:   Scripts/sync-secret-patterns.sh
//
// We keep only the unique-prefix patterns from gitleaks (AKIA…, ghp_…,
// sk-…, xoxb-…, etc.) — i.e. patterns that match the credential by its
// own structure rather than by a nearby keyword like "stripe = …".
// Generic context-keyword patterns from gitleaks (adobe, asana, …) don't
// translate well to free-form email bodies and are intentionally omitted.
//
// Each pattern's trailing context check
//   (?:[\x60'"\s;]|\\[nr]|$)
// from gitleaks is replaced with `\b`, which is the right anchor for
// natural-language email bodies (gitleaks scans source-code diffs).
import Foundation

struct SecretPattern {
    let label: String           // gitleaks rule id, for telemetry
    let regex: NSRegularExpression
    let replacement: String     // user-visible redaction marker
}

enum SecretPatterns {

    static let all: [SecretPattern] = [
        // AWS — A3T…/AKIA/ASIA/ABIA/ACCA + 16 base32 chars.
        make(
            "aws_access_token",
            #"\b(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}\b"#,
            "[redacted: aws_key]"
        ),
        // GCP — AIza + 35 [\w-].
        make(
            "gcp_api_key",
            #"\bAIza[A-Za-z0-9_\-]{35}\b"#,
            "[redacted: gcp_key]"
        ),
        // GitHub PAT (classic).
        make(
            "github_pat",
            #"\bghp_[0-9A-Za-z]{36}\b"#,
            "[redacted: github_token]"
        ),
        // GitHub fine-grained PAT.
        make(
            "github_fine_grained_pat",
            #"\bgithub_pat_[A-Za-z0-9_]{82}\b"#,
            "[redacted: github_token]"
        ),
        // GitHub OAuth.
        make(
            "github_oauth",
            #"\bgho_[0-9A-Za-z]{36}\b"#,
            "[redacted: github_token]"
        ),
        // GitHub App tokens (user / server).
        make(
            "github_app_token",
            #"\b(?:ghu|ghs)_[0-9A-Za-z]{36}\b"#,
            "[redacted: github_token]"
        ),
        // GitLab PAT.
        make(
            "gitlab_pat",
            #"\bglpat-[A-Za-z0-9_\-]{20}\b"#,
            "[redacted: gitlab_token]"
        ),
        // Stripe — sk_/rk_ × test/live/prod.
        make(
            "stripe_access_token",
            #"\b(?:sk|rk)_(?:test|live|prod)_[A-Za-z0-9]{10,99}\b"#,
            "[redacted: stripe_key]"
        ),
        // Slack bot token — xoxb-…
        make(
            "slack_bot_token",
            #"xoxb-[0-9]{10,13}-[0-9]{10,13}[A-Za-z0-9\-]*"#,
            "[redacted: slack_token]"
        ),
        // Slack user / extension tokens — xoxp-… / xoxe-…
        make(
            "slack_user_token",
            #"xox[pe](?:-[0-9]{10,13}){3}-[A-Za-z0-9\-]{28,34}"#,
            "[redacted: slack_token]"
        ),
        // Slack app-level token — xapp-…
        make(
            "slack_app_token",
            #"(?i)xapp-\d-[A-Z0-9]+-\d+-[a-z0-9]+"#,
            "[redacted: slack_token]"
        ),
        // Slack incoming-webhook URL.
        make(
            "slack_webhook_url",
            #"(?:https?://)?hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9+/]{43,56}"#,
            "[redacted: slack_webhook]"
        ),
        // SendGrid — SG.<22>.<43>
        make(
            "sendgrid_api_token",
            #"(?i)\bSG\.[A-Z0-9=_\-\.]{66}\b"#,
            "[redacted: sendgrid_key]"
        ),
        // Mailgun private API token — key-<32 hex>
        make(
            "mailgun_private_api_token",
            #"\bkey-[a-f0-9]{32}\b"#,
            "[redacted: mailgun_key]"
        ),
        // OpenAI — modern (sk-proj-/svcacct-/admin-) and legacy (sk-…T3BlbkFJ…).
        make(
            "openai_api_key",
            #"\bsk-(?:proj|svcacct|admin)-(?:[A-Za-z0-9_\-]{74}|[A-Za-z0-9_\-]{58})T3BlbkFJ(?:[A-Za-z0-9_\-]{74}|[A-Za-z0-9_\-]{58})\b|\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b"#,
            "[redacted: openai_key]"
        ),
        // Anthropic — sk-ant-api03-…
        make(
            "anthropic_api_key",
            #"\bsk-ant-api03-[A-Za-z0-9_\-]{93}AA\b"#,
            "[redacted: anthropic_key]"
        ),
        // Anthropic admin variant.
        make(
            "anthropic_admin_api_key",
            #"\bsk-ant-admin01-[A-Za-z0-9_\-]{93}AA\b"#,
            "[redacted: anthropic_key]"
        ),
        // npm access token.
        make(
            "npm_access_token",
            #"(?i)\bnpm_[A-Z0-9]{36}\b"#,
            "[redacted: npm_token]"
        ),
        // Twilio API key SID.
        make(
            "twilio_api_key",
            #"\bSK[0-9a-fA-F]{32}\b"#,
            "[redacted: twilio_key]"
        ),
        // 1Password service-account token. Label matches upstream gitleaks
        // rule id `1password-service-account-token` so the sync script's diff
        // stays clean.
        make(
            "1password_service_account_token",
            #"\bops_eyJ[A-Za-z0-9+/]{250,}={0,3}"#,
            "[redacted: onepassword_token]"
        ),
        // JWT — three base64url segments separated by dots, leading "ey".
        make(
            "jwt",
            #"\bey[A-Za-z0-9]{17,}\.ey[A-Za-z0-9/\\_\-]{17,}\.[A-Za-z0-9/\\_\-]{10,}={0,2}\b"#,
            "[redacted: jwt]"
        ),
        // PEM private key block.
        make(
            "private_key",
            #"(?i)-----BEGIN[ A-Z0-9_\-]{0,100}PRIVATE KEY(?: BLOCK)?-----[\s\S]{64,}?KEY(?: BLOCK)?-----"#,
            "[redacted: private_key]"
        ),
    ]

    private static func make(
        _ label: String,
        _ pattern: String,
        _ replacement: String
    ) -> SecretPattern {
        let regex = try! NSRegularExpression(pattern: pattern, options: [])
        return SecretPattern(label: label, regex: regex, replacement: replacement)
    }
}
