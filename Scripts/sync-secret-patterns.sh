#!/usr/bin/env bash
#
# Refresh helper for App/Services/MailSanitizer+SecretPatterns.swift.
#
# We vendor a curated subset of gitleaks's regex rules (the unique-prefix
# credential patterns: AKIA…, ghp_…, sk-…, xoxb-…, etc.). This script does
# NOT regenerate the Swift file automatically — the curation step requires
# human judgement. Instead it fetches upstream, records the commit SHA, and
# diffs the rule set so you can tell at a glance what changed.
#
# Run quarterly. If meaningful new rules appeared upstream, manually port
# them and update the SHA in MailSanitizer+SecretPatterns.swift's header.

set -euo pipefail

UPSTREAM_REPO="gitleaks/gitleaks"
UPSTREAM_FILE="config/gitleaks.toml"
CACHE_DIR="${TMPDIR:-/tmp}/imcp-mail-sanitizer-sync"
mkdir -p "$CACHE_DIR"

echo "Fetching latest upstream commit for $UPSTREAM_REPO …"
LATEST_SHA=$(
    curl -fsSL "https://api.github.com/repos/$UPSTREAM_REPO/commits/master" \
        | python3 -c 'import json,sys; print(json.load(sys.stdin)["sha"])'
)
echo "  upstream master @ $LATEST_SHA"

echo "Fetching $UPSTREAM_FILE …"
curl -fsSL \
    "https://raw.githubusercontent.com/$UPSTREAM_REPO/$LATEST_SHA/$UPSTREAM_FILE" \
    -o "$CACHE_DIR/gitleaks.toml"

echo "Extracting rule ids …"
grep -E '^id = "' "$CACHE_DIR/gitleaks.toml" | sort -u > "$CACHE_DIR/upstream-rules.txt"

VENDORED_RULES_FILE="$(dirname "$0")/../App/Services/MailSanitizer+SecretPatterns.swift"
# Each `make()` invocation in the vendored file is multi-line, with the label
# string on its own indented line: `            "aws_access_token",`.
# Match those (lowercase snake_case, trailing comma) — pattern strings start
# with `#"` and replacement strings contain `[redacted: ...]`, so neither
# matches this regex. Normalize underscores back to hyphens so labels line up
# with upstream gitleaks rule ids (which use `aws-access-token` style).
grep -E '^[[:space:]]+"[a-z0-9_]+",[[:space:]]*$' "$VENDORED_RULES_FILE" \
    | sed -E 's/^[[:space:]]+"([a-z0-9_]+)".*/\1/' \
    | tr '_' '-' \
    | sed -E 's/^/id = "/; s/$/"/' \
    | sort -u > "$CACHE_DIR/vendored-rules.txt"

echo
echo "===== rules upstream but NOT vendored ====="
comm -23 "$CACHE_DIR/upstream-rules.txt" "$CACHE_DIR/vendored-rules.txt" || true
echo
echo "===== rules vendored but no longer upstream ====="
comm -13 "$CACHE_DIR/upstream-rules.txt" "$CACHE_DIR/vendored-rules.txt" || true
echo
echo "Upstream toml cached at: $CACHE_DIR/gitleaks.toml"
echo "Update header SHA in MailSanitizer+SecretPatterns.swift to: $LATEST_SHA"
