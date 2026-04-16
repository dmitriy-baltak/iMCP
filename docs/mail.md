# Mail service

The Mail service exposes Apple Mail.app via the iMCP server using
AppleScript (NSAppleScript + NSAppleEventDescriptor). Enable it in the
menu-bar toggle list alongside Calendar, Messages, etc.

## Permissions

On first use, macOS prompts for Automation access so iMCP can control
Mail. Grant it in **System Settings → Privacy & Security → Automation
→ iMCP → Mail**. If the dialog was dismissed, tools will fail with an
error message pointing you back to that panel.

The app ships with `com.apple.mail` listed under
`com.apple.security.temporary-exception.apple-events` in its
entitlements so the sandboxed binary can target Mail. No other
per-user setup is required.

## Tools

### `mail_search`

Search messages by sender, recipient, subject, body text, date range,
mailbox, or account.

```json
{
  "subject": "invoice",
  "start": "2026-01-01",
  "end":   "2026-04-16",
  "account": "Work",
  "limit": 50
}
```

Every filter is optional. Date range, when supplied, is pushed down to
Mail via a `whose` predicate so large mailboxes stay responsive. Body
matches still scan messages individually; restrict with
mailbox/account/date/limit when you can.

Returned fields: `id`, `messageId`, `from`, `recipients`, `subject`,
`date`, `mailbox`, `account`, `snippet`.

### `mail_fetch`

Fetch a single message by Mail.app id or RFC-5322 Message-ID header.

```json
{ "id": "12345" }
```

```json
{ "message_id": "<abc@example.com>", "include_attachments": true }
```

Returns the full headers block, plain-text body, and attachment
metadata (`name`, `size`, `mimeType`). Attachment **bytes are never
inlined**. When `include_attachments` is true, attachments are saved
to a per-call temp directory and the absolute `path` of each saved
file is included alongside its metadata — you can read those paths
with other MCP tools.

### `mail_send`

Compose and send a message using the default outgoing account.

```json
{
  "to": ["alice@example.com"],
  "cc": ["bob@example.com"],
  "subject": "Hello",
  "body": "Just checking in.",
  "attachments": ["/Users/me/Documents/report.pdf"]
}
```

Required: `to`, `subject`, `body`. All user-supplied values (subject,
body, addresses, attachment paths) travel through
`NSAppleEventDescriptor` parameters rather than being interpolated
into AppleScript source, so quotes and other metacharacters are safe.

The `isHTML` flag is accepted for forward compatibility. The current
AppleScript backend sends the body as plain text — HTML markup will
be delivered verbatim, not rendered. If you need real HTML, set it on
the message by hand in Mail.app or wait for a future backend that
uses a different transport.

### `mail_list_mailboxes`

Enumerate accounts and their mailboxes.

```json
{}
```

Returns an array of `{ name, id, mailboxes[] }` records. Useful for
finding the exact `account` or `mailbox` name to pass to
`mail_search`.

## Known limitations

- **Speed.** AppleScript cross-process calls are slow. Body-text
  searches iterate messages one-by-one. For large mailboxes, expect
  seconds-per-mailbox unless you scope the query with
  `mailbox`/`account`/date range. A fast path that reads
  `~/Library/Mail/V*/MailData/Envelope Index` (SQLite) is a planned
  follow-up.
- **HTML send.** `mail_send` sends plain text only; `isHTML` is a
  no-op today.
- **Bcc visibility.** Mail's scripting dictionary does not always
  return Bcc recipients reliably; `mail_fetch` returns what Mail
  exposes.
- **Account ids.** The `id` returned by `mail_list_mailboxes` is
  Mail's internal account id, not a human-facing name; use `name`
  for scoping user-facing queries.
