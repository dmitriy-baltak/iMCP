# Mail service

The Mail service exposes Apple Mail.app via the iMCP server using
AppleScript (NSAppleScript + NSAppleEventDescriptor). Enable it in the
menu-bar toggle list alongside Calendar, Messages, etc.

## Permissions

On first use, macOS prompts for Automation access so iMCP can control
Mail. Grant it in **System Settings → Privacy & Security → Automation
→ iMCP-MY → Mail**. If the dialog was dismissed, tools will fail with an
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

Every filter is optional. By default the `body` filter matches the
cached snippet; pass `full_body_match: true` to scan each candidate's
full body via AppleScript (much slower — seconds-per-mailbox). When
`full_body_match` is set, at least one narrowing filter
(`sender`/`recipient`/`subject`/`mailbox`/`account`/`start`/`end`) is
required.

`unread_only` and `flagged_only` filter server-side when the envelope
index exposes those columns; otherwise the call errors with a
descriptive message.

Returned fields: `id`, `messageId`, `from`, `recipients`, `subject`,
`date`, `mailbox`, `account`, `snippet`, plus `read` and `flagged`
(when the envelope index exposes those columns).

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
with other MCP tools. Response also includes `read` and `flagged` when
the envelope index exposes those columns.

### `mail_attachments_fetch`

Fetch attachment bytes + metadata without loading the message body.
Useful when you want to process attachments without paying for the
body read.

```json
{ "id": "12345", "output_dir": "/Users/me/Downloads/mail-atts" }
```

Omit `output_dir` to let the service create a per-call temp directory.
Returns `messageId` and an `attachments` array where each entry
contains `name`, `size`, `mimeType`, and the absolute saved `path`.

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

### `mail_threads`

Return every message in the same conversation as the source message,
newest-first. Drafts and trashed messages are excluded.

```json
{ "id": "12345", "limit": 50 }
```

Results have the same shape as `mail_search`. When Mail's envelope
index exposes a `conversation_id` column (modern macOS), the service
uses it for a fast lookup. On older versions (or when the source
message has no conversation id), a header walk over `References:` and
`In-Reply-To:` reconstructs the thread at best-effort cost.

### `mail_reply`

Reply to a message using Mail's built-in `reply` AppleScript command,
so threading headers and the `Re:` subject prefix are set correctly.

```json
{
  "id": "12345",
  "body": "Sounds good — see you Monday.",
  "reply_all": false,
  "send": true
}
```

`body` is required. `reply_all` replies to all recipients of the
source message. `additional_cc` / `additional_bcc` add recipients on
top of whatever Mail prefilled. `attachments` attaches extra files.
Set `send: false` to save the reply as a draft instead of sending.

### `mail_forward`

Forward a message, preserving the quoted content and the `Fwd:`
subject prefix.

```json
{
  "id": "12345",
  "to": ["bob@example.com"],
  "body": "FYI"
}
```

`body` is a preface prepended above the quoted content; it may be
empty. `send: false` saves the forward as a draft.

### `mail_move`

Move a message to a different mailbox. To archive, pass the account's
Archive mailbox (or `[Gmail]/All Mail` for Gmail-style accounts).

```json
{ "id": "12345", "mailbox": "Archive" }
```

When the target mailbox belongs to a different account than the
source, pass `account` to disambiguate; otherwise the source's
account is used.

### `mail_mark_read`

Mark a message read or unread.

```json
{ "id": "12345", "read": true }
```

Pass `read: false` to mark unread.

### `mail_list_mailboxes`

Enumerate accounts and their mailboxes.

```json
{}
```

Returns an array of `{ name, id, mailboxes[] }` records. Useful for
finding the exact `account` or `mailbox` name to pass to
`mail_search`.

## Known limitations

- **Full-body search speed.** `mail_search`'s default body match
  compares against the cached snippet. Pass `full_body_match: true`
  to scan real bodies — this runs AppleScript per candidate, so
  expect seconds-per-mailbox. A narrowing filter
  (`sender`/`recipient`/`subject`/`mailbox`/`account`/date range) is
  required so the scan stays bounded.
- **HTML send.** `mail_send`, `mail_reply`, and `mail_forward`
  send plain text only; `isHTML` is a no-op today.
- **Read/flagged fields are macOS-version-dependent.** `read` and
  `flagged` only appear in `mail_search` / `mail_fetch` results
  (and can only be used as `unread_only` / `flagged_only` filters)
  when the envelope index exposes the corresponding columns.
  Older macOS releases may omit one or both.
- **Bcc visibility.** Mail's scripting dictionary does not always
  return Bcc recipients reliably; `mail_fetch` returns what Mail
  exposes.
- **Account ids.** The `id` returned by `mail_list_mailboxes` is
  Mail's internal account id, not a human-facing name; use `name`
  for scoping user-facing queries.
