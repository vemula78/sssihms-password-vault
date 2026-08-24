# What the independent audit changed, and what it deliberately did not

The audit is `NOTES/audit-2026-08-24-claude.md`; the brief it ran from is `AUDIT-PROMPT.md`.
This file records the fixes and, more importantly, the calls that were left open.

## The shape of the problem

The reveal door itself was sound — log, commit, then decrypt, in that order, with the
auditor disqualification genuinely mirrored. What was weak was everything *around* it:

- the audit log accepted arbitrary content from callers who held no vault role, and the
  reports then rendered that content as HTML to the two most privileged vault identities;
- the rate limit the design leaned on was defeated by one client-supplied header;
- three grant paths the permission model does not describe — DocShare, the reminder digest,
  and a Manager's unscoped write on `disabled` — routed around membership entirely.

The generalisable lesson: **a permission model is only as good as the paths it models.**
Every one of those three is a Frappe feature working exactly as documented, in a direction
this app never considered. Auditing `permissions.py` again would not have found any of them.

## Fixed

**One patch closed four findings**, because H1's injection vector, H3's forged log content
and M5's false `success` row all flowed through the same twenty lines of `reveal_secret`:

- `_require_vault_role()` now gates the reveal door, as it always did the other two RPCs.
- A nonexistent credential answers exactly like an inaccessible one, and writes nothing.
- `field_key` must match `^[A-Za-z0-9_.\-]{1,60}$`. Rejecting markup at the door matters
  more than escaping it at render time, because the log is permanent: an escaped payload is
  still a payload sitting in the table.
- An unknown field key is resolved to a *denial* before the success row is written.
- Both reports `escape_html` every user-authored `Data` column — the half of the fix that
  also covers rows written before the door was closed.

**Rate limiting is now per authenticated user**, counted from the access log itself, with
Frappe's `@rate_limit` kept as an outer guard. `frappe.local.request_ip` is the first
element of the caller's own `X-Forwarded-For` with no trusted-proxy check, and the
decorator's cache key embeds `form_dict.cmd`, which `/api/v2` never sets — so the
decorator alone gave an attacker unlimited buckets on one route and a colliding bucket on
the other. Nothing is logged when the budget is exhausted, deliberately: logging there
would let a caller keep appending to an uneditable table at request rate.

**The three grant paths:**

- DocShare on `Vault Credential`, `Vault Space` and `Credential Access Log` is refused by a
  `doc_events` validate hook, and the `share` DocPerm is gone from both doctypes. Sharing
  is evaluated *after* a `has_permission` denial and is OR-ed over
  `permission_query_conditions`, so one row could have overturned both hooks — including
  the auditor's `1=0`.
- The rotation digest drops auditors from its recipient list, and logs one `reminder` row
  per space notified. The sweep runs as Administrator and never consults the hooks, which
  is exactly why the three mirrors did not cover it.
- Only a Vault Admin may change `disabled`. It was enforced against precisely the people
  who could turn it off.

**Also:** the health report denies auditors explicitly rather than relying on an empty
result two layers downstream, and refuses disabled spaces for non-admins (it decrypts
everything in scope to score it). Space creation and deletion are logged. `ip_address`
records the real socket peer alongside the client-asserted value when they differ. The CSV
import gained a role gate and one uniform denial message. `get_password_override` resolves
a child row's parent so the *more* targeted bypass is on record, and tests by module rather
than a hardcoded doctype set.

**Four comments asserted protections that were not the ones doing the work** — corrected in
`vault_health.py`, `permissions.py`, `credential_access_log.py` and `api.py`, and in
DESIGN §6 and §2.4. This mattered more than its severity suggests: CLAUDE.md tells the next
session to trust these files.

BRIEF §6 asked for `no_track` on secret fields. That is unimplementable — `no_track` is not
a Frappe 16 DocField property — so the requirement was amended to name `track_changes: 0`,
which is what actually prevents a Version row.

## Left open, on purpose

- **`masked_hint` (L9)** stores the last four characters of Aadhaar, PAN, card and account
  numbers unencrypted, with no `print_hide`/`report_hide`. DESIGN deviation 3 accepted this
  — but it accepted it by inheriting `maskValue()` from the personal vault, which had no
  statutory exposure. Last-4 of an Aadhaar is personal data under the DPDP Act 2023. This
  is Praveen's call, not a bug to be quietly patched.
- **`X-Forwarded-For` at the proxy (H2, second half).** The per-user budget makes the
  limiter sound regardless, but whether the Apache in front of the site *sets* or *appends*
  the header still decides whether `ip_address` and the outer decorator mean anything.
  Needs one look at the vhost on the VM.
- **`Vault Space.track_changes: 1` (L16)** keeps a second, unprotected copy of every
  membership change in Version rows, visible to anyone who can read the space. The access
  log already records these append-only. Left alone rather than silently dropping an
  admin-visible history; worth a decision.
- **The CSV import client (L10)** still does not exist, so the endpoint is unreachable from
  the UI and its "no secret-bearing file in `/private/files`" guarantee is vacuously true.
  Either build the button or remove the endpoint.
- **L18/L19** are cosmetic: two unreachable entries in `_READ_PTYPES`, and a Vault Space
  rename from the desk that silently does nothing.

## Verification status — read this before trusting the fixes

The pure suite (52 tests) passes and every module compiles. **The site-dependent tests were
written but never executed** — this machine has no bench, and the fixes touch exactly the
paths those tests cover. Ten new tests in `test_vault_credential.py` and two in the new
`test_vault_space.py` are therefore unproven, and so is the runtime behaviour of every
change above. Run them on the bench before believing any of it:

```bash
bench --site <site> run-tests --app sssihms_password_vault
```

Specific things most likely to fail first on a real site: `frappe.RateLimitExceededError`
existing under that name, `frappe.db.count` accepting the list-filter form used in
`_enforce_reveal_budget`, `escape_html` being importable from `frappe.utils`, and the
`Notification Log` subject filter in the digest test.
