# Independent security audit — SSSIHMS Password Vault

Date: 2026-08-24. Auditor: Claude (Opus 5). Repo state: working tree at
`~/Documents/sssihms-password-vault`, 52/52 pure tests green, `py_compile` clean.

## How this was verified, and what was not

No bench or site was available (no `frappe` on this machine; the evaluation VM was not
contacted). So:

- **Framework behaviour was verified against Frappe `version-16` source fetched from
  github.com/frappe/frappe**, not against the installed 16.31 tree. Every framework claim
  below cites file:line in that source. Where 16.31 could differ from the branch tip I say so.
- **All 28 site-dependent tests (21 credential + 7 access-log) were not run.** Findings that
  would have been caught or refuted by executing them are marked *unverified-by-execution*.
- No HTTP request was made against any site, so every "remotely reachable" claim is derived
  from routing/permission source, not from an observed response.

Severity is impact-if-exploited; confidence is how sure I am the code does what I say.
Design concerns are labelled as such.

---

## HIGH

### H1. Stored XSS in Credential Access Report and Vault Health, plantable by any authenticated user, firing in a Vault Admin's or Vault Auditor's session
**Severity: High. Confidence: High (bug). Class: exploitable.**

`Credential Access Log.field_key`, `field_label`, `detail` and `credential_title` are
`Data`/`Small Text` columns rendered by two Script Reports as `Data` columns:
- `password_vault/report/credential_access_report/credential_access_report.py:145-147`
  (`field_label`, `detail`), `:133` (`credential_title`)
- `password_vault/report/vault_health/vault_health.py:80,82` (`title`, `field_label`)

Frappe's `Data` formatter does **not** escape HTML — it returns the value after an optional
custom formatter (`frappe/public/js/frappe/form/formatters.js:36-48`). `frappe.format` then
passes the string through `frappe.dom.remove_script_and_style`
(`formatters.js:447`), which removes only `script`, `style`, `noscript`, `title`, `meta`,
`base`, `head` and stylesheet `link` elements and **strips no event-handler attributes**
(`frappe/public/js/frappe/dom.js:33-74`); it short-circuits and returns the input verbatim
when none of those tag names appear (`dom.js:44-46`). Query-report cells are then rendered
as HTML — this app's own formatter relies on exactly that to colour denied rows
(`credential_access_report.js:62` returns a `<span style=...>`), which is self-contained
proof that cell content is injected as markup.

Attack path (no vault role required):
1. Any authenticated ERPNext account POSTs
   `/api/method/sssihms_password_vault.vault.api.reveal_secret`
   with `credential=VC-00001` (names are sequential, `autoname: format:VC-{#####}`) and
   `field_key=<img src=x onerror=...>` (≤140 chars, the `Data` column limit).
2. `vault/api.py:83-84` sets `denied_reason = "not a member of this space"`;
   `vault/api.py:89` resolves `field_label` to the `field_key` itself because
   `_find_secret_row` returns `None` (`api.py:195-207`); `api.py:95-103` writes the row and
   `api.py:103` **commits it** before the throw. The payload is now permanently in an
   append-only log.
3. A Vault Admin or Vault Auditor opens Credential Access Report. The payload executes in
   their session — the two highest-privileged vault identities. From there it can call
   `reveal_secret` on every credential as that admin, or `frappe.share.add` (see M1).

A space member can also plant it via the *success* path (M5), and an Editor can plant it in
`Vault Credential.title` or `Credential Secret Field.label`, which fires in Vault Health for
any space Manager.

**Smallest fix:** escape server-side in both reports before returning — wrap `field_label`,
`detail`, `credential_title`, `title` in `frappe.utils.escape_html()`; and validate
`field_key` at the door in `reveal_secret` (reject anything not matching
`^[A-Za-z0-9_.\-]{1,60}$` before it reaches `write_access_log`). Escaping only in the JS
formatter is not enough — Vault Health has no custom formatter.

**Test that would have caught it:** a doctype test that writes a log row with
`field_label='<img src=x onerror=1>'`, runs `credential_access_report.execute()` and asserts
the returned `field_label` contains no `<`. There is no such test.

**Related, unverified:** the same Editor-controlled `Credential Secret Field.label` is used
as a Select option label in the reveal/generate dialogs (`vault_credential.js:124,212`). I
could not locate `$.fn.add_options` in the v16 tree to confirm whether it escapes, so I make
no claim about that path — worth checking separately.

---

### H2. The reveal rate limit is bypassable outright by spoofing `X-Forwarded-For`
**Severity: High. Confidence: High on the framework mechanism; Medium on exploitability, which depends on the Apache config in front of the site.**

`@rate_limit(limit=30, seconds=300)` on `reveal_secret` (`vault/api.py:50`) uses the default
`ip_based=True` with no `key`, so the bucket identity is `frappe.local.request_ip`
(`frappe/rate_limiter.py:140-154`). `request_ip` is taken from the **client-supplied
`X-Forwarded-For` header, first element, with no trusted-proxy validation**:

```python
def set_request_ip(self):
    if frappe.get_request_header("X-Forwarded-For"):
        frappe.local.request_ip = (frappe.get_request_header("X-Forwarded-For").split(",", 1)[0]).strip()
```
(`frappe/auth.py:62-73`)

Sending a different `X-Forwarded-For` value per request yields an unlimited number of fresh
buckets, defeating BRIEF §2(c) and the AUDIT-PROMPT guarantee 1 clause "and is rate-limited"
for all three limited endpoints (`reveal_secret` 30/300, `generate_credential_secret`
60/300, `import_credentials_csv` 5/3600). A single compromised Reader account can then dump
every secret in its spaces as fast as the server answers, with no throttle — audit rows are
written, but nothing slows the exfiltration.

The standard bench nginx template forwards `X-Forwarded-For $proxy_add_x_forwarded_for`,
which *appends* and therefore preserves the client value as element 0 — under that config the
spoof works. Whether the Apache in front of `sssihms-web-vm2023` overwrites the header
instead is the deciding factor and I could not inspect it.

**Smallest fix:** key the limiter on the authenticated identity, not the IP. Frappe's
decorator has no per-user mode (`ip_based=False` with no `key` throws,
`rate_limiter.py:151-152`), so this needs a small counter in `vault/api.py` over
`frappe.cache` keyed on `frappe.session.user`. Also confirm the reverse proxy *sets* rather
than appends `X-Forwarded-For`.

**Test that would have caught it:** none exists — there is no test of the rate limiter at all.

---

### H3. `reveal_secret` has no role gate, so any authenticated account can enumerate credential IDs and write arbitrary content into the append-only audit log
**Severity: High. Confidence: High. Class: exploitable; direct violation of guarantee 2.**

`get_templates` and `generate_credential_secret` both call `_require_vault_role()`
(`vault/api.py:220,239`). `reveal_secret` does not (`vault/api.py:49-107`). Consequences for
a plain ERPNext account with zero vault roles:

1. **Existence oracle.** `frappe.get_doc` at `api.py:68` raises `DoesNotExistError` (404) for
   an unknown name but the flow reaches `frappe.throw(..., PermissionError)` (403) for a real
   one. Probing `VC-00001…VC-99999` maps the whole credential namespace, including its size.
2. **Forged audit content.** Each probe commits a `Credential Access Log` row
   (`api.py:95-103`) whose `field_key`/`field_label` are verbatim attacker input and whose
   `action` is a `reveal` attempt against a credential the attacker merely named. Guarantee 2
   requires log rows to be "impossible to create with false content"; this creates them at
   will, and they can never be deleted or edited (which is the point of the log, and now also
   the problem). Combined with H2 the volume is unbounded — the audit trail can be buried.
3. It is also the injection vector for H1.

**Smallest fix:** call `_require_vault_role()` as the first line of `reveal_secret`; validate
`field_key` against the credential's actual keys before logging; and return the same
`PermissionError` for a nonexistent credential as for an inaccessible one (resolve existence
with `frappe.db.exists` and throw the identical message either way).

**Test that would have caught it:** a test asserting a user with no vault role gets
`PermissionError` from `reveal_secret` *and* that no log row is created for a nonexistent
credential name. Existing tests only cover `OUTSIDER`, who is deliberately given the
`Vault User` role (`test_vault_credential.py:59-62`).

---

## MEDIUM

### M1. A DocShare row overrides both `has_permission` and `permission_query_conditions`, including the auditor `1=0` lock
**Severity: Medium (needs a Vault Admin action, but it is one UI click). Confidence: High. Class: design + framework interaction.**

`vault/permissions.py:15-17` states "Frappe controllers and hooks can only ever *deny*, never
grant". True of hooks — but Frappe evaluates document sharing *after* the controller denial
and lets it grant:

```python
if not perm and not ignore_share_permissions:
    perm = false_if_not_shared()
```
(`frappe/permissions.py:206-208`; `get_doc_permissions` returns `{ptype: 0}` when the
controller hook denies, `permissions.py:499-501`)

and in list/report queries the share set is OR-ed over the hook's condition:

```python
where_condition = Criterion.all(conditions)
shared_docs = frappe.share.get_shared(doctype, self.user)
if shared_docs:
    where_condition |= table.name.isin(shared_docs)
```
(`frappe/database/query.py:1588-1595`)

`Vault Credential` and `Vault Space` both grant `share: 1` to Vault Admin
(`vault_credential.json:143`, `vault_space.json:65`), and `frappe.share.add` is whitelisted
with an `everyone` flag (`frappe/share.py:21-46,190`). So
`POST /api/method/frappe.share.add {doctype: "Vault Credential", name: "VC-00001",
everyone: 1, read: 1}` makes that credential's row and fields readable by **every**
authenticated user — including a Vault Auditor, whose `credential_query_conditions` `1=0`
(`permissions.py:170`) is simply OR-ed away, and including accounts with no vault role at
all. With `write: 1` the sharee can also edit the credential, and `share: 1` lets them
re-share.

Secrets themselves stay behind `reveal_secret`, which checks membership independently
(`api.py:70,83`) — so this leaks titles, usernames, URLs and the plaintext `notes` field, not
passwords. But it silently voids the membership model and the separation-of-duties lock, and
the grant itself is not access-logged.

**Smallest fix:** drop `share: 1` from both DocPerm rows (Vault Admin already sees
everything, so sharing buys nothing), and add a `doc_events` `validate` on `DocShare` that
throws for `share_doctype in ("Vault Credential", "Vault Space")`. Optionally set
`disable_document_sharing` in System Settings.

**Test that would have caught it:** share a credential with `OUTSIDER` via
`frappe.share.add` and assert `frappe.get_list("Vault Credential")` as that user still
returns `[]`. No such test exists.

---

### M2. The rotation-reminder digest sends credential titles and due dates to Vault Auditors — the fourth auditor path the three mirrored guards do not cover
**Severity: Medium. Confidence: High. Class: exploitable-in-normal-operation (no attacker needed).**

`vault/reminders.py:133-141` selects recipients purely by `access_level == "Manager"` in the
member table. Nothing filters `is_vault_auditor` / `is_vault_auditor_only`. So an auditor who
is a space Manager receives, per `reminders.py:96-107`:
- a `Notification Log` row inserted with `ignore_permissions=True` (`reminders.py:97-105`),
- an email (`reminders.py:107`), whose body is stored in `tabEmail Queue`,

both containing `f"- {cred.title} (due {…})"` for every overdue credential in that space
(`reminders.py:161-171`).

Credential titles are exactly what `credential_query_conditions` returns `1=0` to hide from
an auditor (`permissions.py:166-170`), and what `credential_has_permission` returns `False`
for (`permissions.py:210-211`). The three mirrors are bypassed here because the sweep runs as
Administrator and never consults them — `reminders.py:20-22` says so explicitly. The same
path also sends a space's titles to **all Vault Admin role holders** on the no-manager
fallback (`reminders.py:81`), and none of it is access-logged (`ACTIONS` in `vault/audit.py:21-30`
has no reminder action).

**Smallest fix:** filter recipients through `is_vault_auditor_only()` in
`_space_manager_emails`, and add a `"reminder"` action to `ACTIONS` with one log row per space
notified.

**Test that would have caught it:** make the auditor a Manager of a space with an overdue
credential, run `daily_rotation_sweep()`, assert no `Notification Log` row exists for that
user. No such test exists.

---

### M3. On `/api/v2/method/...` the rate-limit bucket collapses to `rl:None:<ip>`, doubling the reveal limit and colliding with the generator's
**Severity: Medium. Confidence: High.**

The cache key is `f"rl:{frappe.form_dict.cmd}:{identity}"` plus the window
(`frappe/rate_limiter.py:154-157`). `frappe.form_dict.cmd` is set only on the v1 route
(`frappe/api/v1.py:40`) and by the desk handler (`frappe/handler.py:49`). The v2 route calls
`frappe.override_whitelisted_method` directly and never sets `cmd`
(`frappe/api/v2.py:28-51`). Therefore:

- `/api/method/…reveal_secret` uses bucket `rl:sssihms…reveal_secret:<ip>:300`
- `/api/v2/method/…reveal_secret` uses bucket `rl:None:<ip>:300`

An attacker alternating the two routes gets 60 reveals per 5 minutes per IP instead of 30.
Worse, on v2 the same `rl:None:<ip>:300` bucket is shared with
`generate_credential_secret` (also `seconds=300`, `api.py:228`) and with any other
`@rate_limit(seconds=300)` endpoint in the site, so ordinary generator use throttles reveals
and vice versa.

DESIGN §3 states the limiter is "keyed by IP+path in Frappe's implementation — accepted". The
IP part is an accepted trade; the *path* part is simply not true on `/api/v2`.

**Smallest fix:** the same per-user counter that fixes H2 removes this too, because it stops
depending on `form_dict.cmd`. A narrower fix is `@rate_limit(key="credential", …)`, but that
keys on a client-supplied field and is worse.

---

### M4. Every access-log row's `ip_address` is attacker-controlled
**Severity: Medium. Confidence: High. Class: guarantee-2 violation.**

`vault/audit.py:101` records `frappe.local.request_ip`, which is the unvalidated first element
of the client's `X-Forwarded-For` header (`frappe/auth.py:62-64`, quoted in H2). So the "and
from where" half of every audit row — including the rows recording a successful reveal — can
be set to any value by the person being audited. The log is append-only but not truthful.

**Smallest fix:** record `frappe.request.remote_addr` (the real peer, or the proxy) in a
second column, or store the full `X-Forwarded-For` chain rather than element 0, and label the
existing column as client-asserted.

---

### M5. A `success` log row is committed for reveals that return nothing
**Severity: Medium. Confidence: High. Class: guarantee-2 violation (false content).**

`vault/api.py:110-120` writes `outcome="success"` and commits. Only afterwards, at
`api.py:130-133`, does the code discover `row is None` and throw "That field does not exist on
this credential." The committed row asserts a successful reveal of a field that never
existed and whose value was never returned. Any space member can generate these at will, and
they cannot be corrected because the log is append-only.

The comment at `api.py:130-132` ("Checked only after the permission gate: telling a non-member
which field keys exist would be a disclosure in itself") justifies deferring the check past
the *permission* gate — but it did not need to be deferred past the *logging* gate.

**Smallest fix:** resolve the row and reject an unknown `field_key` immediately after the
permission gate and before `write_access_log`, logging it as `outcome="denied",
detail="unknown field"`. That fixes M5 and removes H1's success-path injection at once.

**Test that would have caught it:** call `reveal_secret(cred, "nope")` as a Manager and assert
the resulting log row has `outcome="denied"`. `test_invalid_reveal_action_is_logged`
(`test_vault_credential.py:303`) covers the sibling case but not this one.

---

### M6. The access report silently truncates at 2000 rows
**Severity: Medium. Confidence: High. Class: design defect in an audit tool.**

`credential_access_report.py:36,102` caps the query at `limit_page_length=2000` ordered
`timestamp desc`, and the return value (`:105`) carries no indication that anything was
dropped. An auditor filtering a wide date range sees the newest 2000 rows and has no way to
know the window was cut — so "no reveal of X appears in the log" is not a safe conclusion.
Given H3/H2 allow an attacker to generate thousands of rows cheaply, this is also the
mechanism by which real rows get pushed out of view.

Two smaller notes on the same lines: `limit_page_length` is deprecated in Frappe 16
(`frappe/model/qb_query.py:152-157` emits a deprecation warning and maps it to `limit`), and
the report has no `credential_title` filter, so narrowing is only possible by ID.

**Smallest fix:** query `limit=_PAGE_LENGTH + 1`, and when the extra row comes back, prepend
a `frappe.msgprint` or a summary row stating the result was truncated and the filter must be
narrowed.

---

### M7. A space Manager can clear `disabled` on their own space
**Severity: Medium. Confidence: High. Class: design.**

`space_has_permission` grants `write` on a Vault Space to its Managers
(`permissions.py:259-260`), and `VaultSpace.validate` (`vault_space.py:20-23`) guards only
duplicate members, at-least-one-Manager and member stamping. Nothing restricts *which* fields
a Manager may write. So a Manager can set `disabled = 0`, perform the reveals and edits the
flag was meant to prevent, and set it back.

The `disabled` flag is described as an archival read-only lock
(`vault_space.json:32`, DESIGN §1.2), and it is enforced in `reveal_secret`
(`api.py:85-86`), `credential_has_permission` (`permissions.py:228,230`) and the CSV import
(`csv_import.py:160-161`) — against exactly the people who can turn it off. DESIGN §1.2 never
considered field-level scoping of a Manager's write.

**Smallest fix:** in `VaultSpace.validate`, throw if `disabled` changed and the caller is not
`is_vault_admin(frappe.session.user)`; log the change to the access log either way.

---

### M8. `get_password_override` refuses `Credential Secret Field` and `Vault Settings` without any audit row — contrary to its own comment
**Severity: Medium. Confidence: High. Class: audit gap + false comment.**

`vault/api.py:169-171` says:

> Best-effort audit: a Credential Secret Field name is a child row, so resolve its parent
> credential for the log; failure to resolve must not swallow the refusal.

The code never resolves the parent. `api.py:172` logs only when
`doctype == "Vault Credential"`. So an attempt to grab a child-row secret directly —
`frappe.client.get_password("Credential Secret Field", "<row hash>", "secret_value")`, the
*more* targeted bypass, because that is where every non-login template's secrets live — is
refused silently, with nothing on record.

**Smallest fix:** for `Credential Secret Field`, look up
`frappe.db.get_value("Credential Secret Field", name, "parent")` and log against that
credential; for `Vault Settings` (which has no Password field at all — see L14) log a
space-level row or drop it from the set.

---

## LOW and design concerns

**L1. `vault_health.py:38-39` states something false about `frappe.get_all`.** *(false comment; High confidence)*
The comment reads "get_all applies credential_query_conditions (the EXISTS-membership
clause), so the name list is already scoped". It does not: `frappe.get_all` sets
`ignore_permissions=True` unconditionally (`frappe/__init__.py:1402`). The list is scoped only
by the per-row `frappe.has_permission(..., doc=row.name, ...)` at `vault_health.py:51`, which
does work — `has_permission` accepts a docname string (`frappe/permissions.py:138-141`) and
routes through `get_doc_permissions` → `has_controller_permissions`
(`permissions.py:481-498`), so `credential_has_permission` runs. The same file's sibling
report states the truth (`credential_access_report.py:17`, "frappe.get_all, which ignores
permissions — deliberate"), so the codebase contradicts itself on one line. DESIGN §6 step 1
is the origin and is wrong in the same way, and adds a second error: "then `get_doc` per
credential so `has_permission`/query conditions stay in force" — `frappe.get_doc` checks
nothing, as `api.py:65-66` correctly notes. **Fix:** correct the comment and DESIGN §6.

**L2. `vault_health.py:24-28` claims Vault Auditor "never reaches this function". It does.** *(false comment; High confidence)*
The report's roles are Vault Admin and Vault User (`vault_health.json`), and `Vault User` is
auto-granted to every space member (`vault_space.py:90-97`) — which CLAUDE.md itself flags as
the reason auditor-ness must be a disqualification. So an auditor who is a space Manager
passes the role gate *and* the Manager check at `vault_health.py:32`. What actually stops
them is `credential_has_permission` returning `False` at `permissions.py:210-211`, leaving
`accessible` empty. The guard holds — by the third mirror, not by the roles list. DESIGN §2.4
clause (a) ("no DocPerm row on Vault Credential ⇒ Frappe denies before hooks run") is wrong
for the same reason, and clause (b) ("reveal_secret rejects any caller whose membership level
is below Reader — auditor-ness never substitutes for membership") describes weaker behaviour
than the code implements. **Fix:** correct both comments; add an explicit
`if is_vault_auditor_only(user): frappe.throw(...)` at the top of `execute()` so the report
does not depend on a downstream mirror.

**L3. The audit-delete override is reachable over HTTP, not only from a shell.** *(false comment; Medium confidence — I did not verify the `safe_exec` namespace)*
`credential_access_log.py:36-40` and DESIGN §4 both assert "The flag cannot be set over HTTP —
no whitelisted method in this app sets it — so the override requires shell access to the VM".
The qualifier "in this app" is doing unnoticed work: a System Manager holding Script Manager
can create a Server Script (API type) that sets `frappe.flags.vault_audit_delete_override`
and calls `frappe.delete_doc`, all over HTTP. That is still a System Manager, which the trust
model accepts — but "requires shell access to the VM" overstates the bar, and a false
reassurance in the file that defends the audit trail is worth correcting. **Fix:** reword to
"requires System Manager plus either shell access or Script Manager", or gate on
`frappe.conf` / an env marker that a Server Script cannot set.

**L4. Vault Health decrypts secrets in disabled spaces.** *(design inconsistency; High confidence)*
`reveal_secret` refuses on a disabled space (`api.py:85-86`) and `credential_has_permission`
blocks write/delete there (`permissions.py:228,230`), but `read` passes unconditionally
(`permissions.py:225-226`) and `vault_health.py` never checks `space_is_disabled`. So a
Manager of an archived space can still have every secret in it decrypted server-side and
learn weak/reused verdicts. **Fix:** add the disabled check to `vault_health.execute`, or
state in DESIGN that "reveal-free" excludes derived verdicts.

**L5. An org-wide Vault Health run is unbounded.** *(availability; High confidence)*
`vault_health.py:44-46` calls `frappe.get_all` with no limit, so `frappe.get_all` defaults
`limit_page_length=0` (`frappe/__init__.py:1403-1404`) — every credential in the site. Then
one `frappe.has_permission` (which loads a lazy doc), one `frappe.get_doc`, and one
`get_decrypted_password` per credential and per `is_password` child row
(`health.py:191-233`), synchronously, with `disable_prepared_report: 1` in
`vault_health.json` preventing backgrounding. On a large vault this is a long-running request
that decrypts everything. **Fix:** allow the prepared report, or page the credential list.

**L6. `import_credentials_csv` leaks space existence before checking anything.** *(enumeration oracle; High confidence)*
`csv_import.py:158-168` runs `frappe.db.exists` → "Vault Space not found.", then the disabled
check → "This space is disabled.", then membership → "You need Editor access". There is no
`_require_vault_role()` gate, so any authenticated account can distinguish all three and map
space names and their disabled state. Denied attempts write no log row, unlike
`reveal_secret`. **Fix:** call `_require_vault_role()` first and collapse the three messages
into one permission error; log denials.

**L7. `parse_csv_rows` materialises the whole upload before truncating.** *(resource; High confidence)*
`csv_import.py:74` does `list(csv.reader(io.StringIO(csv_text)))` on the full text;
`MAX_IMPORT_ROWS` is applied only at `:88`. A large `csv_text` is fully parsed into memory
first. Bounded in practice by the web server's body limit and 5/hour — but that limit is
itself bypassable (H2). **Fix:** iterate the reader and stop at `MAX_IMPORT_ROWS + 1`.

**L8. Secret length is readable through any list path with no audit row.** *(information disclosure; High confidence)*
Frappe stores `"*" * len(new_password)` in the table column for a `Password` field
(`frappe/model/base_document.py:1364-1369`). Neither `password` nor `secret_value` carries a
`permlevel`, and `get_permitted_fields` filters by permlevel only — it has no
Password-fieldtype exclusion (`frappe/model/__init__.py:216-262`). So
`frappe.client.get_list("Vault Credential", fields=["name","password"])` returns the exact
character length of every secret in the caller's spaces, un-audited. `report_hide`/`print_hide`
on those fields are UI hints only. Low impact, but it is one more thing a secret's shape
tells you without going through the audited door. **Fix:** if this matters, move the Password
fields to a non-zero permlevel granted to no role, so the list layer strips them.

**L9. `masked_hint` puts the last four characters of Aadhaar/PAN, card and account numbers in a plaintext, un-audited column.** *(design concern, deliberate; High confidence)*
`templates.py:411-421` is explicit that this is intended, and DESIGN deviation 3 accepts it.
Worth surfacing anyway because of *which* fields carry `masked: True` alongside
`sensitive: True`: `govid.idNumber` (`templates.py:298-303`), `card.cardNumber` (`:204-209`),
`netbanking.accountNumber` (`:133-138`), `demat.boId` (`:265-270`),
`insurance.policyNumber` (`:354-359`). The hint is computed from the real plaintext at
`vault_credential.py:114-116`, stored unencrypted, and has no `print_hide`/`report_hide`
(`credential_secret_field.json:86-93`) so it exports and prints for Vault Admin. Last-4 of an
Aadhaar is personal data under the DPDP Act 2023; that is a decision to record deliberately
rather than inherit from `maskValue()` in a different product. **Fix (if wanted):** add
`print_hide`/`report_hide` to `masked_hint`, and drop `masked` from `govid.idNumber`.

**L10. The CSV import endpoint ships with no client, and its central guarantee depends on that missing client.** *(incomplete; High confidence)*
`import_credentials_csv` is whitelisted (`csv_import.py:139`) but nothing calls it — the only
client scripts in the repo are `vault_credential.js` and `credential_access_report.js`, and
neither references it. Its docstring (`csv_import.py:146-148`) and DESIGN §7 rest the "no
secret-bearing CSV in `/private/files`" guarantee on a client that "reads the file with
FileReader and posts text". That client does not exist, so today the guarantee is vacuously
true and the feature is unreachable from the UI. Related and good: the generic Data Import
route is closed, because no doctype sets `allow_import` and `has_permission` returns False for
`ptype="import"` when `meta.allow_import` is falsy (`frappe/permissions.py:157-159`).
**Fix:** either build the Vault Space client button as designed, or remove the endpoint until
it has one — a whitelisted, unreferenced write endpoint is attack surface with no user.

**L11. Space creation and deletion are not access-logged.** *(audit gap; High confidence)*
`vault_space.py` logs membership add/remove/level-change (`:99-125`) but neither
`after_insert` nor `on_trash` writes a row (`on_trash` at `:127-138` only blocks the delete).
Deleting a space destroys its entire member table with no audit record of who did it, and
`ACTIONS` (`audit.py:21-30`) has no space-lifecycle action.

**L12. The `get_password` override wins only by app load order.** *(fragility; High confidence)*
`frappe.override_whitelisted_method` returns `overrides[-1]`
(`frappe/__init__.py:1577-1580`). The hook value is a list built across installed apps, so if
any other app on this bench ever overrides `frappe.client.get_password` and sorts later, this
app's override is silently displaced and the prior audit's finding #1 returns with no test
failure. **Fix:** assert the resolution in a test (see T1).

**L13. `get_password_override` is itself a whitelisted alias for framework password retrieval.** *(design; High confidence)*
`api.py:156` whitelists it with the default method set, so
`/api/method/sssihms_password_vault.vault.api.get_password_override` is a live endpoint. For
non-vault doctypes it reproduces `frappe.only_for("System Manager")` and returns the password
(`api.py:190-192`) — no escalation, but a second, undocumented, unrate-limited, unlogged path
to the same capability. **Fix:** drop `@frappe.whitelist()`; the hook resolves the dotted path
via `frappe.get_attr` and then calls `is_whitelisted(method)` (`frappe/handler.py:83`,
`frappe/api/v2.py:48`) — so it does need the decorator. Then leave it, but say so in the
docstring instead of implying it is reachable only as an override.

**L14. The override's doctype set is hardcoded and one entry is wrong.** *(fragility; High confidence)*
`api.py:167` lists `{"Vault Credential", "Credential Secret Field", "Vault Settings"}`.
`Vault Settings` has no Password field at all (`vault_settings.json`), so that entry is dead,
and the comment implying it holds secrets is misleading. Conversely a Password field added to
any future vault doctype is not covered. **Fix:** test
`frappe.get_meta(doctype).module == "Password Vault"` instead of an explicit set.

**L15. `index_web_pages_for_search: 1` on Vault Space and Vault Space Member is inert but latent.** *(design; High confidence)*
`vault_space.json:46` and `vault_space_member.json:51` set it. The website search indexer
requires `has_web_view: 1` **and** `allow_guest_to_view: 1` as well
(`frappe/search/website_search.py:90`), neither of which is set, so nothing is indexed today.
It reads as intent, though, and if a web view were ever added the membership table would be
swept into a guest-visible index. `Vault Credential` correctly sets it to `0`. **Fix:** set
both to 0.

**L16. Vault Space membership diffs also land in Version rows.** *(information disclosure; High confidence)*
`vault_space.json:87` sets `track_changes: 1`, so every member add/remove/level change writes
a `Version` row containing the diff (`Document.save_version`,
`frappe/model/document.py:1586-1609`). Those rows are surfaced by `get_docinfo` to anyone with
read on the space and are not covered by the append-only guarantees the access log has.
Membership is not secret from members, so this is minor — but it is a second, unprotected
copy of the same security events.

**L17. `reminders.py` passes User *names* to `frappe.sendmail(recipients=…)`.** *(correctness; High confidence)*
`_enabled()` returns `row.name` from the User doctype (`reminders.py:157-158`), the helpers
that call it are named `_space_manager_emails` / `_vault_admin_emails`, and the value is used
both as `Notification Log.for_user` (correct — wants a User name) and as an email recipient
(`reminders.py:107`). Those coincide only on sites where the username is the email address.
**Fix:** select `["name", "email"]` and use `email` for `sendmail`.

**L18. Two entries in `_READ_PTYPES` and the hook's export/share denial are unreachable.** *(dead code / misleading comment; High confidence)*
`permissions.py:33` includes `print` and `email`, but the Vault User DocPerm grants neither
(`vault_credential.json:146-154`), and `has_permission` requires both the hook and the role
perm — so members never get print/email regardless. And `permissions.py:232-235`'s
"export / share / import: Vault Admin only" is never consulted for export, because
`can_export` reads role permissions directly and never calls the hooks
(`frappe/permissions.py:646-654`). The outcome is right (Vault User has `export: 0`) but for a
different reason than the comment gives.

**L19. Renaming a Vault Space from the desk silently does nothing.** *(functional; High confidence)*
`vault_space.json` combines `autoname: field:space_name`, `title_field: space_name` and
`allow_rename: 0`. The whitelisted `update_document_title` treats a `space_name` edit as a
title update and saves it (`frappe/model/rename_doc.py:62-96`), but
`BaseDocument._sync_autoname_field` then resets the field to `self.name`
(`frappe/model/base_document.py:1247-1253`). The user sees a success toast and no change.

---

## Tested and found to hold

Re-tested the four findings in `NOTES/codex-audit-2026-08-24.md`:

- **#1 `frappe.client.get_password` — closed on every HTTP route.** The override is applied by
  `frappe.override_whitelisted_method` in both `frappe/handler.py:67` (which serves `/app`
  desk calls, `/api/method/...` and `/api/v1/method/...` via `frappe/api/v1.py:35-41`) and
  independently in `frappe/api/v2.py:36`. There is no v2 gap. `frappe.get_lazy_doc` exists in
  16 (`frappe/__init__.py:1592`) and the override's non-vault fall-through matches stock
  (`frappe/client.py:544-552`) line for line.
- **#2 auditor reading credentials — the three mirrors are real and consistent.** Verified
  that `has_controller_permissions` runs the `has_permission` hook whenever a doc is supplied
  (`frappe/permissions.py:481-498`) and that `get_permission_query_conditions` picks up the
  hook by doctype name (`frappe/database/query.py:1610-1637`). The extra `doctype=` kwarg
  Frappe passes is dropped by `get_newargs` before the call
  (`frappe/__init__.py:1168-1190`), so the two-arg hook signatures are safe. Residual auditor
  paths are M1, M2 and L2, not this.
- **#3 `no_track` — the app is right and the brief is wrong.** `no_track` is genuinely not a
  DocField property in Frappe 16: `frappe/core/doctype/docfield/docfield.json` has 79 fields
  and none is `no_track`. `track_changes: 0` is the effective control, because
  `Document.save_version` returns before creating anything when the meta flag is false
  (`frappe/model/document.py:1586-1597`). BRIEF §6's literal requirement is unimplementable
  and should be amended to name `track_changes`.
- **#4 invalid `action` — now logged** (`api.py:72-77`), and coerced to a safe literal before
  reaching `write_access_log`'s validation.

Also verified clean:

- **Child tables reached via parent are filtered in Frappe 16.** This was my main suspected
  hole and it does not exist here. For a query on `Credential Secret Field` with
  `parent="Vault Credential"`, the engine sets `permission_doctype = parent_doctype`
  (`frappe/database/query.py:276`), inner-joins the parent table on
  `child.parent = parent.name`, and applies the *parent's* `permission_query_conditions`
  against the joined table (`query.py:1548-1560`). Without a `parent`, `has_child_permission`
  denies outright (`frappe/permissions.py:828-833`), so
  `GET /api/v2/document/Credential Secret Field` is refused. Note this is a v16 hardening —
  a test should pin it (T5).
- **`frappe.client.insert` / `set_value` / `delete` on child rows all route through the parent's
  `save()`** (`frappe/client.py:205-217` and `:526-547`), so `Vault Space Member` rows cannot
  be added, changed or removed without `VaultSpace.validate` and `on_update` running — i.e.
  membership changes cannot be made unvalidated or unlogged. Same for
  `Credential Secret Field`, so `_validate_secret_rows` cannot be skipped.
- **Rename of a log row or credential is blocked** by `allow_rename: 0` plus
  `validate_rename` (`frappe/model/rename_doc.py:382`), and `update_document_title` cannot
  touch a log row because its `title_field` resolves to `name` and it first requires write
  permission the log grants to nobody.
- **Bulk delete and Bulk Update both hit the controller.** `delete_items` →
  `frappe.delete_doc` per row → `on_trash` throws
  (`frappe/desk/reportview.py:660-691`); `frappe.client.bulk_update` and
  `submit_cancel_or_update_docs` both go through `doc.save()` → `validate()` throws.
- **`ignore_links_on_delete` does what hooks.py says.** `Credential Access Log` is skipped as
  a *linking* doctype during delete-link checks
  (`frappe/model/delete_doc.py:312-320, 395-399, 444-448`), so a revealed credential stays
  deletable and its log rows survive as dangling links — which is the intended design.
- **No secret reaches a Version row, a websocket payload, or the global search index.**
  `track_changes: 0` short-circuits `save_version`; `notify_update` publishes only
  `{modified, doctype, name}` and `{doctype, name, user}`
  (`frappe/model/document.py:1491-1511`); `update_global_search` indexes nothing because no
  field sets `in_global_search` and no doctype sets `show_name_in_global_search`
  (`frappe/utils/global_search.py:254-286`).
- **No SQL injection.** The app contains no `frappe.db.sql`, no string-formatted SQL, no
  `eval`/`exec`. The two `permission_query_conditions` interpolate only
  `frappe.db.escape(user)`. Every report filter is either matched against a fixed tuple
  (`ACTIONS`, `OUTCOMES`) or passed as a parameterised filter value, and `order_by`/`group_by`
  are hardcoded.
- **`reference/from-personal-password-manager/` is not imported anywhere** — it appears only
  inside docstrings in `health.py`, `generator.py`, `templates.py`, `csv_import.py`.
- **The generator is sound.** All randomness is `secrets.randbelow`, the Fisher–Yates shuffle
  is hand-written over it, and `vault/api.py:250-271` clamps every numeric option to a code
  constant before it reaches the generator.
- **`flags.in_insert` is true inside `on_update` during an insert**, as CLAUDE.md claims: it is
  cleared at `frappe/model/document.py:487` but deliberately re-set at `:503`, immediately
  before `run_post_save_methods()`. So the create/update double-log guard at
  `vault_credential.py:153` works.
- **`masked_hint` is computed from the real plaintext, not from asterisks.** Controller
  `validate` runs inside `run_before_save_methods()` (`document.py:484`), which precedes
  `self._validate()` (`:485`) where `_save_passwords` replaces the value with asterisks.
- **52/52 pure tests pass** and every module compiles.

---

## Test-coverage gaps (security-relevant)

- **T1 — the highest-value gap.** `test_framework_get_password_is_blocked`
  (`test_vault_credential.py:291-301`) imports `get_password_override` and calls it directly
  in Python. That tests the function, not the wiring: **delete the
  `override_whitelisted_methods` entry from `hooks.py` and this test still passes**, which is
  precisely the regression the prior audit found. Both CLAUDE.md and AUDIT-PROMPT.md say to
  verify this one over HTTP. Add, at minimum, the pure assertion
  `self.assertEqual(frappe.override_whitelisted_method("frappe.client.get_password"),
  "sssihms_password_vault.vault.api.get_password_override")` — it needs no HTTP and closes
  L12 too — plus an authenticated request against the site for the real thing.
- **T2** No test that report output is escaped (H1).
- **T3** No test that a DocShare cannot grant credential access (M1).
- **T4** No test that a Vault Auditor is excluded from Vault Health or from the reminder
  digest (L2, M2).
- **T5** No test pinning the child-table-via-parent query path. It holds today because of a
  Frappe 16 change; a test would catch a regression or a downgrade.
- **T6** No test that `_validate_secret_rows` rejects a row with both `is_secret` and `value`
  — a claim made in three places (`credential_secret_field.json:71`, `templates.py:22`,
  `vault_credential.py:54-57`) and asserted nowhere.
- **T7** No test of any rate limit (H2, M3).
- **T8** No test that a non-admin cannot change `Vault Space.disabled` (M7) — it would fail
  today.
- **T9** No test that `reveal_secret` refuses a caller with no vault role (H3).
- **T10** `import_credentials_csv` has no site-level test at all; `test_csv_import.py:3`
  acknowledges this.

---

## Summary

The reveal path itself is well built — log-then-commit-then-decrypt is correct, the ordering
is right, the auditor disqualification is genuinely mirrored in three places, and the
framework-level `get_password` hole from the prior audit is properly closed on every HTTP
route. What is weaker is everything *around* that door: the audit log accepts arbitrary
content from unauthenticated-of-vault callers and then renders it as HTML to admins (H1, H3),
the rate limit that guarantee 1 depends on is defeated by a header (H2), and three
grant paths the design does not model — DocShare (M1), the reminder digest (M2), and a
Manager's write on `disabled` (M7) — route around the membership model. Several comments in
the security-critical files assert protections that are not the ones actually doing the work
(L1, L2, L3, M8), which matters more than usual here because the next person to change this
code will trust them.
