# DESIGN.md — sssihms_password_vault

Binding design for the Frappe 16 custom app `sssihms_password_vault` (module `Password Vault`).
BRIEF.md governs; this document turns it into buildable specifications. Two builder agents
implement PACKAGE A and PACKAGE B (§10) in parallel from this file alone. House style follows
`sssihms_hr` (controllers with explicit permission checks, "deliberate decision" comments,
`frappe.db.set_value` only where re-entering `validate()` would be wrong, hand-written Version
rows when the controller is bypassed).

## Deviations from BRIEF.md

1. **Added a third role, `Vault User`.** The brief names only `Vault Admin` and `Vault Auditor`
   plus space membership. Frappe DocPerm rows grant by role; without a base role, members would
   have zero ORM access and the `permission_query_conditions` hook would have nothing to narrow
   (controllers/hooks can only deny, never grant). `Vault User` is the doctype-level grant that
   membership then scopes. It is auto-assigned when a user first appears in any space's member
   table and confers nothing by itself on any row the user is not a member of.
2. **Tags and favorites use Frappe built-ins.** Tags = the standard `_user_tags` tag box (no
   custom field). Favorite = Frappe's standard Like (`_liked_by`), which is per-user — better
   than the brief's implied shared flag. No `tags`/`favorite` fields exist on the doctype.
3. **Masked fields store a plaintext last-4 hint.** `masked_hint` ("•••• 1234") is computed
   server-side on save and stored unencrypted so lists/forms can show the suffix without a
   reveal. This deliberately leaks the last 4 characters of masked fields (account numbers,
   card numbers) — exactly the semantics of `maskValue()` in the personal app's templates.ts.
4. **The generator RPC is not audit-logged.** A generated value belongs to no credential yet;
   logging it would create noise with no subject. Reveal/copy/import/create/update/delete are
   logged; generation is only rate-limited.
5. **Rotation reminders use a per-credential `last_reminded_on` date**, not a reminder-ledger
   doctype pair like `sssihms_hr`'s. One tier, one cadence — the ledger machinery is overkill
   here and would violate the simplicity rule.
6. **Reveal and copy are one RPC.** The client copies to clipboard itself; it passes
   `action="copy"` so the log distinguishes them. A separate endpoint would duplicate every
   check for zero security gain.
7. **Secret custom fields on `custom`-type credentials use the same child table** as template
   secrets — no separate mechanism.

---

## 1. DocType schemas

### 1.1 Decision: fixed columns vs child table for template fields

**Chosen: hybrid.** Fixed columns for the fields every credential has (`title`, `vault_space`,
`credential_type`, `username`, `url`, `notes`, one primary `password`), plus a child table
`Credential Secret Field` for all template-specific fields (netbanking alone has ~22).

Why not fixed columns per type: the union of all template fields is ~70 columns, mostly NULL,
and every new template is a schema migration. Why the child table is safe: Frappe's `Password`
fieldtype works identically on child-table fields — the value is encrypted with the site
encryption key and stored in the `__Auth` table keyed by (doctype, child-row name, fieldname);
the child row's own column holds only asterisks. `get_doc`/`get_list` never return the real
value; retrieval requires `frappe.utils.password.get_decrypted_password("Credential Secret
Field", row.name, "secret_value")`. Leakage surfaces closed explicitly:

- No secret field ever has `in_list_view`, `in_standard_filter`, `in_global_search`, or
  `search_index`.
- Every secret field carries `report_hide: 1`, `print_hide: 1`, `no_copy: 1`
  (`no_track` is **not** a real Frappe 16 docfield property — version tracking is disabled
  at the doctype level with `track_changes: 0`; see BRIEF §6)
  (belt-and-braces: Password values would only ever appear as asterisks in Versions/reports
  anyway, since the table column never holds plaintext).
- The parent controller enforces that a row with `is_secret=1` has an empty `value` (the plain
  Data column) — a secret can never land in a plaintext column by UI accident.
- `Credential Access Log` stores field *labels/keys*, never values.

Templates are defined as a Python constant (`vault/templates.py`, §1.8) — a direct port of
templates.ts. The Desk form script builds child rows from the template on type selection;
the server validates conformance but tolerates extra rows (that is how `custom` works).

### 1.2 Vault Space

`password_vault/doctype/vault_space/vault_space.json`

| fieldname | fieldtype | options / notes | reqd | read_only | no_copy | other |
|---|---|---|---|---|---|---|
| space_name | Data | unique=1 | 1 | | | in_list_view, in_standard_filter |
| description | Small Text | | | | | |
| disabled | Check | default 0 | | | | in_list_view. Disabled space: no reveals, no edits, reads still allowed |
| members | Table | Credential Space Member → **Vault Space Member** | | | | |

- `autoname: "field:space_name"`, `allow_rename: 0`, `track_changes: 1`.
- `naming_rule: "By fieldname"`; `title_field: space_name`; `search_fields: "space_name"`.

Controller (`vault_space.py`):
- `validate()`: (a) no duplicate `user` across member rows; (b) if the space has members, at
  least one must be `Manager` — `frappe.throw` otherwise (Vault Admin can always administer,
  but an unmanageable space is a config error, not a fallback); (c) each member row that is
  new gets `added_by = frappe.session.user`, `added_on = now()`.
- `on_update()`: ensure every member user holds the `Vault User` role — `frappe.get_doc("User",
  u).add_roles("Vault User")` guarded by an exists-check (role assignment needs
  `ignore_permissions`; deliberate: membership is granted by a Manager/Admin who may not be
  User-doctype-privileged, and the role confers nothing without membership).
- `on_update()` second duty: diff member rows against `get_doc_before_save()` and write one
  `Credential Access Log` row per added/removed/level-changed member (`action="membership"`,
  details in `detail` field). Membership changes are security events.
- `on_trash()`: `frappe.throw` if any `Vault Credential` links to this space. No cascade.

Permissions (JSON `permissions` array):

| role | read | write | create | delete | notes |
|---|---|---|---|---|---|
| Vault Admin | 1 | 1 | 1 | 1 | export 1, report 1 |
| Vault User | 1 | 1 | 0 | 0 | narrowed by hooks: read → member, write → Manager (§2) |
| Vault Auditor | 1 | 0 | 0 | 0 | report 1 — needs space names to filter log reports; sees membership, never credentials |

### 1.3 Vault Space Member (child)

`istable: 1`, `editable_grid: 1`, `autoname: hash`.

| fieldname | fieldtype | options | reqd | read_only | no_copy | other |
|---|---|---|---|---|---|---|
| user | Link | User | 1 | | | in_list_view, columns 4 |
| access_level | Select | `Reader\nEditor\nManager` | 1 | | | default `Reader`, in_list_view |
| added_by | Link | User | | 1 | 1 | |
| added_on | Datetime | | | 1 | 1 | |

No permissions array (child tables inherit the parent's).

### 1.4 Vault Credential

`password_vault/doctype/vault_credential/vault_credential.json`
`autoname: "format:VC-{#####}"`, `naming_rule: "Expression"`, `allow_rename: 0`,
`track_changes: 1`, `title_field: title`, `search_fields: "title,username,url"`,
`sort_field: modified`, `sort_order: DESC`.

| fieldname | fieldtype | options / notes | reqd | read_only | no_copy | secret handling |
|---|---|---|---|---|---|---|
| title | Data | | 1 | | | in_list_view |
| vault_space | Link | Vault Space | 1 | | | in_list_view, in_standard_filter, search_index. Immutable after insert (validate blocks change — moving a credential between spaces silently changes who can read it; delete + recreate instead) |
| credential_type | Select | `login\nnetbanking\nupi\ncard\ndemat\ngovid\nnote\nwifi\ninsurance\ncustom` | 1 | | | default `login`, in_list_view, in_standard_filter. Immutable after insert |
| username | Data | | | | | in_list_view |
| url | Data | options: `URL` | | | | |
| notes | Text | description: "Never put secrets here — this field is plaintext and appears in versions." | | | | |
| password | Password | primary secret; counts toward health | | | 1 | report_hide 1, print_hide 1 (doctype `track_changes: 0`) |
| secret_fields | Table | **Credential Secret Field** | | | | |
| expiry_date | Date | credential/document expiry | | | | in_standard_filter |
| rotation_due | Date | | | | | in_standard_filter, search_index |
| rotation_interval_days | Int | 0 = no auto schedule | | | | |
| last_rotated | Date | | | 1 | 1 | set by controller when `password` or any secret child changes |
| last_reminded_on | Date | scheduler bookkeeping (§8) | | 1 | 1 | hidden 1 |

Controller (`vault_credential.py`):
- `validate()`:
  - Block `vault_space` / `credential_type` change after insert (compare `get_doc_before_save()`).
  - Child-row hygiene: for each `secret_fields` row, if `is_secret` then `frappe.throw` when
    `value` is non-empty; `field_key` unique within the credential; `field_kind in` the allowed
    Select set.
  - Template conformance (soft): for non-`custom` types, warn (msgprint, not throw) on child
    `field_key`s absent from `TEMPLATES[credential_type]` — extra rows are legal, typos should
    be visible.
  - Rotation: if the primary `password` changed (detect via `self.password` not being the
    asterisk placeholder AND differing — see implementation note below) or any secret child
    changed, set `last_rotated = today()`; if `rotation_interval_days`, set
    `rotation_due = today() + interval` and clear `last_reminded_on`.
  - **Implementation note (Password change detection):** on form save Frappe sends the real
    new value in `self.password` only when the user typed one; an untouched Password field
    round-trips as `"*"*n` or None. Treat "changed" as: value present and not all-asterisks.
    Same rule per child `secret_value`.
  - Compute `masked_hint` on each child row with `is_masked=1` and a freshly supplied secret:
    last 4 non-space chars, `f"•••• {tail}"`.
- `after_insert()`: `write_access_log(self, action="create")`.
- `on_update()`: if not new, `write_access_log(self, action="update")` — field values are
  never logged, only that an update happened (Versions carry the non-secret diff).
- `on_trash()`: `write_access_log(self, action="delete")`. Log rows survive the delete via
  `ignore_links_on_delete` (§1.6).

Permissions:

| role | read | write | create | delete | export | report |
|---|---|---|---|---|---|---|
| Vault Admin | 1 | 1 | 1 | 1 | 1 | 1 |
| Vault User | 1 | 1 | 1 | 1 | 0 | 1 |

`Vault User`'s grants are ceilings; §2's hooks narrow them to membership level per row.
`Vault Auditor` has **no row** on this doctype — auditors never read credentials, even
metadata. Export is Vault-Admin-only (a report export of the doctype leaks structure; secrets
would export as asterisks, but titles/usernames/URLs of every space is still too much for a
non-admin).

### 1.5 Credential Secret Field (child)

`istable: 1`, `editable_grid: 1`, `autoname: hash`, `track_changes: 0`.

| fieldname | fieldtype | options | reqd | read_only | no_copy | secret handling |
|---|---|---|---|---|---|---|
| field_key | Data | template key, e.g. `transactionPassword` | 1 | | | in_list_view |
| label | Data | display label | 1 | | | in_list_view |
| field_kind | Select | `text\npassword\npin\nemail\nphone\nurl\ndate\nnumber\nmultiline` | 1 | | | default `text` |
| is_secret | Check | value lives in `secret_value` | | | | in_list_view |
| is_masked | Check | show last-4 hint | | | | |
| is_password | Check | counts toward health analysis | | | | |
| value | Data | ONLY for `is_secret=0` rows | | | | |
| secret_value | Password | ONLY for `is_secret=1` rows | | | 1 | report_hide 1, print_hide 1, never in_list_view (doctype `track_changes: 0`) |
| masked_hint | Data | "•••• 1234", server-computed | | 1 | 1 | |
| warning | Small Text | template warning text, informational | | | | |

### 1.6 Credential Access Log

`password_vault/doctype/credential_access_log/credential_access_log.json`
`autoname: hash`, `in_create: 1` (no "New" button), `track_changes: 0`, `allow_rename: 0`,
`sort_field: timestamp`, `sort_order: DESC`. Modeled on `Staff Document Access` in sssihms_hr.

| fieldname | fieldtype | options | reqd | read_only | no_copy | other |
|---|---|---|---|---|---|---|
| credential | Link | Vault Credential | | 1 | 1 | not reqd — survives credential deletion as a dangling name (see hooks note) |
| credential_title | Data | snapshot at log time | 1 | 1 | 1 | in_list_view |
| vault_space | Link | Vault Space | 1 | 1 | 1 | in_list_view, in_standard_filter |
| action | Select | `reveal\ncopy\ncreate\nupdate\ndelete\nimport\nmembership\nhealth_report` | 1 | 1 | 1 | in_list_view, in_standard_filter |
| outcome | Select | `success\ndenied` | 1 | 1 | 1 | default `success`, in_list_view, in_standard_filter |
| field_key | Data | which secret was revealed | | 1 | 1 | |
| field_label | Data | | | 1 | 1 | in_list_view |
| user | Link | User | 1 | 1 | 1 | in_list_view, in_standard_filter |
| timestamp | Datetime | | 1 | 1 | 1 | in_list_view, search_index |
| ip_address | Data | `frappe.local.request_ip` | | 1 | 1 | |
| detail | Small Text | free-form context (e.g. "imported 42 rows", denial reason). NEVER a secret value. | | 1 | 1 | |

Permissions — read-only for everyone, creatable by no role (creation is controller-only):

| role | read | write | create | delete | report | export |
|---|---|---|---|---|---|---|
| System Manager | 1 | 0 | 0 | 0 | 1 | 1 |
| Vault Admin | 1 | 0 | 0 | 0 | 1 | 1 |
| Vault Auditor | 1 | 0 | 0 | 0 | 1 | 1 |

Controller: §4. Note: `Vault User` (space managers) reach per-space log data through the
scoped Script Report (§3/§6-adjacent), not through direct doctype read.

### 1.7 Vault Settings (Single)

`issingle: 1`.

| fieldname | fieldtype | default | notes |
|---|---|---|---|
| rotation_reminders_enabled | Check | 1 | master switch for the daily job |
| reminder_repeat_days | Int | 7 | re-notify cadence while overdue |
| reveal_auto_hide_seconds | Int | 30 | client hint only: form script re-masks after N s |
| default_password_length | Int | 20 | generator UI default |
| default_passphrase_words | Int | 5 | generator UI default |

Permissions: Vault Admin read/write; Vault User read (the form script needs the defaults).
Rate-limit numbers are **code constants** (§3), not settings — a limit an admin can raise from
the UI is not a limit.

### 1.8 Templates constant (not a doctype)

`vault/templates.py` — direct port of templates.ts. Owned by PACKAGE A (the credential
controller validates against it); PACKAGE B imports it for health. Pinned shape:

```python
TEMPLATES: dict[str, dict] = {
  "login": {"label": "Login", "icon": "🔑", "fields": [
      {"key": "username", "label": "Username / email", "kind": "text"},
      {"key": "password", "label": "Password", "kind": "password", "sensitive": True, "is_password": True},
      {"key": "url", "label": "Website URL", "kind": "url"},
      {"key": "totpNote", "label": "2FA / TOTP note", "kind": "text"},
  ]},
  # ... netbanking, upi, card, demat, govid, note, wifi, insurance, custom —
  # transcribe every field, flag (sensitive→is_secret, masked→is_masked,
  # isPassword→is_password), placeholder and warning string verbatim from
  # reference/from-personal-password-manager/templates.ts. "custom" has fields: [].
}
```

Mapping rule for the form script and CSV import: template `sensitive` → child `is_secret`,
`masked` → `is_masked`, `isPassword` → `is_password`, `kind` → `field_kind`. For the `login`
template specifically, `username`/`url`/`password` map to the parent's fixed columns, not
child rows; every other template maps entirely to child rows except that its first
`is_password` field also mirrors into the parent `password` column? **No — decided against
mirroring** (two copies of one secret drift). The parent `password` column is used by `login`,
`wifi` (primary Wi-Fi password) and CSV imports; all other templates keep every secret in
child rows and leave parent `password` empty. Health (§6) scans both locations, so nothing
is missed either way.

---

## 2. Permission model

### 2.1 Roles (created in `install.py`, idempotent, mirroring sssihms_hr's `_create_custom_roles`)

- **Vault Admin** — app administrator: creates spaces, sees every credential, manages
  settings. Does NOT get audit-log delete (nobody below System Manager console access does).
- **Vault Auditor** — reads `Credential Access Log` and `Vault Space` (names/membership).
  Zero access to `Vault Credential` — no DocPerm row at all, and reveal denies by role
  before membership is even consulted (defense in depth; an auditor added to a space by
  mistake still cannot reveal).
- **Vault User** — base grant narrowed per-row by hooks. Auto-assigned on membership (§1.2).

`install.py` `after_install()`: create the three roles; create the Module Def if missing;
`frappe.db.commit()`.

### 2.2 DocPerm JSON — summarized in each doctype table above (§1.2, §1.4, §1.6, §1.7)

### 2.3 `hooks.py` registrations (owned by PACKAGE A — PACKAGE B never edits hooks.py)

```python
has_permission = {
    "Vault Credential": "sssihms_password_vault.vault.permissions.credential_has_permission",
    "Vault Space": "sssihms_password_vault.vault.permissions.space_has_permission",
}
permission_query_conditions = {
    "Vault Credential": "sssihms_password_vault.vault.permissions.credential_query_conditions",
    "Vault Space": "sssihms_password_vault.vault.permissions.space_query_conditions",
}
# Log rows must outlive the credential they log (same mechanism as Staff Document
# Access in sssihms_hr — Codex finding #9 pattern).
ignore_links_on_delete = ["Credential Access Log"]
scheduler_events = {"daily": ["sssihms_password_vault.vault.reminders.daily_rotation_sweep"]}
after_install = "sssihms_password_vault.install.after_install"
```

### 2.4 `vault/permissions.py` (PACKAGE A)

```python
LEVEL_RANK = {"Reader": 1, "Editor": 2, "Manager": 3}

def get_membership_level(user: str, space: str) -> str | None:
    """Highest access_level of `user` in `space`, or None. Cached per-request
    via frappe.local. The single source of truth — reveal, reports, CSV import
    and hooks all call this."""

def is_vault_admin(user: str) -> bool:
    return bool({"Vault Admin", "System Manager"} & set(frappe.get_roles(user)))
```

`credential_query_conditions(user)` — returns SQL appended to every `get_list`/list view/
report query (values escaped with `frappe.db.escape`, never f-string interpolation of raw
input; `user` comes from Frappe, but escape anyway):

```python
def credential_query_conditions(user: str | None = None) -> str:
    user = user or frappe.session.user
    if is_vault_admin(user):
        return ""
    # Auditor or role-less account: no membership rows -> EXISTS matches nothing -> sees nothing.
    return (
        "exists (select 1 from `tabVault Space Member` vsm "
        "where vsm.parenttype = 'Vault Space' "
        "and vsm.parent = `tabVault Credential`.vault_space "
        "and vsm.user = {user})"
    ).format(user=frappe.db.escape(user))
```

`space_query_conditions(user)` — Vault Admin: `""`. **Vault Auditor: `""`** (needs space list
for log filtering; a space's existence and membership is not a secret from the auditor).
Otherwise:

```python
    return (
        "exists (select 1 from `tabVault Space Member` vsm "
        "where vsm.parenttype = 'Vault Space' and vsm.parent = `tabVault Space`.name "
        "and vsm.user = {user})"
    ).format(user=frappe.db.escape(user))
```

`credential_has_permission(doc, ptype, user)` — called by Frappe for single-doc access
(get_doc, save, delete). Returns False to deny, True to fall through to DocPerms:

| ptype | requirement |
|---|---|
| read, report, print, email | membership at any level (or vault admin) |
| create, write | `Editor`+ ; deny if space `disabled` |
| delete | `Manager` ; deny if space `disabled` |
| everything else (export, share, import) | vault admin only |

For `create`, `doc.vault_space` is set by the time the hook runs on insert; if empty, deny
(validate would throw anyway, but the hook must not approve an unscoped doc).

`space_has_permission(doc, ptype, user)` — read: member, auditor, or admin; write:
`Manager` of that space or admin (this is how a space Manager edits the member table without
Vault-Admin help); create/delete: admin only.

**How "no membership sees nothing" holds:** list/report queries get the EXISTS condition,
which matches zero rows for a user with no `Vault Space Member` rows; direct `get_doc` by
guessed name hits `credential_has_permission` → `get_membership_level` → None → False.
Both paths are ORM-level, independent of any UI.

**How "Vault Auditor sees logs but never secrets" holds:** (a) no DocPerm row on Vault
Credential ⇒ Frappe denies before hooks run; (b) `reveal_secret` (§3) independently rejects
any caller whose membership level is below Reader — auditor-ness never substitutes for
membership; (c) the log doctype stores labels and titles, never values; (d) the health report
denies auditors (it exposes weakness *facts* about secrets — manager/admin only).

---

## 3. Whitelisted API surface

All in `vault/api.py` (PACKAGE A) except where noted. Every function:
`@frappe.whitelist(methods=["POST"])` (GET only for the two pure lookups noted), explicit
permission checks first, **no `ignore_permissions=True` anywhere except audit-log inserts and
role assignment**, and no secret ever placed in an exception message, log line, or traceback
string. Rate limits use `from frappe.rate_limiter import rate_limit` (decorator; keyed by
IP+path in Frappe's implementation — accepted; per-user granularity is not worth a custom
limiter in V1).

| function | args | perm check | rate limit | logs |
|---|---|---|---|---|
| `reveal_secret` | `credential: str, field_key: str, action: str = "reveal"` | member (any level) of the credential's space; space not disabled; `action in ("reveal","copy")` | `@rate_limit(limit=30, seconds=300)` | one row BEFORE returning; denied attempts logged with `outcome="denied"` BEFORE the throw |
| `get_templates` | — (GET ok) | any authenticated user with Vault User/Admin role | none | no |
| `generate_credential_secret` | `kind: str ("password"\|"passphrase"\|"pin"), options: dict` | Vault User or Vault Admin role | `@rate_limit(limit=60, seconds=300)` | no (Deviation 4) |
| `import_credentials_csv` | `vault_space: str, csv_text: str` | `Editor`+ in that space; space not disabled | `@rate_limit(limit=5, seconds=3600)` | one `action="import"` row with counts in `detail` (PACKAGE B, §7) |
| `run_health_check` | — (Script Report, not RPC; §6) | Manager/admin inside `execute()` | n/a | one `action="health_report"` row per run |

### `reveal_secret` — exact flow (order is load-bearing)

```python
@frappe.whitelist(methods=["POST"])
@rate_limit(limit=30, seconds=300)
def reveal_secret(credential: str, field_key: str, action: str = "reveal") -> dict:
    if action not in ("reveal", "copy"):
        frappe.throw(_("Invalid action."))
    doc = frappe.get_doc("Vault Credential", credential)   # raises 404 if absent

    level = get_membership_level(frappe.session.user, doc.vault_space)
    denied_reason = None
    if is_vault_auditor_only(frappe.session.user):          # (b) in §2.4 — auditors never reveal
        denied_reason = "auditor role cannot reveal secrets"
    elif level is None and not is_vault_admin(frappe.session.user):
        denied_reason = "not a member of this space"
    elif frappe.db.get_value("Vault Space", doc.vault_space, "disabled"):
        denied_reason = "space is disabled"

    field_label = _resolve_field_label(doc, field_key)      # "password" or a child row

    if denied_reason:
        # Log the denial BEFORE throwing — a failed grab attempt is the most
        # interesting row in the whole log.
        write_access_log(doc, action=action, outcome="denied",
                         field_key=field_key, field_label=field_label,
                         detail=denied_reason)
        frappe.db.commit()
        frappe.throw(_("You do not have permission to reveal this secret."),
                     frappe.PermissionError)

    # ---- Log BEFORE decrypting/returning (BRIEF security req 2b). ----
    write_access_log(doc, action=action, outcome="success",
                     field_key=field_key, field_label=field_label)
    # Deliberate explicit commit: Frappe commits at request end, but if anything
    # after this point raises, the reveal attempt must still be on record. A log
    # row for a reveal that then failed is acceptable; a reveal without a log
    # row is not.
    frappe.db.commit()

    if field_key == "password":
        value = get_decrypted_password("Vault Credential", doc.name, "password",
                                       raise_exception=False) or ""
    else:
        row = next(r for r in doc.secret_fields if r.field_key == field_key)
        if row.is_secret:
            value = get_decrypted_password("Credential Secret Field", row.name,
                                           "secret_value", raise_exception=False) or ""
        else:
            value = row.value or ""   # non-secret fields go through the same
                                      # audited path when the UI asks — cheap uniformity
    return {"value": value, "field_label": field_label,
            "auto_hide_seconds": frappe.db.get_single_value(
                "Vault Settings", "reveal_auto_hide_seconds")}
```

`write_access_log(credential_doc, *, action, outcome="success", field_key=None,
field_label=None, detail=None)` lives in `vault/audit.py` (PACKAGE A) and is the ONLY code
path that inserts log rows: builds the doc with snapshot `credential_title`, `vault_space`,
`user=frappe.session.user`, `timestamp=now()`, `ip_address=frappe.local.request_ip`, then
`.insert(ignore_permissions=True)` — deliberate: no role has `create` on the log doctype
precisely so nothing but this function can write it. It also accepts
`credential_doc=None, vault_space="..."` for space-level events (membership, import).

`generate_credential_secret` parses `options` (JSON dict from the client), whitelists the
known keys per kind, and dispatches to the pure functions in §5. Unknown keys are ignored,
values are clamped (length ≤ 128, words ≤ 12, pin digits 4–12).

---

## 4. Audit log integrity

Layered so that no single mistake reopens it:

1. **DocPerms** (§1.6): no role has write/create/delete. `in_create: 1` removes the New
   button. Creation happens only via `write_access_log`'s `ignore_permissions` insert.
2. **Controller** (`credential_access_log.py`):

```python
class CredentialAccessLog(Document):
    def validate(self):
        if not self.is_new():
            # Codex-finding style: append-only means append-only. Even System
            # Manager edits are blocked at the controller; there is no
            # legitimate reason to rewrite history.
            frappe.throw(_("Access log rows cannot be modified."))

    def on_trash(self):
        # System Manager override is deliberate and console-only:
        #   bench --site <site> console
        #   >>> frappe.flags.vault_audit_delete_override = True
        #   >>> frappe.delete_doc("Credential Access Log", name)
        # The flag cannot be set over HTTP — no whitelisted method sets it —
        # so the override requires System Manager plus either shell access or Script
        # Manager (a Server Script of type API can set a flag and call delete_doc over
        # HTTP — corrected 2026-08-24, audit L3), which is the
        # correct bar for destroying audit evidence.
        if not (
            "System Manager" in frappe.get_roles(frappe.session.user)
            and frappe.flags.get("vault_audit_delete_override")
        ):
            frappe.throw(_("Access log rows cannot be deleted."), frappe.PermissionError)
        frappe.logger("sssihms_password_vault").warning(
            f"AUDIT OVERRIDE: {frappe.session.user} deleted access log row {self.name}"
        )
```

3. Not submittable ⇒ no amend path exists. `allow_rename: 0`, `track_changes: 0` (a Version
   of a log row is itself a mutation vector and adds nothing).
4. Bulk delete via "Delete" in list view hits `on_trash` per row — same block. Direct
   `frappe.db.delete` from custom code is out of scope of any framework guard; the rule for
   this app is that no code in it may call `frappe.db.delete/sql` against the log table, and
   review enforces it.

---

## 5. Generator port (`vault/generator.py`, PACKAGE B)

Pure functions, no Frappe imports, all randomness from the stdlib `secrets` module.
`secrets.randbelow(n)` is rejection-sampled and unbiased — the exact analogue of libsodium's
`randombytes_uniform`. **Never `random.*`, never `random.shuffle`** (Mersenne Twister); the
Fisher–Yates shuffle is hand-written over `secrets.randbelow`.

```python
SETS = {
    "lower": "abcdefghijklmnopqrstuvwxyz",
    "upper": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "digits": "0123456789",
    "symbols": "!@#$%^&*()-_=+[]{};:,.?/",
}
AMBIGUOUS = set("0O1lI|")

def generate_password(length: int = 20, lower: bool = True, upper: bool = True,
                      digits: bool = True, symbols: bool = True,
                      exclude_ambiguous: bool = True) -> str:
    """Semantics identical to generator.ts:
    - pools = selected sets, each stripped of AMBIGUOUS when exclude_ambiguous;
    - raise ValueError if no set selected;
    - effective length = max(length, number_of_selected_sets, 8);
    - guarantee >=1 char from each selected set (one secrets.randbelow pick per
      cleaned pool), fill the rest uniformly from the concatenation, then
      Fisher-Yates shuffle with secrets.randbelow."""

def generate_passphrase(words: int = 5, separator: str = "-",
                        capitalize: bool = True, include_number: bool = True) -> str:
    """EFF short wordlist 2.0 (WORDLIST, vault/wordlist.py). n = max(3, words).
    Capitalize each word if set; if include_number, append str(secrets.randbelow(100))
    to ONE word at a secrets.randbelow(n) position; join with separator."""

def generate_pin(digits: int = 6) -> str:
    """''.join(str(secrets.randbelow(10)) for _ in range(digits)) — leading
    zeros legal, exactly as generator.ts."""
```

**Wordlist decision:** vendor EFF short wordlist 2.0 (1,296 words, 4 dice / ~10.34 bits per
word) into `vault/wordlist.py` as `WORDLIST: tuple[str, ...]`. Source:
`https://www.eff.org/files/2016/09/08/eff_short_wordlist_2_0.txt` (strip the dice-roll
column). Vendored because the bench VM is proxy-restricted and a runtime fetch is both a
dependency and a tamper surface. PACKAGE B commits the full literal; a unit test asserts
`len(WORDLIST) == 1296` and all-lowercase-ASCII.

---

## 6. Health report

**Artifact: Script Report** (`password_vault/report/vault_health/`, `is_standard: "Yes"`,
`ref_doctype: "Vault Credential"`, report_type "Script Report"). Chosen over a Page because
execute() is server-side Python (decryption never touches the client), and filters, column
rendering, and export come free. A Page would re-implement all of that for no gain.

- Report roles: `Vault Admin`, `Vault User`. First lines of `execute(filters)` re-check:
  the `vault_space` filter is mandatory for non-admins and the caller must be `Manager` of it
  (`get_membership_level`); Vault Admin may omit it for org-wide. A disabled space is
  refused for non-admins — the report decrypts everything in scope, so running it over an
  archived space is a reveal in all but name.
  **Corrected 2026-08-24 (audit L2):** the roles list does *not* exclude an auditor —
  `Vault User` is auto-granted to every space member, so an auditor who is also a space
  Manager passes both the roles list and the Manager check. `execute()` therefore denies
  `is_vault_auditor_only` explicitly as its first act, rather than relying on the
  per-document `has_permission` loop returning an empty set two layers downstream.
- `execute()` (logic in `vault/health.py`, thin report wrapper around it):
  1. `frappe.get_all("Vault Credential", filters=..., fields=["name"])` to get candidate
     names, then an explicit `frappe.has_permission(..., doc=name, user=user)` per name.
     **Corrected 2026-08-24 (audit L1):** this step used to claim that `get_all` applies
     the query conditions and that `get_doc` keeps `has_permission` in force. Neither is
     true — `frappe.get_all` sets `ignore_permissions=True` unconditionally, and
     `frappe.get_doc` checks nothing. The per-name `has_permission` call is the *only*
     thing scoping this report, which makes it load-bearing and not a belt-and-braces
     re-check. Never `ignore_permissions` anywhere in this path.
  2. For each credential: decrypt parent `password` and every child row with
     `is_password=1` (and `is_secret=1`) via `get_decrypted_password`. Port of
     `health.ts::passwordUses`.
  3. Score each value with `estimate_strength(password) -> (strength, bits)` — direct port
     of `health.ts::estimateStrength` including `COMMON_PASSWORDS` (same 28 entries),
     pool-size entropy, the all-one-char / sequence-prefix / repeat-run penalties, and the
     28/45/65-bit thresholds.
  4. Reuse: group by `hashlib.sha256(value.encode()).hexdigest()` **in memory**; the dict of
     hashes is function-local and discarded. Groups of ≥2 get sequential ids R1, R2, ….
  5. **Rows returned to the client contain NO values and NO hashes**: columns =
     credential (Link), title, space, field_label, verdict (`very-weak/weak/fair/strong`),
     bits (Int), reused_group (`R1` or blank), reused_group_size (Int), rotation_status
     (`overdue/due soon/ok`), expiry_status. Summary block: total passwords, weak count,
     reused count, score 0–100 (same formula as `analyzeHealth`: `100 * (1 - |weak ∪
     reused| / total)`).
  6. `write_access_log(None, vault_space=..., action="health_report", detail="score=NN")`.
- Weak-only and reused-only slices are client-side column filters on the same report —
  no second report artifact.

---

## 7. CSV import (`vault/csv_import.py`, PACKAGE B; RPC listed in §3)

```python
@frappe.whitelist(methods=["POST"])
@rate_limit(limit=5, seconds=3600)
def import_credentials_csv(vault_space: str, csv_text: str) -> dict
```

- Permission: `get_membership_level(user, vault_space)` must be Editor/Manager (or vault
  admin); space must exist and not be disabled. Checked before any parsing.
- Parsing: stdlib `csv.reader(io.StringIO(csv_text))` (RFC-4180 quoting/embedded newlines —
  no hand-rolled state machine needed in Python). First row = header, lowercased+trimmed,
  mapped through the alias table **ported verbatim from importCsv.ts**:

```python
HEADER_ALIASES = {
    "title": "title", "name": "title",
    "url": "url", "website": "url", "login uri": "url", "uri": "url",
    "username": "username", "user name": "username", "login": "username", "email": "username",
    "password": "password",
    "notes": "notes", "note": "notes",
    "otpauth": "otpauth", "otp auth": "otpauth", "totp": "otpauth", "otp secret": "otpauth",
}
MAX_IMPORT_ROWS = 5000
```

  First matching header wins per column (same first-index rule as the TS).
- Row handling (mirrors parseCsvToLoginItems): rows beyond MAX_IMPORT_ROWS →
  `truncated=True`, not processed; all-blank row → skip reason `"blank row"`; no
  title/username/password/url at all → skip `"no usable columns"`. Title fallback chain
  `title or url or username or "Imported login"`.
- Each accepted row → `frappe.get_doc({...}).insert()` — a **normal permission-checked
  insert** (`credential_type="login"`, parent `title/username/url/notes/password`;
  `otpauth` becomes one child row `{field_key: "otpauth", label: "2FA / TOTP (otpauth URI)",
  field_kind: "text", is_secret: 1}`). A per-row insert failure (validation error) is caught,
  the row skipped with reason `f"insert failed: {e.__class__.__name__}"` — **exception text
  is not included** (it could echo a field value).
- Single `write_access_log(None, vault_space=vault_space, action="import",
  detail=f"created={n} skipped={m} truncated={t}")` at the end, plus each insert's own
  `after_insert` create-row.
- Returns `{"created": n, "skipped": [{"row": i, "reason": r}, ...], "total_rows": t,
  "truncated": bool}` — row numbers are 1-based data-row indices matching the file the user
  is looking at (header excluded).
- `csv_text` arrives as a string (client reads the file with FileReader and posts text) —
  the file never lands in Frappe's File doctype, so no secret-bearing CSV sits in
  `/private/files`. The form script should remind the user to delete the source CSV.

---

## 8. Scheduler (`vault/reminders.py`, PACKAGE B)

`daily_rotation_sweep()` — registered in hooks.py (§2.3) by PACKAGE A:

1. Exit if `Vault Settings.rotation_reminders_enabled` is 0.
2. `frappe.get_all("Vault Credential", filters={"rotation_due": ("<=", today())},
   fields=["name", "title", "vault_space", "rotation_due", "last_reminded_on"],
   ignore_permissions... )` — **runs as Administrator in the scheduler; no
   ignore_permissions flag needed and none used.** Excludes credentials in disabled spaces
   (join via a second get_all on disabled spaces, filtered in Python).
3. Skip a credential if `last_reminded_on` is within `reminder_repeat_days` — the re-remind
   cadence, so overdue items nag weekly, not daily.
4. Group by `vault_space`; recipients = that space's `Manager`-level members (enabled Users
   only) plus nobody else. If a space has due items but zero enabled managers, fall back to
   all `Vault Admin` role holders and say so in the message.
5. Per space, send ONE digest: a `Notification Log` entry per recipient
   (`frappe.get_doc({"doctype": "Notification Log", ...}).insert(ignore_permissions=True)`)
   **and** `frappe.sendmail(recipients=..., subject=f"[Password Vault] {n} credential(s)
   overdue for rotation in {space}", message=<title + due date list>)`. Titles and due dates
   only — never usernames, URLs, or any secret.
6. `frappe.db.set_value("Vault Credential", name, "last_reminded_on", today(),
   update_modified=False)` per notified credential — deliberate direct write: this is
   bookkeeping, not an edit; it must not touch `modified`, fire `validate`, or clear
   anything (same pattern and reasoning as sssihms_hr's `verify()`).

---

## 9. File tree

`bench new-app` conventions, Frappe 16. Everything below is generated; (A)/(B) marks
ownership per §10.

```
sssihms-password-vault/
├── pyproject.toml                        (A)  # name="sssihms_password_vault", flit_core backend, no deps beyond frappe
├── license.txt                           (A)  # MIT
├── README.md                             (A)  # install: bench get-app + install-app + migrate (BRIEF restore procedure)
├── .gitignore                            (A)  # *.pyc, __pycache__, node_modules, .DS_Store
└── sssihms_password_vault/
    ├── __init__.py                       (A)  # __version__ = "0.0.1"
    ├── hooks.py                          (A)  # §2.3 — B NEVER edits this file
    ├── install.py                        (A)  # roles, §2.1
    ├── modules.txt                       (A)  # "Password Vault"
    ├── patches.txt                       (A)  # empty
    ├── config/__init__.py                (A)
    ├── public/.gitkeep                   (A)
    ├── vault/                                 # non-doctype server code
    │   ├── __init__.py                   (A)
    │   ├── permissions.py                (A)  # §2.4
    │   ├── audit.py                      (A)  # write_access_log, §3
    │   ├── api.py                        (A)  # reveal_secret, get_templates, generate_credential_secret (thin wrapper importing B's generator)
    │   ├── templates.py                  (A)  # §1.8 pinned constant
    │   ├── generator.py                  (B)  # §5
    │   ├── wordlist.py                   (B)  # §5, vendored EFF list
    │   ├── health.py                     (B)  # §6 logic (estimate_strength, collect_uses, analyze)
    │   ├── csv_import.py                 (B)  # §7
    │   └── reminders.py                  (B)  # §8
    └── password_vault/                        # module directory (module "Password Vault")
        ├── __init__.py                   (A)
        ├── doctype/
        │   ├── __init__.py               (A)
        │   ├── vault_space/              (A)  # .json + .py + __init__.py each
        │   ├── vault_space_member/       (A)
        │   ├── vault_credential/         (A)
        │   ├── credential_secret_field/  (A)
        │   ├── credential_access_log/    (A)
        │   └── vault_settings/           (A)
        └── report/
            ├── __init__.py               (A)
            ├── vault_health/             (B)  # vault_health.json + .py wrapper over vault/health.py
            │   └── __init__.py
            └── credential_access_report/ (A)  # Script Report: log rows scoped — auditor/admin all spaces, space Manager own spaces only (execute() check via get_membership_level)
                └── __init__.py

    tests live inside doctype dirs (Frappe convention) plus:
        vault/tests/__init__.py           (B)
        vault/tests/test_generator.py     (B)
        vault/tests/test_health.py        (B)
        vault/tests/test_csv_import.py    (B)  # pure-parse tests; insert path mocked/skipped without site
        password_vault/doctype/vault_credential/test_vault_credential.py   (B)  # FrappeTestCase: perms, reveal, audit
        password_vault/doctype/credential_access_log/test_credential_access_log.py (B)  # append-only proofs
```

Desk form scripts (`vault_credential.js` inside its doctype dir, PACKAGE A): build child rows
from `get_templates()` on type selection; "Reveal"/"Copy" buttons calling `reveal_secret`
with re-mask after `auto_hide_seconds`; "Generate" button calling
`generate_credential_secret` and writing into the focused Password field. No secret is ever
written into `localStorage`, route args, or `frappe.boot`.

---

## 10. Work split — two independent packages

### PACKAGE A — storage, permissions, audit, reveal
Scaffold (pyproject, hooks.py, install.py, modules.txt, README), all six doctypes
(JSON + controllers + form scripts), `permissions.py`, `audit.py`, `api.py`
(reveal_secret, get_templates, generate_credential_secret *wrapper*), `templates.py`,
`credential_access_report`.

### PACKAGE B — pure logic, report, import, scheduler, tests
`generator.py`, `wordlist.py`, `health.py`, `csv_import.py`, `reminders.py`, the
`vault_health` Script Report, and ALL tests (both packages' logic — B owns the test tree).

### Pinned interfaces (the contract; neither package may rename these)

| name | owner | consumers |
|---|---|---|
| Doctype names: `Vault Space`, `Vault Space Member`, `Vault Credential`, `Credential Secret Field`, `Credential Access Log`, `Vault Settings` | A | B |
| Every fieldname exactly as tabled in §1 (notably `vault_space`, `credential_type`, `password`, `secret_fields`, `field_key`, `is_secret`, `is_password`, `secret_value`, `rotation_due`, `last_reminded_on`, `rotation_reminders_enabled`, `reminder_repeat_days`) | A | B |
| `vault.permissions.get_membership_level(user, space) -> str \| None`, `is_vault_admin(user) -> bool` | A | B (health, csv_import) |
| `vault.audit.write_access_log(credential_doc, *, action, outcome="success", field_key=None, field_label=None, detail=None, vault_space=None)` | A | B (csv_import, health, reminders) |
| `vault.templates.TEMPLATES` (§1.8 shape) | A | B (health) |
| `vault.generator.generate_password / generate_passphrase / generate_pin` (§5 signatures) | B | A (api.py wrapper) |
| `vault.reminders.daily_rotation_sweep` (no args) | B | A (hooks.py points at it — A writes the string path, B provides the function) |
| Role names `Vault Admin`, `Vault Auditor`, `Vault User`; levels `Reader/Editor/Manager` | A | B |
| Access-log `action` Select values (§1.6) | A | B |

Shared-file rule: **A owns hooks.py, modules.txt, pyproject.toml, and every `__init__.py` it
creates; B adds only new files listed as (B) in §9.** The only cross-package imports are the
pinned ones above, all `import`-at-call-site-safe (no import cycles: B never imports
`api.py`; A's `api.py` imports B's `generator` lazily inside the function body so PACKAGE A
is testable before B lands).

Test command (BRIEF): `bench --site <site> run-tests --app sssihms_password_vault`. Pure
modules (generator, health scoring, csv parsing) must also run under plain
`python -m pytest sssihms_password_vault/vault/tests/` with no bench — keep them free of
frappe imports except inside the functions that genuinely need them (csv_import splits its
pure `parse_csv_rows(csv_text) -> ParseResult` from the inserting RPC for exactly this
reason).
