"""Row-level access control for Vault Credential and Vault Space.

Wired into Frappe through ``hooks.py`` (``has_permission`` and
``permission_query_conditions``). Both halves are needed:

* ``*_has_permission`` gates single-document access — ``frappe.get_doc``, save, delete.
* ``*_query_conditions`` gates SQL-backed list/report queries, which ``has_permission``
  never sees.

Both are ORM-level, so a user with no ``Vault Space Member`` row sees nothing regardless
of what the UI asks for: list queries get an ``EXISTS`` clause that matches zero rows, and
a direct ``get_doc`` on a guessed ``VC-#####`` name resolves to no membership level and is
denied.

Frappe controllers and hooks can only ever *deny*, never grant beyond the role-based
DocPerm rows. Everything here therefore narrows the ``Vault User`` ceiling declared in the
doctype JSON; it cannot widen anything.
"""

from __future__ import annotations

import frappe

#: Access levels, ordered. Compared by rank, never by string equality, so "at least
#: Editor" stays one readable expression.
LEVEL_RANK: dict[str, int] = {"Reader": 1, "Editor": 2, "Manager": 3}

#: Permission types that only need membership at any level. Deliberately does not include
#: ``export``, ``share`` or ``import``: a report export of Vault Credential leaks the
#: titles, usernames and URLs of every credential in every space the caller can read, and
#: ``share`` would let a member hand access to a non-member, routing around the membership
#: table that is the whole access model. Those are Vault-Admin-only.
_READ_PTYPES = frozenset({"read", "report", "print", "email", "select"})

_ADMIN_ROLES = frozenset({"Vault Admin", "System Manager"})


# --------------------------------------------------------------------- membership


def _membership_cache() -> dict:
    """Per-request memo. ``frappe.local`` is torn down at the end of every request/job,
    so a membership change is never visible as stale data to the *next* request — and
    within one request the list view can ask about the same (user, space) pair dozens of
    times."""
    cache = getattr(frappe.local, "vault_membership_cache", None)
    if cache is None:
        cache = {}
        frappe.local.vault_membership_cache = cache
    return cache


def get_membership_level(user: str, space: str) -> str | None:
    """Highest ``access_level`` held by ``user`` in ``space``, or None if not a member.

    The single source of truth for membership: the permission hooks, ``reveal_secret``,
    the CSV import, the health report and the access report all call this and nothing else.

    Queried through ``frappe.qb`` rather than ``frappe.get_all`` for two reasons: querying
    a child doctype through ``get_all`` needs a ``parent`` argument and drags the whole
    permission machinery into a function the permission machinery itself calls (a
    re-entrancy hazard), and the query builder parameterises its literals so there is no
    string interpolation of ``user`` anywhere.
    """
    if not user or not space:
        return None

    cache = _membership_cache()
    key = (user, space)
    if key in cache:
        return cache[key]

    member = frappe.qb.DocType("Vault Space Member")
    rows = (
        frappe.qb.from_(member)
        .select(member.access_level)
        .where(
            (member.parenttype == "Vault Space")
            & (member.parent == space)
            & (member.user == user)
        )
    ).run(as_dict=True)

    best: str | None = None
    for row in rows:
        level = row.get("access_level")
        if level in LEVEL_RANK and (best is None or LEVEL_RANK[level] > LEVEL_RANK[best]):
            best = level

    cache[key] = best
    return best


def has_level(user: str, space: str, minimum: str) -> bool:
    """True when ``user``'s membership in ``space`` is at least ``minimum``."""
    level = get_membership_level(user, space)
    return level is not None and LEVEL_RANK[level] >= LEVEL_RANK[minimum]


def get_managed_spaces(user: str) -> list[str]:
    """Every space in which ``user`` holds Manager level. Used by the scoped access report
    (and by anything else that needs "the spaces this person administers")."""
    member = frappe.qb.DocType("Vault Space Member")
    rows = (
        frappe.qb.from_(member)
        .select(member.parent)
        .distinct()
        .where(
            (member.parenttype == "Vault Space")
            & (member.user == user)
            & (member.access_level == "Manager")
        )
    ).run(as_dict=True)
    return [row["parent"] for row in rows if row.get("parent")]


# --------------------------------------------------------------------- role tests


def is_vault_admin(user: str) -> bool:
    return bool(_ADMIN_ROLES & set(frappe.get_roles(user)))


def is_vault_auditor(user: str) -> bool:
    return "Vault Auditor" in frappe.get_roles(user)


def is_vault_auditor_only(user: str) -> bool:
    """True when ``user`` holds the auditor role and is not a Vault Admin.

    Auditor-ness is a *disqualification* from revealing, not merely an absence of
    permission — separation of duties (BRIEF security requirement 3): the person who reads
    the access log is not the person who reads the secrets. So this returns True even for
    an auditor who also happens to hold ``Vault User`` and a space membership. That is
    deliberate: ``Vault User`` is auto-assigned the moment anyone is added to a space's
    member table, so a narrower "auditor *and nothing else*" test would evaporate for
    exactly the case DESIGN.md §2.4(b) names — an auditor added to a space by mistake.
    Vault Admin wins, because an admin is expected to hold every capability.
    """
    if is_vault_admin(user):
        return False
    return is_vault_auditor(user)


def space_is_disabled(space: str) -> bool:
    """A disabled space is read-only and reveal-free: an archived department's credentials
    stay visible for reference but cannot be edited or decrypted."""
    return bool(frappe.db.get_value("Vault Space", space, "disabled"))


# ------------------------------------------------------- permission query conditions


def credential_query_conditions(user: str | None = None) -> str:
    """SQL appended to every Vault Credential list/report query.

    A caller with no membership rows matches nothing, so a Vault Auditor (no DocPerm row
    on this doctype at all) and a role-less account both see an empty list rather than an
    error. ``user`` comes from Frappe, not from request input, but it is escaped anyway —
    there is no version of this file in which a raw value is interpolated into SQL.
    """
    user = user or frappe.session.user
    if is_vault_admin(user):
        return ""
    return (
        "exists (select 1 from `tabVault Space Member` vsm "
        "where vsm.parenttype = 'Vault Space' "
        "and vsm.parent = `tabVault Credential`.vault_space "
        "and vsm.user = {user})"
    ).format(user=frappe.db.escape(user))


def space_query_conditions(user: str | None = None) -> str:
    """SQL appended to every Vault Space list/report query.

    Vault Auditor sees every space: the access-log reports filter by space, so an auditor
    who cannot enumerate space names cannot do the job. A space's name and membership are
    not secrets from the auditor — its credentials are, and those live behind
    ``credential_query_conditions`` and a missing DocPerm row.
    """
    user = user or frappe.session.user
    if is_vault_admin(user) or is_vault_auditor(user):
        return ""
    return (
        "exists (select 1 from `tabVault Space Member` vsm "
        "where vsm.parenttype = 'Vault Space' and vsm.parent = `tabVault Space`.name "
        "and vsm.user = {user})"
    ).format(user=frappe.db.escape(user))


# ------------------------------------------------------------- has_permission hooks


def credential_has_permission(doc, ptype: str | None = None, user: str | None = None, debug=False) -> bool:
    """Single-document access to a Vault Credential. Returns False to deny; True falls
    through to the DocPerm rows (which is where the role ceiling still applies)."""
    user = user or frappe.session.user
    if is_vault_admin(user):
        return True

    ptype = ptype or "read"
    space = doc.get("vault_space") if doc else None
    if not space:
        # On insert the hook runs with vault_space already populated from the form.
        # An unscoped document would be denied by validate() anyway, but the hook must
        # not be the thing that approves it: "no space" must never mean "no restriction".
        return False

    level = get_membership_level(user, space)
    if level is None:
        return False

    if ptype in _READ_PTYPES:
        return True
    if ptype in ("create", "write"):
        return LEVEL_RANK[level] >= LEVEL_RANK["Editor"] and not space_is_disabled(space)
    if ptype == "delete":
        return LEVEL_RANK[level] >= LEVEL_RANK["Manager"] and not space_is_disabled(space)

    # export / share / import / anything Frappe adds later: Vault Admin only, and the
    # admin case already returned above. Defaulting to deny rather than allow means a
    # future Frappe permission type is closed until someone here opens it deliberately.
    return False


def space_has_permission(doc, ptype: str | None = None, user: str | None = None, debug=False) -> bool:
    """Single-document access to a Vault Space.

    Write is Manager-level, which is how a space Manager maintains their own member table
    without needing Vault Admin. Create and delete stay with Vault Admin: spaces are the
    unit of access scoping, and a Manager who could create one could create a space, add
    themselves and start collecting credentials outside any admin's view.
    """
    user = user or frappe.session.user
    if is_vault_admin(user):
        return True

    ptype = ptype or "read"
    space = doc.get("name") if doc else None
    if not space:
        return False

    if ptype in _READ_PTYPES:
        if is_vault_auditor(user):
            return True
        return get_membership_level(user, space) is not None
    if ptype == "write":
        return get_membership_level(user, space) == "Manager"
    return False
