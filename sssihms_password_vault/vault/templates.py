"""Indian credential templates — a direct port of the personal password manager's
``templates.ts`` (see ``reference/from-personal-password-manager/templates.ts``).

Pure data plus two pure helpers: no Frappe imports, so this module is importable from a
plain ``pytest`` run with no bench.

Field flag mapping, pinned by DESIGN.md §1.8 and used by the form script, the credential
controller and the CSV import alike:

===============  =======================================
template flag    ``Credential Secret Field`` fieldname
===============  =======================================
``sensitive``    ``is_secret``
``masked``       ``is_masked``
``is_password``  ``is_password``
``kind``         ``field_kind``
``warning``      ``warning``
===============  =======================================

A ``sensitive`` field's value lives in ``secret_value`` (a Frappe ``Password`` field,
encrypted at rest); a non-sensitive field's value lives in the plain ``value`` column. The
credential controller enforces that the two never both hold data for one row.

The ``login`` template's ``username`` / ``password`` / ``url`` keys map to the *parent*
Vault Credential columns of the same name, not to child rows; ``wifi``'s ``password``
likewise maps to the parent column. Every other template keeps all of its secrets in child
rows and leaves the parent ``password`` empty — a secret is stored in exactly one place, so
the two copies can never drift.
"""

from __future__ import annotations

#: Set of legal ``field_kind`` values. Must stay in step with the Select options on
#: ``Credential Secret Field.field_kind``.
FIELD_KINDS: tuple[str, ...] = (
    "text",
    "password",
    "pin",
    "email",
    "phone",
    "url",
    "date",
    "number",
    "multiline",
)

PIN_WARNING = (
    "Storing a full PIN increases risk. Prefer a memory hint you'll recognise but "
    "others won't."
)

#: Keys the ``login`` and ``wifi`` templates route to the parent Vault Credential columns
#: instead of to a ``Credential Secret Field`` child row.
PARENT_FIELD_KEYS: dict[str, tuple[str, ...]] = {
    "login": ("username", "password", "url"),
    "wifi": ("password",),
}

TEMPLATES: dict[str, dict] = {
    "login": {
        "label": "Login",
        "icon": "🔑",
        "fields": [
            {"key": "username", "label": "Username / email", "kind": "text"},
            {
                "key": "password",
                "label": "Password",
                "kind": "password",
                "sensitive": True,
                "is_password": True,
            },
            {"key": "url", "label": "Website URL", "kind": "url"},
            {"key": "totpNote", "label": "2FA / TOTP note", "kind": "text"},
        ],
    },
    "netbanking": {
        "label": "Netbanking",
        "icon": "🏦",
        "fields": [
            {
                "key": "bankName",
                "label": "Bank name",
                "kind": "text",
                "placeholder": "e.g. SBI, HDFC, ICICI",
            },
            {"key": "accountHolder", "label": "Account holder name", "kind": "text"},
            {"key": "customerId", "label": "Customer ID / User ID", "kind": "text"},
            {
                "key": "loginPassword",
                "label": "Login password",
                "kind": "password",
                "sensitive": True,
                "is_password": True,
            },
            {
                "key": "transactionPassword",
                "label": "Transaction password",
                "kind": "password",
                "sensitive": True,
                "is_password": True,
                "warning": "Reveal or copy transaction passwords only when needed.",
            },
            {
                "key": "profilePassword",
                "label": "Profile password",
                "kind": "password",
                "sensitive": True,
                "is_password": True,
            },
            {
                "key": "mpin",
                "label": "MPIN",
                "kind": "pin",
                "sensitive": True,
                "warning": PIN_WARNING,
            },
            {
                "key": "tpin",
                "label": "TPIN",
                "kind": "pin",
                "sensitive": True,
                "warning": PIN_WARNING,
            },
            {
                "key": "atmPinHint",
                "label": "ATM PIN hint",
                "kind": "text",
                "warning": "Store a hint, not the raw PIN, unless you accept the risk.",
            },
            {"key": "registeredMobile", "label": "Registered mobile number", "kind": "phone"},
            {"key": "registeredEmail", "label": "Registered email", "kind": "email"},
            {
                "key": "accountNumber",
                "label": "Account number",
                "kind": "text",
                "sensitive": True,
                "masked": True,
            },
            {"key": "ifsc", "label": "IFSC code", "kind": "text"},
            {"key": "branch", "label": "Branch", "kind": "text"},
            {"key": "upiId", "label": "UPI ID", "kind": "text"},
            {"key": "debitCardLast4", "label": "Debit card — last 4 digits", "kind": "text"},
            {"key": "creditCardLast4", "label": "Credit card — last 4 digits", "kind": "text"},
            {
                "key": "securityQuestions",
                "label": "Security questions & answers",
                "kind": "multiline",
                "sensitive": True,
            },
            {"key": "nominee", "label": "Nominee details", "kind": "text"},
            {"key": "helpline", "label": "Bank helpline number", "kind": "phone"},
            {"key": "url", "label": "Website URL", "kind": "url"},
            {"key": "appName", "label": "Mobile app name", "kind": "text"},
            {"key": "lastPasswordChange", "label": "Last password change date", "kind": "date"},
        ],
    },
    "upi": {
        "label": "UPI",
        "icon": "📲",
        "warning": (
            "Storing a raw UPI PIN is risky — prefer a memory hint. Anyone with your UPI "
            "PIN can move money."
        ),
        "fields": [
            {
                "key": "appName",
                "label": "UPI app",
                "kind": "text",
                "placeholder": "BHIM, PhonePe, Google Pay, Paytm…",
            },
            {"key": "upiId", "label": "UPI ID", "kind": "text"},
            {"key": "linkedBank", "label": "Linked bank", "kind": "text"},
            {"key": "registeredMobile", "label": "Registered mobile number", "kind": "phone"},
            {
                "key": "upiPinHint",
                "label": "UPI PIN hint",
                "kind": "text",
                "warning": PIN_WARNING,
            },
            {"key": "deviceBinding", "label": "Device binding notes", "kind": "multiline"},
            {"key": "recoverySteps", "label": "Recovery steps", "kind": "multiline"},
            {"key": "supportContact", "label": "Support contact", "kind": "text"},
        ],
    },
    "card": {
        "label": "Card",
        "icon": "💳",
        "fields": [
            {"key": "issuer", "label": "Card issuer", "kind": "text"},
            {
                "key": "cardType",
                "label": "Card type",
                "kind": "text",
                "placeholder": "debit / credit / forex / prepaid",
            },
            {
                "key": "network",
                "label": "Card network",
                "kind": "text",
                "placeholder": "RuPay / Visa / Mastercard / Amex",
            },
            {"key": "cardholderName", "label": "Cardholder name", "kind": "text"},
            {
                "key": "cardNumber",
                "label": "Card number",
                "kind": "text",
                "sensitive": True,
                "masked": True,
            },
            {"key": "expiry", "label": "Expiry date", "kind": "text", "placeholder": "MM/YY"},
            {
                "key": "cvv",
                "label": "CVV",
                "kind": "pin",
                "sensitive": True,
                "warning": "Storing CVV increases risk if this vault is ever exposed.",
            },
            {"key": "pinHint", "label": "PIN hint", "kind": "text", "warning": PIN_WARNING},
            {"key": "billingCycle", "label": "Billing cycle", "kind": "text"},
            {
                "key": "paymentDueDate",
                "label": "Payment due date",
                "kind": "text",
                "placeholder": "e.g. 5th of every month",
            },
            {"key": "creditLimit", "label": "Credit limit", "kind": "text", "placeholder": "₹"},
            {"key": "rewardProgram", "label": "Reward program", "kind": "text"},
            {"key": "customerCare", "label": "Customer care number", "kind": "phone"},
            {"key": "lostCardNumber", "label": "Lost-card blocking number", "kind": "phone"},
        ],
    },
    "demat": {
        "label": "Demat / Trading",
        "icon": "📈",
        "fields": [
            {
                "key": "broker",
                "label": "Broker name",
                "kind": "text",
                "placeholder": "Zerodha, Groww, Upstox…",
            },
            {"key": "clientId", "label": "Client ID", "kind": "text"},
            {
                "key": "loginPassword",
                "label": "Login password",
                "kind": "password",
                "sensitive": True,
                "is_password": True,
            },
            {
                "key": "tradingPassword",
                "label": "Trading password",
                "kind": "password",
                "sensitive": True,
                "is_password": True,
            },
            {
                "key": "tpin",
                "label": "TPIN (CDSL/NSDL)",
                "kind": "pin",
                "sensitive": True,
                "warning": PIN_WARNING,
            },
            {
                "key": "boId",
                "label": "Demat BO ID",
                "kind": "text",
                "sensitive": True,
                "masked": True,
            },
            {
                "key": "depository",
                "label": "Depository",
                "kind": "text",
                "placeholder": "CDSL / NSDL",
            },
            {"key": "linkedBank", "label": "Linked bank account", "kind": "text"},
            {"key": "registeredEmail", "label": "Registered email", "kind": "email"},
            {"key": "registeredMobile", "label": "Registered mobile", "kind": "phone"},
            {"key": "nominee", "label": "Nominee details", "kind": "text"},
            {"key": "supportContact", "label": "Support contact", "kind": "text"},
        ],
    },
    "govid": {
        "label": "Government ID",
        "icon": "🪪",
        "fields": [
            {
                "key": "idType",
                "label": "ID type",
                "kind": "text",
                "placeholder": (
                    "Aadhaar / PAN / Passport / DL / Voter ID / ABHA / DigiLocker / "
                    "EPFO-UAN / NPS / IT portal / GST"
                ),
            },
            {
                "key": "idNumber",
                "label": "ID number",
                "kind": "text",
                "sensitive": True,
                "masked": True,
            },
            {"key": "holderName", "label": "Name on document", "kind": "text"},
            {"key": "portalUrl", "label": "Portal URL", "kind": "url"},
            {"key": "portalUsername", "label": "Portal username", "kind": "text"},
            {
                "key": "portalPassword",
                "label": "Portal password",
                "kind": "password",
                "sensitive": True,
                "is_password": True,
            },
            {"key": "issueDate", "label": "Issue date", "kind": "date"},
            {"key": "expiryDate", "label": "Expiry / renewal date", "kind": "date"},
            {"key": "registeredMobile", "label": "Registered mobile", "kind": "phone"},
        ],
    },
    "note": {
        "label": "Secure note",
        "icon": "📝",
        "fields": [
            {"key": "body", "label": "Note", "kind": "multiline", "sensitive": True},
        ],
    },
    "wifi": {
        "label": "Wi-Fi",
        "icon": "📶",
        "fields": [
            {"key": "ssid", "label": "Network name (SSID)", "kind": "text"},
            {
                "key": "password",
                "label": "Wi-Fi password",
                "kind": "password",
                "sensitive": True,
                "is_password": True,
            },
            {"key": "routerAdminUrl", "label": "Router admin URL", "kind": "url"},
            {
                "key": "routerAdminPassword",
                "label": "Router admin password",
                "kind": "password",
                "sensitive": True,
                "is_password": True,
            },
        ],
    },
    "insurance": {
        "label": "Insurance",
        "icon": "🛡️",
        "fields": [
            {"key": "insurer", "label": "Insurer", "kind": "text"},
            {
                "key": "policyNumber",
                "label": "Policy number",
                "kind": "text",
                "sensitive": True,
                "masked": True,
            },
            {
                "key": "policyType",
                "label": "Policy type",
                "kind": "text",
                "placeholder": "health / life / motor / term",
            },
            {"key": "portalUrl", "label": "Portal URL", "kind": "url"},
            {"key": "portalUsername", "label": "Portal username", "kind": "text"},
            {
                "key": "portalPassword",
                "label": "Portal password",
                "kind": "password",
                "sensitive": True,
                "is_password": True,
            },
            {"key": "premiumDueDate", "label": "Premium due date", "kind": "date"},
            {"key": "nominee", "label": "Nominee details", "kind": "text"},
            {"key": "agentContact", "label": "Agent / support contact", "kind": "text"},
        ],
    },
    # Custom credentials carry no predefined fields: the user adds Credential Secret Field
    # rows by hand, and template conformance checking is skipped for this type.
    "custom": {
        "label": "Custom",
        "icon": "🗂️",
        "fields": [],
    },
}

#: The Select options on ``Vault Credential.credential_type``, in form order.
CREDENTIAL_TYPES: tuple[str, ...] = tuple(TEMPLATES.keys())


def template_for(credential_type: str) -> dict | None:
    """The template dict for a credential type, or None for an unknown type."""
    return TEMPLATES.get(credential_type)


def template_field_keys(credential_type: str) -> set[str]:
    """Every field key the template defines, parent-mapped keys included.

    Used by the credential controller's soft conformance check: a child ``field_key`` that
    is not in this set is a probable typo and is surfaced with a message, not a throw
    (extra rows are legal — that is exactly how ``custom`` works).
    """
    template = TEMPLATES.get(credential_type)
    if not template:
        return set()
    return {field["key"] for field in template["fields"]}


def mask_value(value: str) -> str:
    """``•••• 1234`` — the last four non-whitespace characters of ``value``.

    Port of ``maskValue()`` in templates.ts. This deliberately discloses the last four
    characters of a masked field (account number, card number, policy number) without a
    reveal and without an audit-log row, which is the whole point of a masked field. The
    result is stored in the plaintext ``masked_hint`` column — never call this on a field
    whose full value must stay secret.
    """
    tail = "".join(ch for ch in str(value or "") if not ch.isspace())[-4:]
    return f"•••• {tail}" if tail else "••••"
