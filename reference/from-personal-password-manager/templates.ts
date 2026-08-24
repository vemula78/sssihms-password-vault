// Indian credential templates — field definitions per SPEC § Indian Banking Credential
// Templates. `sensitive: true` fields are hidden by default and require reauthentication
// (master password / biometric) before reveal. `masked` fields show only a suffix.
import type { ItemType } from "./model";

export type FieldKind =
  | "text"
  | "password"
  | "pin"
  | "email"
  | "phone"
  | "url"
  | "date"
  | "number"
  | "multiline";

export interface FieldDef {
  key: string;
  label: string;
  kind: FieldKind;
  sensitive?: boolean;
  masked?: boolean;
  warning?: string;
  placeholder?: string;
  /** Counts toward password-health analysis (weak/reused detection). */
  isPassword?: boolean;
}

export interface Template {
  type: ItemType;
  label: string;
  icon: string;
  fields: FieldDef[];
  warning?: string;
}

const PIN_WARNING =
  "Storing a full PIN increases risk. Prefer a memory hint you'll recognise but others won't.";

export const TEMPLATES: Record<ItemType, Template> = {
  login: {
    type: "login",
    label: "Login",
    icon: "🔑",
    fields: [
      { key: "username", label: "Username / email", kind: "text" },
      { key: "password", label: "Password", kind: "password", sensitive: true, isPassword: true },
      { key: "url", label: "Website URL", kind: "url" },
      { key: "totpNote", label: "2FA / TOTP note", kind: "text" },
    ],
  },

  netbanking: {
    type: "netbanking",
    label: "Netbanking",
    icon: "🏦",
    fields: [
      { key: "bankName", label: "Bank name", kind: "text", placeholder: "e.g. SBI, HDFC, ICICI" },
      { key: "accountHolder", label: "Account holder name", kind: "text" },
      { key: "customerId", label: "Customer ID / User ID", kind: "text" },
      { key: "loginPassword", label: "Login password", kind: "password", sensitive: true, isPassword: true },
      { key: "transactionPassword", label: "Transaction password", kind: "password", sensitive: true, isPassword: true,
        warning: "Reveal or copy transaction passwords only when needed." },
      { key: "profilePassword", label: "Profile password", kind: "password", sensitive: true, isPassword: true },
      { key: "mpin", label: "MPIN", kind: "pin", sensitive: true, warning: PIN_WARNING },
      { key: "tpin", label: "TPIN", kind: "pin", sensitive: true, warning: PIN_WARNING },
      { key: "atmPinHint", label: "ATM PIN hint", kind: "text",
        warning: "Store a hint, not the raw PIN, unless you accept the risk." },
      { key: "registeredMobile", label: "Registered mobile number", kind: "phone" },
      { key: "registeredEmail", label: "Registered email", kind: "email" },
      { key: "accountNumber", label: "Account number", kind: "text", sensitive: true, masked: true },
      { key: "ifsc", label: "IFSC code", kind: "text" },
      { key: "branch", label: "Branch", kind: "text" },
      { key: "upiId", label: "UPI ID", kind: "text" },
      { key: "debitCardLast4", label: "Debit card — last 4 digits", kind: "text" },
      { key: "creditCardLast4", label: "Credit card — last 4 digits", kind: "text" },
      { key: "securityQuestions", label: "Security questions & answers", kind: "multiline", sensitive: true },
      { key: "nominee", label: "Nominee details", kind: "text" },
      { key: "helpline", label: "Bank helpline number", kind: "phone" },
      { key: "url", label: "Website URL", kind: "url" },
      { key: "appName", label: "Mobile app name", kind: "text" },
      { key: "lastPasswordChange", label: "Last password change date", kind: "date" },
    ],
  },

  upi: {
    type: "upi",
    label: "UPI",
    icon: "📲",
    warning:
      "Storing a raw UPI PIN is risky — prefer a memory hint. Anyone with your UPI PIN can move money.",
    fields: [
      { key: "appName", label: "UPI app", kind: "text", placeholder: "BHIM, PhonePe, Google Pay, Paytm…" },
      { key: "upiId", label: "UPI ID", kind: "text" },
      { key: "linkedBank", label: "Linked bank", kind: "text" },
      { key: "registeredMobile", label: "Registered mobile number", kind: "phone" },
      { key: "upiPinHint", label: "UPI PIN hint", kind: "text", warning: PIN_WARNING },
      { key: "deviceBinding", label: "Device binding notes", kind: "multiline" },
      { key: "recoverySteps", label: "Recovery steps", kind: "multiline" },
      { key: "supportContact", label: "Support contact", kind: "text" },
    ],
  },

  card: {
    type: "card",
    label: "Card",
    icon: "💳",
    fields: [
      { key: "issuer", label: "Card issuer", kind: "text" },
      { key: "cardType", label: "Card type", kind: "text", placeholder: "debit / credit / forex / prepaid" },
      { key: "network", label: "Card network", kind: "text", placeholder: "RuPay / Visa / Mastercard / Amex" },
      { key: "cardholderName", label: "Cardholder name", kind: "text" },
      { key: "cardNumber", label: "Card number", kind: "text", sensitive: true, masked: true },
      { key: "expiry", label: "Expiry date", kind: "text", placeholder: "MM/YY" },
      { key: "cvv", label: "CVV", kind: "pin", sensitive: true,
        warning: "Storing CVV increases risk if this vault is ever exposed." },
      { key: "pinHint", label: "PIN hint", kind: "text", warning: PIN_WARNING },
      { key: "billingCycle", label: "Billing cycle", kind: "text" },
      { key: "paymentDueDate", label: "Payment due date", kind: "text", placeholder: "e.g. 5th of every month" },
      { key: "creditLimit", label: "Credit limit", kind: "text", placeholder: "₹" },
      { key: "rewardProgram", label: "Reward program", kind: "text" },
      { key: "customerCare", label: "Customer care number", kind: "phone" },
      { key: "lostCardNumber", label: "Lost-card blocking number", kind: "phone" },
    ],
  },

  demat: {
    type: "demat",
    label: "Demat / Trading",
    icon: "📈",
    fields: [
      { key: "broker", label: "Broker name", kind: "text", placeholder: "Zerodha, Groww, Upstox…" },
      { key: "clientId", label: "Client ID", kind: "text" },
      { key: "loginPassword", label: "Login password", kind: "password", sensitive: true, isPassword: true },
      { key: "tradingPassword", label: "Trading password", kind: "password", sensitive: true, isPassword: true },
      { key: "tpin", label: "TPIN (CDSL/NSDL)", kind: "pin", sensitive: true, warning: PIN_WARNING },
      { key: "boId", label: "Demat BO ID", kind: "text", sensitive: true, masked: true },
      { key: "depository", label: "Depository", kind: "text", placeholder: "CDSL / NSDL" },
      { key: "linkedBank", label: "Linked bank account", kind: "text" },
      { key: "registeredEmail", label: "Registered email", kind: "email" },
      { key: "registeredMobile", label: "Registered mobile", kind: "phone" },
      { key: "nominee", label: "Nominee details", kind: "text" },
      { key: "supportContact", label: "Support contact", kind: "text" },
    ],
  },

  govid: {
    type: "govid",
    label: "Government ID",
    icon: "🪪",
    fields: [
      { key: "idType", label: "ID type", kind: "text",
        placeholder: "Aadhaar / PAN / Passport / DL / Voter ID / ABHA / DigiLocker / EPFO-UAN / NPS / IT portal / GST" },
      { key: "idNumber", label: "ID number", kind: "text", sensitive: true, masked: true },
      { key: "holderName", label: "Name on document", kind: "text" },
      { key: "portalUrl", label: "Portal URL", kind: "url" },
      { key: "portalUsername", label: "Portal username", kind: "text" },
      { key: "portalPassword", label: "Portal password", kind: "password", sensitive: true, isPassword: true },
      { key: "issueDate", label: "Issue date", kind: "date" },
      { key: "expiryDate", label: "Expiry / renewal date", kind: "date" },
      { key: "registeredMobile", label: "Registered mobile", kind: "phone" },
    ],
  },

  note: {
    type: "note",
    label: "Secure note",
    icon: "📝",
    fields: [{ key: "body", label: "Note", kind: "multiline", sensitive: true }],
  },

  wifi: {
    type: "wifi",
    label: "Wi-Fi",
    icon: "📶",
    fields: [
      { key: "ssid", label: "Network name (SSID)", kind: "text" },
      { key: "password", label: "Wi-Fi password", kind: "password", sensitive: true, isPassword: true },
      { key: "routerAdminUrl", label: "Router admin URL", kind: "url" },
      { key: "routerAdminPassword", label: "Router admin password", kind: "password", sensitive: true, isPassword: true },
    ],
  },

  insurance: {
    type: "insurance",
    label: "Insurance",
    icon: "🛡️",
    fields: [
      { key: "insurer", label: "Insurer", kind: "text" },
      { key: "policyNumber", label: "Policy number", kind: "text", sensitive: true, masked: true },
      { key: "policyType", label: "Policy type", kind: "text", placeholder: "health / life / motor / term" },
      { key: "portalUrl", label: "Portal URL", kind: "url" },
      { key: "portalUsername", label: "Portal username", kind: "text" },
      { key: "portalPassword", label: "Portal password", kind: "password", sensitive: true, isPassword: true },
      { key: "premiumDueDate", label: "Premium due date", kind: "date" },
      { key: "nominee", label: "Nominee details", kind: "text" },
      { key: "agentContact", label: "Agent / support contact", kind: "text" },
    ],
  },

  custom: {
    type: "custom",
    label: "Custom",
    icon: "🗂️",
    fields: [],
  },
};

export function templateFor(type: ItemType): Template {
  return TEMPLATES[type];
}

/** Mask a value for display: keep last 4 characters, e.g. •••• 1234. */
export function maskValue(value: string): string {
  const tail = value.replace(/\s/g, "").slice(-4);
  return tail ? `•••• ${tail}` : "••••";
}
