// Password health: weak / reused / duplicate detection over decrypted items (runs only
// in memory after unlock; nothing here leaves the device).
import type { VaultItem } from "./model";
import { TEMPLATES } from "./templates";

export type Strength = "very-weak" | "weak" | "fair" | "strong";

const COMMON_PASSWORDS = new Set([
  "password", "password1", "password123", "123456", "12345678", "123456789", "1234567890",
  "qwerty", "qwerty123", "abc123", "111111", "letmein", "welcome", "admin", "iloveyou",
  "india123", "india@123", "pass@123", "password@123", "welcome@123", "admin@123",
  "abcd1234", "p@ssw0rd", "monkey", "dragon", "sunshine", "666666", "654321",
]);

/** Rough entropy estimate from character-class pool size; penalises repeats/sequences. */
export function estimateStrength(password: string): { strength: Strength; bits: number } {
  if (!password) return { strength: "very-weak", bits: 0 };
  const lower = password.toLowerCase();
  if (COMMON_PASSWORDS.has(lower)) return { strength: "very-weak", bits: 10 };

  let pool = 0;
  if (/[a-z]/.test(password)) pool += 26;
  if (/[A-Z]/.test(password)) pool += 26;
  if (/[0-9]/.test(password)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(password)) pool += 33;
  let bits = password.length * Math.log2(pool || 1);

  if (/^(.)\1+$/.test(password)) bits = Math.min(bits, 8); // all one character
  if (/^(0123|1234|2345|3456|4567|5678|6789|abcd|qwer)/i.test(password)) bits *= 0.5;
  if (/(.)\1{2,}/.test(password)) bits *= 0.8; // runs of repeats

  const strength: Strength =
    bits < 28 ? "very-weak" : bits < 45 ? "weak" : bits < 65 ? "fair" : "strong";
  return { strength, bits: Math.round(bits) };
}

export interface PasswordUse {
  itemId: string;
  itemTitle: string;
  fieldKey: string;
  fieldLabel: string;
  value: string;
  strength: Strength;
  bits: number;
}

export interface HealthReport {
  totalPasswords: number;
  weak: PasswordUse[];
  /** Groups of 2+ uses sharing the same password (reused across items or fields). */
  reused: PasswordUse[][];
  /** 0–100. */
  score: number;
  weakCount: number;
  reusedCount: number;
}

function passwordUses(items: VaultItem[]): PasswordUse[] {
  const uses: PasswordUse[] = [];
  for (const item of items) {
    if (item.archived) continue;
    for (const def of TEMPLATES[item.type].fields) {
      if (!def.isPassword) continue;
      const value = item.fields[def.key];
      if (!value) continue;
      const { strength, bits } = estimateStrength(value);
      uses.push({
        itemId: item.id, itemTitle: item.title,
        fieldKey: def.key, fieldLabel: def.label,
        value, strength, bits,
      });
    }
    for (const cf of item.customFields) {
      if (!cf.sensitive || !cf.value) continue;
      const { strength, bits } = estimateStrength(cf.value);
      uses.push({
        itemId: item.id, itemTitle: item.title,
        fieldKey: `custom:${cf.label}`, fieldLabel: cf.label,
        value: cf.value, strength, bits,
      });
    }
  }
  return uses;
}

export function analyzeHealth(items: VaultItem[]): HealthReport {
  const uses = passwordUses(items);
  const weak = uses.filter((u) => u.strength === "very-weak" || u.strength === "weak");

  const byValue = new Map<string, PasswordUse[]>();
  for (const u of uses) {
    const list = byValue.get(u.value) ?? [];
    list.push(u);
    byValue.set(u.value, list);
  }
  const reused = [...byValue.values()].filter((g) => g.length > 1);
  const reusedFlat = new Set(reused.flat().map((u) => `${u.itemId}:${u.fieldKey}`));

  let score = 100;
  if (uses.length > 0) {
    const bad = new Set([
      ...weak.map((u) => `${u.itemId}:${u.fieldKey}`),
      ...reusedFlat,
    ]);
    score = Math.round(100 * (1 - bad.size / uses.length));
  }

  return {
    totalPasswords: uses.length,
    weak,
    reused,
    score,
    weakCount: weak.length,
    reusedCount: reused.reduce((n, g) => n + g.length, 0),
  };
}
