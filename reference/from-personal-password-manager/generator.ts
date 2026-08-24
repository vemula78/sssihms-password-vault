// Password & passphrase generation. All randomness comes from libsodium's CSPRNG
// (randombytes_uniform — rejection-sampled, unbiased).
import { randomUniform } from "./crypto";
import { WORDLIST } from "./wordlist";

export interface PasswordOptions {
  length: number;
  lower: boolean;
  upper: boolean;
  digits: boolean;
  symbols: boolean;
  /** Drop look-alikes: 0O1lI| */
  excludeAmbiguous: boolean;
}

export const DEFAULT_PASSWORD_OPTIONS: PasswordOptions = {
  length: 20,
  lower: true,
  upper: true,
  digits: true,
  symbols: true,
  excludeAmbiguous: true,
};

const SETS = {
  lower: "abcdefghijklmnopqrstuvwxyz",
  upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  digits: "0123456789",
  symbols: "!@#$%^&*()-_=+[]{};:,.?/",
};
const AMBIGUOUS = /[0O1lI|]/g;

export function generatePassword(opts: PasswordOptions = DEFAULT_PASSWORD_OPTIONS): string {
  const pools: string[] = [];
  if (opts.lower) pools.push(SETS.lower);
  if (opts.upper) pools.push(SETS.upper);
  if (opts.digits) pools.push(SETS.digits);
  if (opts.symbols) pools.push(SETS.symbols);
  if (pools.length === 0) throw new Error("Select at least one character set");
  const clean = (s: string) => (opts.excludeAmbiguous ? s.replace(AMBIGUOUS, "") : s);
  const cleaned = pools.map(clean);
  const all = cleaned.join("");
  const length = Math.max(opts.length, cleaned.length, 8);

  // Guarantee at least one char from each selected set, then fill uniformly and shuffle.
  const chars: string[] = cleaned.map((pool) => pool[randomUniform(pool.length)]!);
  while (chars.length < length) chars.push(all[randomUniform(all.length)]!);
  for (let i = chars.length - 1; i > 0; i--) {
    const j = randomUniform(i + 1);
    [chars[i], chars[j]] = [chars[j]!, chars[i]!];
  }
  return chars.join("");
}

export interface PassphraseOptions {
  words: number;
  separator: string;
  capitalize: boolean;
  includeNumber: boolean;
}

export const DEFAULT_PASSPHRASE_OPTIONS: PassphraseOptions = {
  words: 5,
  separator: "-",
  capitalize: true,
  includeNumber: true,
};

/** ~10.3 bits per word (EFF short wordlist 2.0). 5 words ≈ 52 bits + number. */
export function generatePassphrase(opts: PassphraseOptions = DEFAULT_PASSPHRASE_OPTIONS): string {
  const n = Math.max(3, opts.words);
  const words: string[] = [];
  for (let i = 0; i < n; i++) {
    let w = WORDLIST[randomUniform(WORDLIST.length)]!;
    if (opts.capitalize) w = w[0]!.toUpperCase() + w.slice(1);
    words.push(w);
  }
  if (opts.includeNumber) {
    const pos = randomUniform(words.length);
    words[pos] = words[pos]! + String(randomUniform(100));
  }
  return words.join(opts.separator);
}

/** 6-digit numeric PIN, for cases where the user explicitly wants one. */
export function generatePin(digits = 6): string {
  let out = "";
  for (let i = 0; i < digits; i++) out += String(randomUniform(10));
  return out;
}
