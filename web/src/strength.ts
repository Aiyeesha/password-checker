/**
 * Moteur d'analyse de robustesse — portage TypeScript de `strength.py`.
 *
 * Différence volontaire avec Python : les conseils ne sont pas du texte mais
 * des CODES (ex. { code: "too_short", min: 8 }). C'est l'interface qui les
 * traduit en français ou en anglais (voir i18n.ts).
 *
 * Le rapport ne contient jamais le mot de passe.
 */

import {
  effectiveEntropy,
  findPatterns,
  isCommonPassword,
  toChars,
  type PatternKind,
  type PatternMatch,
} from "./patterns.ts";

// ─────────────────────────────────────────────────────────────
// 1. Familles de caractères (mêmes identifiants qu'en Python)
// ─────────────────────────────────────────────────────────────
export type CharacterClass = "minuscules" | "majuscules" | "chiffres" | "symboles" | "autres";

// L'ordre compte : il détermine l'ordre des familles suggérées dans les conseils.
const CHARACTER_CLASSES: ReadonlyArray<readonly [CharacterClass, string]> = [
  ["minuscules", "abcdefghijklmnopqrstuvwxyz"],
  ["majuscules", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"],
  ["chiffres", "0123456789"],
  // string.punctuation de Python + l'espace = 33 caractères
  ["symboles", "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~ "],
];
const OTHER_POOL_SIZE = 100;

// ─────────────────────────────────────────────────────────────
// 2. Seuils (CNIL 2022 et NIST SP 800-63B-4, voir strength.py)
// ─────────────────────────────────────────────────────────────
export const NIST_MIN_LENGTH = 8;
export const NIST_MIN_LENGTH_SINGLE_FACTOR = 15;
export const CNIL_RESTRICTED_BITS = 50;
export const CNIL_STANDALONE_BITS = 80;
export const VERY_STRONG_BITS = 100;

export type Score = 0 | 1 | 2 | 3;

// ─────────────────────────────────────────────────────────────
// 3. Les conseils, sous forme de codes à traduire
// ─────────────────────────────────────────────────────────────
export type Advice =
  | { readonly code: "empty" }
  | { readonly code: "common" }
  | { readonly code: "pattern"; readonly kind: PatternKind }
  | { readonly code: "too_short"; readonly min: number }
  | { readonly code: "below_single_factor"; readonly min: number }
  | { readonly code: "low_entropy"; readonly bits: number; readonly min: number }
  | { readonly code: "add_classes"; readonly missing: readonly CharacterClass[] };

export interface StrengthReport {
  readonly length: number;
  readonly classes: readonly CharacterClass[];      // triées par ordre alphabétique, comme le JSON Python
  readonly poolSize: number;
  readonly entropyBits: number;                      // entropie théorique
  readonly effectiveEntropyBits: number;             // entropie corrigée des motifs
  readonly isCommon: boolean;
  readonly patterns: readonly PatternMatch[];
  readonly score: Score;
  readonly advice: readonly Advice[];
}

// ─────────────────────────────────────────────────────────────
// 4. Fonctions élémentaires
// ─────────────────────────────────────────────────────────────
export function detectClasses(password: string): CharacterClass[] {
  const found = new Set<CharacterClass>();
  for (const char of toChars(password)) {
    const family = CHARACTER_CLASSES.find(([, members]) => members.includes(char));
    found.add(family ? family[0] : "autres");
  }
  return [...found].sort();
}

export function poolSize(classes: readonly CharacterClass[]): number {
  let total = 0;
  for (const name of classes) {
    const family = CHARACTER_CLASSES.find(([id]) => id === name);
    total += family ? toChars(family[1]).length : OTHER_POOL_SIZE;
  }
  return total;
}

export function entropyBits(length: number, pool: number): number {
  if (length === 0 || pool <= 1) return 0;
  return length * Math.log2(pool);
}

export function scoreFrom(entropy: number, length: number): Score {
  if (length < NIST_MIN_LENGTH) return 0;
  if (entropy < CNIL_RESTRICTED_BITS) return 0;
  if (entropy < CNIL_STANDALONE_BITS) return 1;
  if (entropy < VERY_STRONG_BITS) return 2;
  return 3;
}

function buildAdvice(
  length: number,
  classes: readonly CharacterClass[],
  entropy: number,
  isCommon: boolean,
  patterns: readonly PatternMatch[],
): Advice[] {
  if (length === 0) return [{ code: "empty" }];
  const advice: Advice[] = [];

  if (isCommon) advice.push({ code: "common" });

  // Un conseil par TYPE de motif, dans l'ordre d'apparition, sans doublon
  for (const kind of new Set(patterns.map((m) => m.kind))) advice.push({ code: "pattern", kind });

  if (length < NIST_MIN_LENGTH) {
    advice.push({ code: "too_short", min: NIST_MIN_LENGTH });
  } else if (length < NIST_MIN_LENGTH_SINGLE_FACTOR) {
    advice.push({ code: "below_single_factor", min: NIST_MIN_LENGTH_SINGLE_FACTOR });
  }

  if (entropy < CNIL_STANDALONE_BITS) {
    advice.push({ code: "low_entropy", bits: Math.round(entropy), min: CNIL_STANDALONE_BITS });
    const missing = CHARACTER_CLASSES.map(([id]) => id).filter((id) => !classes.includes(id));
    if (missing.length > 0) advice.push({ code: "add_classes", missing });
  }
  return advice;
}

// ─────────────────────────────────────────────────────────────
// 5. Point d'entrée public
// ─────────────────────────────────────────────────────────────
export function analyze(password: string): StrengthReport {
  const length = toChars(password).length;
  const classes = detectClasses(password);
  const pool = poolSize(classes);
  const entropy = entropyBits(length, pool);

  const isCommon = isCommonPassword(password);
  const patterns = findPatterns(password);
  const effective = effectiveEntropy(password, pool, patterns);

  return {
    length,
    classes,
    poolSize: pool,
    entropyBits: entropy,
    effectiveEntropyBits: effective,
    isCommon,
    patterns,
    score: scoreFrom(effective, length),
    advice: buildAdvice(length, classes, effective, isCommon, patterns),
  };
}
