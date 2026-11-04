/**
 * Détection des motifs faibles — portage TypeScript de `patterns.py`.
 *
 * Ce module doit produire EXACTEMENT les mêmes résultats que la version Python :
 * les deux sont vérifiées par le même fichier `shared/test-vectors.json`.
 *
 * Point d'attention : JavaScript mesure les chaînes en unités UTF-16, Python en
 * points de code. Un émoji compte pour 2 en JavaScript, pour 1 en Python. Pour
 * rester identique à Python, on travaille ici sur des TABLEAUX de caractères
 * obtenus avec `Array.from()`, qui découpe par point de code.
 *
 * Règle de sécurité : un motif est décrit par son TYPE, sa POSITION et sa
 * LONGUEUR, jamais par son texte.
 */

// ─────────────────────────────────────────────────────────────
// 1. Listes de référence (identiques à patterns.py)
// ─────────────────────────────────────────────────────────────
export const COMMON_PASSWORDS: ReadonlySet<string> = new Set([
  "123456", "123456789", "12345678", "1234567", "12345", "123123", "000000",
  "111111", "abc123", "password", "password1", "motdepasse", "azerty",
  "azerty123", "azertyuiop", "qwerty", "qwerty123", "admin", "doudou",
  "loulou", "soleil", "bonjour", "marseille", "chouchou", "jetaime",
  "iloveyou", "welcome", "letmein", "football", "dragon", "princesse",
]);

export const COMMON_WORDS: ReadonlySet<string> = new Set([
  "password", "motdepasse", "pass", "secret", "admin", "azerty", "qwerty",
  "bonjour", "soleil", "amour", "chocolat", "doudou", "loulou", "chouchou",
  "marseille", "paris", "football", "dragon", "princesse", "jetaime",
  "iloveyou", "welcome", "master", "shadow", "sunshine", "monkey",
  // Exemple célèbre de phrase de passe (bande dessinée xkcd n° 936)
  "correct", "horse", "battery", "staple",
]);

export const KEYBOARD_ROWS: readonly string[] = [
  "azertyuiop", "qsdfghjklm", "wxcvbn",      // AZERTY
  "qwertyuiop", "asdfghjkl", "zxcvbnm",      // QWERTY
];

// Substitutions « leet speak » : un caractère remplacé par un caractère,
// la longueur ne change donc jamais.
const LEET_TABLE: Readonly<Record<string, string>> = {
  "4": "a", "@": "a", "3": "e", "1": "i", "!": "i",
  "0": "o", "$": "s", "5": "s", "7": "t",
};

// ─────────────────────────────────────────────────────────────
// 2. Valeurs utilisées pour recalculer l'entropie
// ─────────────────────────────────────────────────────────────
export const COMMON_PASSWORD_BITS = 10;
export const DICTIONARY_WORD_BITS = Math.log2(7776);   // ≈ 12,9 bits (liste Diceware)
export const PREDICTABLE_CHAR_BITS = 1;
export const MIN_SEQUENCE_LENGTH = 3;
export const MIN_KEYBOARD_LENGTH = 4;

// Les types de motifs gardent les mêmes identifiants qu'en Python
// (c'est ce qui permet de comparer les deux moteurs avec les mêmes vecteurs).
export type PatternKind = "dictionnaire" | "clavier" | "suite" | "répétition";

const PRIORITY: Readonly<Record<PatternKind, number>> = {
  "dictionnaire": 0, "clavier": 1, "suite": 2, "répétition": 3,
};

// ─────────────────────────────────────────────────────────────
// 3. Description d'un motif trouvé (sans son texte)
// ─────────────────────────────────────────────────────────────
export interface PatternMatch {
  readonly kind: PatternKind;
  readonly start: number;    // position en points de code (0 = début)
  readonly length: number;   // nombre de caractères concernés
}

// ─────────────────────────────────────────────────────────────
// 4. Normalisation
// ─────────────────────────────────────────────────────────────
/** Découpe une chaîne en caractères (points de code), comme le fait Python. */
export function toChars(text: string): string[] {
  return Array.from(text);
}

/** Minuscules + annulation du leet speak : « P@ssw0rd » devient « password ». */
export function normalize(password: string): string {
  return toChars(password.toLowerCase())
    .map((char) => LEET_TABLE[char] ?? char)   // ?? : garde le caractère s'il n'est pas dans la table
    .join("");
}

/** Vrai si le mot de passe entier figure dans la liste des plus courants. */
export function isCommonPassword(password: string): boolean {
  return COMMON_PASSWORDS.has(password.toLowerCase())
    || COMMON_PASSWORDS.has(normalize(password));
}

// ─────────────────────────────────────────────────────────────
// 5. Détecteurs : chacun renvoie des « candidats », qui peuvent se chevaucher
// ─────────────────────────────────────────────────────────────
/** Toutes les occurrences de `needle` dans `chars`, positions en points de code. */
function findAll(chars: readonly string[], needle: string, kind: PatternKind): PatternMatch[] {
  const target = toChars(needle);
  const found: PatternMatch[] = [];
  for (let i = 0; i + target.length <= chars.length; i++) {
    let same = true;
    for (let j = 0; j < target.length; j++) {
      if (chars[i + j] !== target[j]) { same = false; break; }
    }
    if (same) found.push({ kind, start: i, length: target.length });
  }
  return found;
}

function dictionaryCandidates(password: string): PatternMatch[] {
  const found: PatternMatch[] = [];
  // Les deux formes, comme en Python : « soleil » et « s0l3il » sont repérés
  for (const form of new Set([password.toLowerCase(), normalize(password)])) {
    const chars = toChars(form);
    for (const word of COMMON_WORDS) found.push(...findAll(chars, word, "dictionnaire"));
  }
  return found;
}

function keyboardCandidates(password: string): PatternMatch[] {
  const chars = toChars(password.toLowerCase());
  const found: PatternMatch[] = [];
  for (const row of KEYBOARD_ROWS) {
    for (const line of [row, toChars(row).reverse().join("")]) {   // ligne lue à l'endroit puis à l'envers
      for (let size = MIN_KEYBOARD_LENGTH; size <= line.length; size++) {
        for (let i = 0; i + size <= line.length; i++) {
          found.push(...findAll(chars, line.slice(i, i + size), "clavier"));
        }
      }
    }
  }
  return found;
}

/** Équivalent de str.isalnum() de Python : lettre ou chiffre, alphabets du monde entier. */
function isAlnum(char: string): boolean {
  return /^[\p{L}\p{N}]$/u.test(char);
}

function codePoint(char: string): number {
  return char.codePointAt(0) ?? 0;
}

function sequenceCandidates(password: string): PatternMatch[] {
  const text = toChars(password.toLowerCase());
  const found: PatternMatch[] = [];
  let i = 0;
  while (i < text.length - 1) {
    const delta = codePoint(text[i + 1]!) - codePoint(text[i]!);
    if ((delta === 1 || delta === -1) && isAlnum(text[i]!) && isAlnum(text[i + 1]!)) {
      let j = i + 1;
      // Prolonge la suite tant que l'écart reste identique
      while (j + 1 < text.length && isAlnum(text[j + 1]!)
             && codePoint(text[j + 1]!) - codePoint(text[j]!) === delta) {
        j++;
      }
      if (j - i + 1 >= MIN_SEQUENCE_LENGTH) {
        found.push({ kind: "suite", start: i, length: j - i + 1 });
        i = j;
        continue;
      }
    }
    i++;
  }
  return found;
}

function repetitionCandidates(password: string): PatternMatch[] {
  const chars = toChars(password);
  const found: PatternMatch[] = [];
  let i = 0;
  while (i < chars.length) {
    let j = i;
    while (j + 1 < chars.length && chars[j + 1] === chars[i]) j++;
    if (j - i + 1 >= MIN_SEQUENCE_LENGTH) {
      found.push({ kind: "répétition", start: i, length: j - i + 1 });
    }
    i = j + 1;
  }
  return found;
}

// ─────────────────────────────────────────────────────────────
// 6. Sélection finale : pas de chevauchement
// ─────────────────────────────────────────────────────────────
export function findPatterns(password: string): PatternMatch[] {
  const candidates = [
    ...dictionaryCandidates(password),
    ...keyboardCandidates(password),
    ...sequenceCandidates(password),
    ...repetitionCandidates(password),
  ];
  // Même ordre qu'en Python : priorité, puis le plus long, puis le plus à gauche
  candidates.sort((a, b) =>
    PRIORITY[a.kind] - PRIORITY[b.kind] || b.length - a.length || a.start - b.start);

  const covered = new Set<number>();
  const selected: PatternMatch[] = [];
  for (const match of candidates) {
    let free = true;
    for (let p = match.start; p < match.start + match.length; p++) {
      if (covered.has(p)) { free = false; break; }
    }
    if (free) {
      selected.push(match);
      for (let p = match.start; p < match.start + match.length; p++) covered.add(p);
    }
  }
  return selected.sort((a, b) => a.start - b.start);
}

// ─────────────────────────────────────────────────────────────
// 7. Entropie corrigée
// ─────────────────────────────────────────────────────────────
export function effectiveEntropy(password: string, pool: number, matches: readonly PatternMatch[]): number {
  const length = toChars(password).length;
  if (length === 0 || pool <= 1) return 0;
  if (isCommonPassword(password)) return COMMON_PASSWORD_BITS;

  const perChar = Math.log2(pool);
  const covered = matches.reduce((total, m) => total + m.length, 0);
  let bits = (length - covered) * perChar;
  for (const match of matches) {
    bits += match.kind === "dictionnaire"
      ? DICTIONARY_WORD_BITS
      : perChar + (match.length - 1) * PREDICTABLE_CHAR_BITS;
  }
  // L'entropie corrigée ne dépasse jamais l'entropie théorique
  return Math.min(bits, length * perChar);
}
