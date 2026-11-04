/**
 * Traductions de l'interface (français et anglais).
 *
 * Le moteur renvoie des CODES (niveaux, familles, motifs, conseils) ; ce module
 * les transforme en phrases. Chaque langue doit définir exactement les mêmes clés :
 * TypeScript le vérifie (type Messages), et un test le revérifie.
 */

import type { Advice, CharacterClass, Score } from "./strength.ts";
import type { PatternKind } from "./patterns.ts";

export type Lang = "fr" | "en";
export const LANGS: readonly Lang[] = ["fr", "en"];

export interface Messages {
  readonly pageTitle: string;
  readonly skipLink: string;
  readonly warning: string;
  readonly heading: string;
  readonly intro: string;
  readonly passwordLabel: string;
  readonly passwordHint: string;
  readonly show: string;
  readonly hide: string;
  readonly mapTitle: string;
  readonly mapEmpty: string;
  readonly mapSummary: (length: number, patterned: number) => string;
  readonly unmarked: string;
  readonly levels: Readonly<Record<Score, string>>;
  readonly levelWaiting: string;
  readonly entropyLine: (effective: number, theoretical: number) => string;
  readonly lengthLine: (length: number) => string;
  readonly classes: Readonly<Record<CharacterClass, string>>;
  readonly kinds: Readonly<Record<PatternKind, string>>;
  readonly adviceTitle: string;
  readonly advice: (item: Advice) => string;
  readonly leakTitle: string;
  readonly leakIntro: string;
  readonly hashSent: string;
  readonly hashKept: string;
  readonly hashCaption: string;
  readonly checkButton: string;
  readonly checking: string;
  readonly leakFound: (count: number) => string;
  readonly leakFoundAdvice: string;
  readonly leakAbsent: string;
  readonly leakError: string;
  readonly leakNeedPassword: string;
  readonly leakStale: string;
  readonly howTitle: string;
  readonly howItems: readonly string[];
  readonly limitsTitle: string;
  readonly limitsItems: readonly string[];
  readonly sourceLink: string;
  readonly langLabel: string;
}

// Formatage des nombres selon la langue (espace insécable en français, virgule en anglais)
const numberFr = new Intl.NumberFormat("fr-FR");
const numberEn = new Intl.NumberFormat("en-GB");

function listFr(items: readonly string[]): string {
  return new Intl.ListFormat("fr", { type: "conjunction" }).format(items);
}
function listEn(items: readonly string[]): string {
  return new Intl.ListFormat("en", { type: "conjunction" }).format(items);
}

const fr: Messages = {
  pageTitle: "Password Checker — robustesse et fuites d'un mot de passe",
  skipLink: "Aller au champ de saisie",
  warning: "Démonstration : n'écrivez jamais ici un mot de passe que vous utilisez réellement.",
  heading: "Votre mot de passe tiendrait-il face à une vraie attaque ?",
  intro: "L'analyse tourne entièrement dans votre navigateur. Seule la vérification des fuites, "
    + "si vous la lancez, envoie 5 caractères d'une empreinte — jamais le mot de passe.",
  passwordLabel: "Mot de passe à tester",
  passwordHint: "Aucun caractère n'est enregistré ni affiché ailleurs que dans ce champ.",
  show: "Afficher",
  hide: "Masquer",
  mapTitle: "Ce qu'un attaquant devinerait en premier",
  mapEmpty: "Commencez à taper : chaque caractère apparaîtra ici sous forme de case, sans être révélé.",
  mapSummary: (length, patterned) =>
    `${length} caractère${length > 1 ? "s" : ""}, dont ${patterned} dans un motif prévisible.`,
  unmarked: "aléatoire",
  levels: { 0: "Très faible", 1: "Faible", 2: "Fort", 3: "Très fort" },
  levelWaiting: "En attente",
  entropyLine: (effective, theoretical) =>
    `Entropie effective : ${effective.toFixed(1).replace(".", ",")} bits `
    + `(${theoretical.toFixed(1).replace(".", ",")} en théorie).`,
  lengthLine: (length) => `${length} caractère${length > 1 ? "s" : ""}`,
  classes: {
    minuscules: "minuscules", majuscules: "majuscules", chiffres: "chiffres",
    symboles: "symboles", autres: "autres caractères",
  },
  kinds: {
    "dictionnaire": "mot courant", "clavier": "touches voisines",
    "suite": "suite logique", "répétition": "répétition",
  },
  adviceTitle: "Pour le renforcer",
  advice: (item) => {
    switch (item.code) {
      case "empty": return "Saisissez un mot de passe pour lancer l'analyse.";
      case "common": return "Il fait partie des mots de passe les plus utilisés : il serait trouvé en quelques secondes.";
      case "pattern": return {
        "dictionnaire": "Il contient un mot courant, même déguisé (« P@ssw0rd » se lit « password »).",
        "clavier": "Il contient des touches voisines du clavier, comme « azer » ou « qsdf ».",
        "suite": "Il contient une suite logique, comme « abc » ou « 1234 ».",
        "répétition": "Il contient un caractère répété, comme « aaa ».",
      }[item.kind];
      case "too_short": return `Moins de ${item.min} caractères : c'est en dessous du minimum absolu du NIST.`;
      case "below_single_factor": return `Visez au moins ${item.min} caractères si aucune double authentification ne le protège (NIST).`;
      case "low_entropy": return `Environ ${item.bits} bits d'entropie : la CNIL en recommande ${item.min} pour un mot de passe utilisé seul.`;
      case "add_classes": return `Allongez-le (le plus efficace) ou ajoutez des ${listFr(item.missing.map((c) => fr.classes[c]))}.`;
    }
  },
  leakTitle: "A-t-il déjà fuité ?",
  leakIntro: "La base Have I Been Pwned recense des centaines de millions de mots de passe divulgués. "
    + "Pour la consulter sans rien révéler, seule une petite partie de l'empreinte SHA-1 quitte votre appareil.",
  hashSent: "envoyé",
  hashKept: "reste sur votre appareil",
  hashCaption: "Empreinte SHA-1 : 40 caractères. Les 5 premiers sont partagés par des centaines de mots de passe différents.",
  checkButton: "Vérifier dans les fuites connues",
  checking: "Vérification en cours…",
  leakFound: (count) => `Trouvé ${numberFr.format(count)} fois dans des fuites de données.`,
  leakFoundAdvice: "Les attaquants le connaissent : ne l'utilisez nulle part.",
  leakAbsent: "Absent des fuites connues. Cela ne le rend pas robuste pour autant : regardez l'analyse ci-dessus.",
  leakError: "La vérification n'a pas abouti : le service est injoignable. Réessayez dans un instant ; l'analyse locale reste valable.",
  leakNeedPassword: "Saisissez d'abord un mot de passe.",
  leakStale: "Le mot de passe a changé : relancez la vérification.",
  howTitle: "Comment ça marche",
  howItems: [
    "Le mot de passe est analysé localement : longueur, familles de caractères, puis recherche des motifs qu'un logiciel de cassage essaie en premier.",
    "L'entropie effective retire la part prévisible : un mot courant vaut environ 12,9 bits, quelle que soit sa longueur.",
    "Pour les fuites, l'empreinte SHA-1 est calculée ici ; seuls ses 5 premiers caractères partent vers api.pwnedpasswords.com, et la comparaison se fait ici.",
    "La page n'autorise aucune autre connexion : vous pouvez le vérifier dans l'onglet Réseau des outils de développement.",
  ],
  limitsTitle: "Limites",
  limitsItems: [
    "Les listes de mots courants sont volontairement courtes ; la vérification des fuites couvre l'essentiel des mots de passe divulgués.",
    "Les corrections d'entropie sont des conventions documentées, pas une norme.",
    "GitHub Pages ne permet pas d'envoyer d'en-têtes de sécurité personnalisés : la politique de sécurité est déclarée dans la page.",
  ],
  sourceLink: "Code source et version en ligne de commande",
  langLabel: "Langue",
};

const en: Messages = {
  pageTitle: "Password Checker — password strength and breach check",
  skipLink: "Skip to the password field",
  warning: "Demo: never type a password you actually use.",
  heading: "Would your password hold up against a real attack?",
  intro: "The analysis runs entirely in your browser. Only the breach check, if you start it, "
    + "sends 5 characters of a hash — never the password.",
  passwordLabel: "Password to test",
  passwordHint: "No character is stored or shown anywhere outside this field.",
  show: "Show",
  hide: "Hide",
  mapTitle: "What an attacker would guess first",
  mapEmpty: "Start typing: each character will appear here as a tile, without being revealed.",
  mapSummary: (length, patterned) =>
    `${length} character${length > 1 ? "s" : ""}, ${patterned} of them in a predictable pattern.`,
  unmarked: "random",
  levels: { 0: "Very weak", 1: "Weak", 2: "Strong", 3: "Very strong" },
  levelWaiting: "Waiting",
  entropyLine: (effective, theoretical) =>
    `Effective entropy: ${effective.toFixed(1)} bits (${theoretical.toFixed(1)} in theory).`,
  lengthLine: (length) => `${length} character${length > 1 ? "s" : ""}`,
  classes: {
    minuscules: "lowercase letters", majuscules: "uppercase letters", chiffres: "digits",
    symboles: "symbols", autres: "other characters",
  },
  kinds: {
    "dictionnaire": "common word", "clavier": "keyboard walk",
    "suite": "sequence", "répétition": "repetition",
  },
  adviceTitle: "To make it stronger",
  advice: (item) => {
    switch (item.code) {
      case "empty": return "Type a password to start the analysis.";
      case "common": return "It is one of the most used passwords: it would be found within seconds.";
      case "pattern": return {
        "dictionnaire": "It contains a common word, even disguised (\"P@ssw0rd\" reads \"password\").",
        "clavier": "It contains neighbouring keyboard keys, such as \"qwer\" or \"asdf\".",
        "suite": "It contains a sequence, such as \"abc\" or \"1234\".",
        "répétition": "It contains a repeated character, such as \"aaa\".",
      }[item.kind];
      case "too_short": return `Fewer than ${item.min} characters: below NIST's absolute minimum.`;
      case "below_single_factor": return `Aim for at least ${item.min} characters if no second factor protects it (NIST).`;
      case "low_entropy": return `About ${item.bits} bits of entropy: France's CNIL recommends ${item.min} for a standalone password.`;
      case "add_classes": return `Make it longer (most effective) or add ${listEn(item.missing.map((c) => en.classes[c]))}.`;
    }
  },
  leakTitle: "Has it already leaked?",
  leakIntro: "Have I Been Pwned lists hundreds of millions of leaked passwords. "
    + "To query it without revealing anything, only a small part of the SHA-1 hash leaves your device.",
  hashSent: "sent",
  hashKept: "stays on your device",
  hashCaption: "SHA-1 hash: 40 characters. The first 5 are shared by hundreds of different passwords.",
  checkButton: "Check known breaches",
  checking: "Checking…",
  leakFound: (count) => `Found ${numberEn.format(count)} times in data breaches.`,
  leakFoundAdvice: "Attackers know it: don't use it anywhere.",
  leakAbsent: "Not found in known breaches. That doesn't make it strong: see the analysis above.",
  leakError: "The check didn't complete: the service can't be reached. Try again shortly; the local analysis still stands.",
  leakNeedPassword: "Type a password first.",
  leakStale: "The password changed: run the check again.",
  howTitle: "How it works",
  howItems: [
    "The password is analysed locally: length, character classes, then the patterns a cracking tool tries first.",
    "Effective entropy removes the predictable part: a common word is worth about 12.9 bits, whatever its length.",
    "For breaches, the SHA-1 hash is computed here; only its first 5 characters go to api.pwnedpasswords.com, and the comparison happens here.",
    "The page allows no other connection: you can check it in the Network tab of the developer tools.",
  ],
  limitsTitle: "Limitations",
  limitsItems: [
    "The common word lists are deliberately short; the breach check covers most leaked passwords.",
    "Entropy corrections are documented conventions, not a standard.",
    "GitHub Pages can't send custom security headers: the security policy is declared in the page itself.",
  ],
  sourceLink: "Source code and command-line version",
  langLabel: "Language",
};

export const MESSAGES: Readonly<Record<Lang, Messages>> = { fr, en };

/** Choisit la langue : paramètre ?lang= d'abord, puis préférence enregistrée, puis navigateur. */
export function pickLang(param: string | null, saved: string | null, browser: readonly string[]): Lang {
  for (const candidate of [param, saved, ...browser.map((tag) => tag.slice(0, 2).toLowerCase())]) {
    if (candidate === "fr" || candidate === "en") return candidate;
  }
  return "en";
}
