/**
 * Vérification des fuites — portage navigateur de `pwned.py`.
 *
 * Même principe de k-anonymité qu'en Python :
 *   1. empreinte SHA-1 calculée LOCALEMENT, avec l'API Web Crypto du navigateur ;
 *   2. seuls les 5 premiers caractères (le préfixe) sont envoyés ;
 *   3. la comparaison du suffixe se fait localement.
 *
 * Différences imposées par le navigateur :
 *   - l'en-tête User-Agent ne peut pas être modifié (le navigateur l'interdit) ;
 *   - la requête est soumise aux règles CORS de l'API (vérifiées à l'étape 7.2).
 *
 * SHA-1 est utilisé UNIQUEMENT parce que c'est le format de l'API.
 */

export const API_URL = "https://api.pwnedpasswords.com/range/";
export const TIMEOUT_MS = 10_000;
const PREFIX_LENGTH = 5;
const PREFIX_PATTERN = /^[0-9A-F]{5}$/;

/** Fonction qui, à partir d'un préfixe, renvoie le texte brut de la réponse. Remplaçable en test. */
export type Fetcher = (prefix: string) => Promise<string>;

/** La vérification n'a pas pu aboutir (réseau, délai dépassé, réponse invalide). */
export class PwnedCheckError extends Error {
  override name = "PwnedCheckError";
}

// ─────────────────────────────────────────────────────────────
// 1. Empreinte et découpage
// ─────────────────────────────────────────────────────────────
/** Empreinte SHA-1 en hexadécimal MAJUSCULE (format de l'API). */
export async function sha1Hex(password: string): Promise<string> {
  const bytes = new TextEncoder().encode(password);             // texte → octets UTF-8 (comme Python)
  const digest = await crypto.subtle.digest("SHA-1", bytes);    // calcul local, rien n'est envoyé
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();
}

export function splitHash(fullHash: string): [prefix: string, suffix: string] {
  return [fullHash.slice(0, PREFIX_LENGTH), fullHash.slice(PREFIX_LENGTH)];
}

// ─────────────────────────────────────────────────────────────
// 2. Appel réseau (la seule fonction qui sort de la machine)
// ─────────────────────────────────────────────────────────────
export interface FetchRangeOptions {
  readonly timeoutMs?: number;
  readonly fetchImpl?: typeof fetch;     // remplaçable en test : aucun appel réel
  readonly padding?: boolean;            // en-tête Add-Padding (désactivable si le CORS le refuse)
}

export async function fetchRange(prefix: string, options: FetchRangeOptions = {}): Promise<string> {
  const { timeoutMs = TIMEOUT_MS, fetchImpl = fetch, padding = true } = options;

  // Garde-fou : jamais autre chose qu'un préfixe de 5 caractères hexadécimaux
  if (!PREFIX_PATTERN.test(prefix)) {
    throw new RangeError("Le préfixe doit contenir exactement 5 caractères hexadécimaux majuscules.");
  }

  // AbortController : annule la requête si elle dépasse le délai
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetchImpl(API_URL + prefix, {
      method: "GET",
      headers: padding ? { "Add-Padding": "true" } : {},
      credentials: "omit",            // aucun cookie envoyé
      referrerPolicy: "no-referrer",  // l'API ne sait pas de quelle page vient la requête
      cache: "no-store",              // rien n'est conservé dans le cache du navigateur
      signal: controller.signal,
    });
    if (!response.ok) {
      throw new PwnedCheckError(`Réponse inattendue de l'API (HTTP ${response.status}).`);
    }
    return await response.text();
  } catch (error) {
    if (error instanceof PwnedCheckError) throw error;
    // Réseau coupé, délai dépassé, requête bloquée par CORS ou par la CSP…
    throw new PwnedCheckError("Service Pwned Passwords injoignable.", { cause: error });
  } finally {
    clearTimeout(timer);              // toujours annuler le minuteur
  }
}

// ─────────────────────────────────────────────────────────────
// 3. Lecture de la réponse (identique à parse_range en Python)
// ─────────────────────────────────────────────────────────────
export function parseRange(body: string): Map<string, number> {
  const results = new Map<string, number>();
  for (const rawLine of body.split(/\r?\n/)) {
    const line = rawLine.trim();
    const separator = line.indexOf(":");
    if (separator === -1) continue;                       // ligne vide ou mal formée : ignorée
    const suffix = line.slice(0, separator).toUpperCase();
    const countText = line.slice(separator + 1);
    if (countText === "") continue;
    if (!/^\d+$/.test(countText)) {
      throw new PwnedCheckError("Réponse de l'API dans un format inattendu.");
    }
    const occurrences = Number(countText);
    if (occurrences > 0) results.set(suffix, occurrences); // 0 = faux résultat du padding
  }
  return results;
}

// ─────────────────────────────────────────────────────────────
// 4. Point d'entrée public
// ─────────────────────────────────────────────────────────────
/** Nombre d'apparitions dans des fuites connues (0 = jamais vu). */
export async function pwnedCount(password: string, fetcher: Fetcher = (p) => fetchRange(p)): Promise<number> {
  const [prefix, suffix] = splitHash(await sha1Hex(password));
  return parseRange(await fetcher(prefix)).get(suffix) ?? 0;
}
