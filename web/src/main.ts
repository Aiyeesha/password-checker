/**
 * Liaison entre la page (index.html) et les moteurs (strength, pwned, i18n).
 *
 * Règles de sécurité appliquées ici :
 *   - le mot de passe n'est lu que depuis le champ, jamais copié ailleurs dans la page ;
 *   - l'analyse locale tourne à chaque frappe, SANS réseau ;
 *   - la vérification des fuites ne part QUE sur clic (sinon chaque début de saisie
 *     « p », « pa », « pas »… enverrait son propre préfixe) ;
 *   - le texte est toujours inséré avec textContent, jamais innerHTML (pas d'injection possible).
 */

import { analyze, type StrengthReport } from "./strength.ts";
import { fetchRange, parseRange, sha1Hex, splitHash } from "./pwned.ts";
import { LANGS, MESSAGES, pickLang, type Lang, type Messages } from "./i18n.ts";
import { patternCells, patternedCount } from "./view-model.ts";
import type { PatternKind } from "./patterns.ts";

// ─────────────────────────────────────────────────────────────
// 1. Accès aux éléments de la page
// ─────────────────────────────────────────────────────────────
/** Récupère un élément par son id, ou arrête tout si la page est incomplète. */
function byId<T extends HTMLElement>(id: string): T {
  const element = document.getElementById(id);
  if (!element) throw new Error(`Élément #${id} introuvable dans index.html`);
  return element as T;
}

const ui = {
  password: byId<HTMLInputElement>("password"),
  toggle: byId<HTMLButtonElement>("toggle"),
  map: byId<HTMLElement>("map"),
  mapSummary: byId<HTMLElement>("map-summary"),
  legend: byId<HTMLElement>("legend"),
  verdict: byId<HTMLElement>("verdict"),
  level: byId<HTMLElement>("level"),
  meter: byId<HTMLElement>("meter"),
  entropy: byId<HTMLElement>("entropy"),
  adviceList: byId<HTMLUListElement>("advice-list"),
  hash: byId<HTMLElement>("hash"),
  hashSr: byId<HTMLElement>("hash-sr"),
  check: byId<HTMLButtonElement>("check"),
  leakResult: byId<HTMLElement>("leak-result"),
  howList: byId<HTMLOListElement>("how-list"),
  limitsList: byId<HTMLUListElement>("limits-list"),
};

const KINDS: readonly PatternKind[] = ["dictionnaire", "clavier", "suite", "répétition"];
// Classe CSS de chaque type de motif (les identifiants internes contiennent des accents)
const KIND_CLASS: Readonly<Record<PatternKind, string>> = {
  "dictionnaire": "is-word", "clavier": "is-keyboard", "suite": "is-sequence", "répétition": "is-repeat",
};

// ─────────────────────────────────────────────────────────────
// 2. État de l'interface
// ─────────────────────────────────────────────────────────────
type LeakState =
  | { readonly kind: "idle" }
  | { readonly kind: "checking"; readonly prefix: string }
  | { readonly kind: "found"; readonly prefix: string; readonly count: number }
  | { readonly kind: "absent"; readonly prefix: string }
  | { readonly kind: "error" }
  | { readonly kind: "need-password" }
  | { readonly kind: "stale" };

let lang: Lang = "en";
let t: Messages = MESSAGES.en;
let report: StrengthReport | null = null;
let leak: LeakState = { kind: "idle" };
let requestId = 0;       // permet d'ignorer une réponse arrivée après une nouvelle saisie

// ─────────────────────────────────────────────────────────────
// 3. Langue
// ─────────────────────────────────────────────────────────────
function readSavedLang(): string | null {
  try { return localStorage.getItem("lang"); } catch { return null; }  // stockage parfois interdit
}

function setLang(next: Lang, save: boolean): void {
  lang = next;
  t = MESSAGES[next];
  document.documentElement.lang = next;
  document.title = t.pageTitle;
  if (save) {
    try { localStorage.setItem("lang", next); } catch { /* sans conséquence */ }
  }
  // Textes statiques : chaque élément porte la clé de son texte dans data-i18n
  for (const element of document.querySelectorAll<HTMLElement>("[data-i18n]")) {
    const value = t[element.dataset["i18n"] as keyof Messages];
    if (typeof value === "string") element.textContent = value;
  }
  // Boutons de langue : aria-pressed indique la langue active aux lecteurs d'écran
  for (const code of LANGS) {
    byId<HTMLButtonElement>(`lang-${code}`).setAttribute("aria-pressed", String(code === next));
  }
  fillList(ui.howList, t.howItems);
  fillList(ui.limitsList, t.limitsItems);
  renderLegend();
  renderToggle();
  renderAnalysis();
  renderLeak();
}

function fillList(list: HTMLElement, items: readonly string[]): void {
  list.replaceChildren(...items.map((text) => {
    const item = document.createElement("li");
    item.textContent = text;
    return item;
  }));
}

// ─────────────────────────────────────────────────────────────
// 4. Rendu de l'analyse locale
// ─────────────────────────────────────────────────────────────
function renderLegend(): void {
  const entries: [string, string][] = [
    ...KINDS.map((kind): [string, string] => [KIND_CLASS[kind], t.kinds[kind]]),
    ["is-random", t.unmarked],
  ];
  ui.legend.replaceChildren(...entries.map(([cssClass, label]) => {
    const item = document.createElement("li");
    const swatch = document.createElement("span");
    swatch.className = `tile ${cssClass}`;
    swatch.setAttribute("aria-hidden", "true");
    item.append(swatch, label);
    return item;
  }));
}

function renderToggle(): void {
  const visible = ui.password.type === "text";
  ui.toggle.textContent = visible ? t.hide : t.show;
  ui.toggle.setAttribute("aria-pressed", String(visible));
}

function renderAnalysis(): void {
  const length = report?.length ?? 0;

  // Carte des motifs : une case par caractère, sans jamais afficher le caractère
  const cells = report ? patternCells(report.length, report.patterns) : [];
  ui.map.replaceChildren(...cells.map((kind) => {
    const tile = document.createElement("span");
    tile.className = `tile ${kind ? KIND_CLASS[kind] : "is-random"}`;
    return tile;
  }));
  ui.mapSummary.textContent = length === 0 ? t.mapEmpty : t.mapSummary(length, patternedCount(cells));

  // Verdict : niveau, jauge à 4 segments, entropie
  ui.verdict.dataset["score"] = report && length > 0 ? String(report.score) : "none";
  ui.level.textContent = report && length > 0 ? t.levels[report.score] : t.levelWaiting;
  const filled = report && length > 0 ? report.score + 1 : 0;
  ui.meter.replaceChildren(...[0, 1, 2, 3].map((index) => {
    const segment = document.createElement("span");
    if (index < filled) segment.className = "on";
    return segment;
  }));
  ui.entropy.textContent = report && length > 0
    ? `${t.lengthLine(length)}. ${t.entropyLine(report.effectiveEntropyBits, report.entropyBits)}`
    : "";

  // Conseils
  const advice = report?.advice ?? [{ code: "empty" as const }];
  ui.adviceList.replaceChildren(...advice.map((item) => {
    const li = document.createElement("li");
    li.textContent = t.advice(item);
    return li;
  }));
}

// ─────────────────────────────────────────────────────────────
// 5. Rendu de la vérification des fuites
// ─────────────────────────────────────────────────────────────
function renderHash(prefix: string | null): void {
  // 40 cases : les 5 premières (préfixe envoyé) puis 35 barres masquées (suffixe gardé)
  const cells: HTMLElement[] = [];
  for (let i = 0; i < 40; i++) {
    const cell = document.createElement("span");
    if (i < 5) {
      cell.className = "hx sent";
      cell.textContent = prefix ? (prefix[i] ?? "") : "";
      // Apparition décalée des 5 caractères (désactivée si l'utilisateur réduit les animations)
      cell.style.setProperty("--i", String(i));
      if (prefix) cell.classList.add("revealed");
    } else {
      cell.className = "hx kept";
    }
    cells.push(cell);
  }
  ui.hash.replaceChildren(...cells);
  ui.hashSr.textContent = prefix ? `${t.hashSent} : ${prefix}` : "";
}

function renderLeak(): void {
  const prefix = "prefix" in leak ? leak.prefix : null;
  renderHash(prefix);

  ui.check.disabled = leak.kind === "checking";
  ui.check.textContent = leak.kind === "checking" ? t.checking : t.checkButton;
  ui.leakResult.dataset["state"] = leak.kind;

  const lines: string[] = [];
  switch (leak.kind) {
    case "found": lines.push(t.leakFound(leak.count), t.leakFoundAdvice); break;
    case "absent": lines.push(t.leakAbsent); break;
    case "error": lines.push(t.leakError); break;
    case "need-password": lines.push(t.leakNeedPassword); break;
    case "stale": lines.push(t.leakStale); break;
    default: break;
  }
  ui.leakResult.replaceChildren(...lines.map((text) => {
    const p = document.createElement("p");
    p.textContent = text;
    return p;
  }));
}

// ─────────────────────────────────────────────────────────────
// 6. Événements
// ─────────────────────────────────────────────────────────────
ui.password.addEventListener("input", () => {
  requestId++;                                   // une vérification en cours devient caduque
  report = ui.password.value ? analyze(ui.password.value) : null;
  if (leak.kind !== "idle") leak = ui.password.value ? { kind: "stale" } : { kind: "idle" };
  renderAnalysis();
  renderLeak();
});

ui.toggle.addEventListener("click", () => {
  ui.password.type = ui.password.type === "password" ? "text" : "password";
  renderToggle();
  ui.password.focus();
});

ui.check.addEventListener("click", async () => {
  const password = ui.password.value;
  if (!password) {
    leak = { kind: "need-password" };
    renderLeak();
    ui.password.focus();
    return;
  }
  const id = ++requestId;
  const [prefix, suffix] = splitHash(await sha1Hex(password));
  leak = { kind: "checking", prefix };
  renderLeak();
  try {
    const count = parseRange(await fetchRange(prefix)).get(suffix) ?? 0;
    if (id !== requestId) return;               // le mot de passe a changé entre-temps : on ignore
    leak = count > 0 ? { kind: "found", prefix, count } : { kind: "absent", prefix };
  } catch {
    if (id !== requestId) return;
    leak = { kind: "error" };
  }
  renderLeak();
});

for (const code of LANGS) {
  byId<HTMLButtonElement>(`lang-${code}`).addEventListener("click", () => setLang(code, true));
}

// ─────────────────────────────────────────────────────────────
// 7. Démarrage
// ─────────────────────────────────────────────────────────────
const urlLang = new URLSearchParams(location.search).get("lang");
setLang(pickLang(urlLang, readSavedLang(), navigator.languages ?? [navigator.language]), false);
document.documentElement.classList.add("js");   // le CSS masque le message « JavaScript requis »
