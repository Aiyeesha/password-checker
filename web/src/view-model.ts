/**
 * Fonctions PURES qui préparent l'affichage (aucun accès à la page).
 * Séparées de main.ts pour pouvoir être testées sans navigateur.
 */

import type { PatternKind, PatternMatch } from "./patterns.ts";

/**
 * Une case par caractère : le type de motif qui la couvre, ou null si le caractère
 * n'appartient à aucun motif. Aucune case ne contient le caractère lui-même.
 */
export function patternCells(length: number, patterns: readonly PatternMatch[]): (PatternKind | null)[] {
  const cells: (PatternKind | null)[] = Array.from({ length }, () => null);
  for (const match of patterns) {
    for (let i = match.start; i < match.start + match.length && i < length; i++) cells[i] = match.kind;
  }
  return cells;
}

/** Nombre de caractères situés dans un motif prévisible. */
export function patternedCount(cells: readonly (PatternKind | null)[]): number {
  return cells.filter((cell) => cell !== null).length;
}
