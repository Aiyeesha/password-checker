/**
 * Le moteur TypeScript doit donner EXACTEMENT les mêmes résultats que le moteur
 * Python, sur les cas définis dans shared/test-vectors.json (généré à partir de Python).
 */

import { test } from "node:test";               // lanceur de tests intégré à Node.js
import assert from "node:assert/strict";          // assertions strictes (=== et comparaison profonde)
import { readFileSync } from "node:fs";

import { analyze } from "../src/strength.ts";

interface VectorCase {
  password: string;
  length: number;
  classes: string[];
  pool_size: number;
  entropy_bits: number;
  effective_entropy_bits: number;
  is_common: boolean;
  patterns: { kind: string; start: number; length: number }[];
  score: number;
}

// new URL(…, import.meta.url) : chemin relatif à CE fichier, quel que soit le dossier courant
const vectors = JSON.parse(
  readFileSync(new URL("../../shared/test-vectors.json", import.meta.url), "utf-8"),
) as { tolerance_bits: number; cases: VectorCase[] };

function assertClose(actual: number, expected: number, label: string): void {
  assert.ok(
    Math.abs(actual - expected) <= vectors.tolerance_bits,
    `${label} : ${actual} au lieu de ${expected}`,
  );
}

for (const cas of vectors.cases) {
  // JSON.stringify affiche le mot de passe d'essai entre guillemets dans le nom du test
  test(`vecteur partagé ${JSON.stringify(cas.password)}`, () => {
    const r = analyze(cas.password);
    assert.equal(r.length, cas.length);
    assert.deepEqual([...r.classes], cas.classes);
    assert.equal(r.poolSize, cas.pool_size);
    assertClose(r.entropyBits, cas.entropy_bits, "entropie théorique");
    assertClose(r.effectiveEntropyBits, cas.effective_entropy_bits, "entropie effective");
    assert.equal(r.isCommon, cas.is_common);
    assert.deepEqual(r.patterns.map((m) => ({ ...m })), cas.patterns);
    assert.equal(r.score, cas.score);
  });
}
