/**
 * Tests propres à la version TypeScript : les conseils sous forme de codes,
 * et la règle de sécurité « le rapport ne contient jamais le mot de passe ».
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { analyze } from "../src/strength.ts";
import { normalize } from "../src/patterns.ts";

test("un mot de passe vide produit le seul conseil « empty »", () => {
  assert.deepEqual(analyze("").advice, [{ code: "empty" }]);
});

test("un mot de passe courant produit d'abord le conseil « common »", () => {
  assert.equal(analyze("motdepasse").advice[0]?.code, "common");
});

test("chaque type de motif n'apparaît qu'une fois dans les conseils", () => {
  // « XYZ-tuv » contient DEUX suites : un seul conseil « pattern / suite » attendu
  const kinds = analyze("XYZ-tuv-Q8!m").advice.filter((a) => a.code === "pattern");
  assert.deepEqual(kinds, [{ code: "pattern", kind: "suite" }]);
});

test("les familles manquantes sont proposées dans l'ordre minuscules → symboles", () => {
  const advice = analyze("abcdefghij").advice.find((a) => a.code === "add_classes");
  assert.deepEqual(advice, { code: "add_classes", missing: ["majuscules", "chiffres", "symboles"] });
});

test("un émoji compte pour UN caractère, comme en Python", () => {
  assert.equal(analyze("🔐").length, 1);
});

test("la normalisation annule le leet speak", () => {
  assert.equal(normalize("P@ssw0rd"), "password");
});

test("le rapport ne contient jamais le mot de passe, ni le mot courant détecté", () => {
  const secret = "Xk9#soleil!Tq";
  const serialized = JSON.stringify(analyze(secret));
  assert.ok(!serialized.includes(secret));
  assert.ok(!serialized.includes("soleil"));
});
