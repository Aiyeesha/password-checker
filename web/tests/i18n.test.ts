/**
 * Tests de l'internationalisation et des fonctions d'affichage (étape 7.3).
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { MESSAGES, LANGS, pickLang } from "../src/i18n.ts";
import { analyze, type Advice } from "../src/strength.ts";
import { patternCells, patternedCount } from "../src/view-model.ts";

test("le français et l'anglais définissent exactement les mêmes clés", () => {
  assert.deepEqual(Object.keys(MESSAGES.fr).sort(), Object.keys(MESSAGES.en).sort());
});

test("chaque conseil possible a une traduction non vide dans les deux langues", () => {
  const samples: Advice[] = [
    { code: "empty" }, { code: "common" },
    { code: "pattern", kind: "dictionnaire" }, { code: "pattern", kind: "clavier" },
    { code: "pattern", kind: "suite" }, { code: "pattern", kind: "répétition" },
    { code: "too_short", min: 8 }, { code: "below_single_factor", min: 15 },
    { code: "low_entropy", bits: 42, min: 80 },
    { code: "add_classes", missing: ["majuscules", "chiffres"] },
  ];
  for (const lang of LANGS) {
    for (const item of samples) {
      assert.ok(MESSAGES[lang].advice(item).length > 10, `${lang} / ${item.code}`);
    }
  }
});

test("les conseils réels du moteur sont tous traduisibles", () => {
  for (const password of ["", "abc", "motdepasse", "Soleil2026!", "azertyuiop1234aaa", "q7#Lm2!vXp9@Rt4z"]) {
    for (const item of analyze(password).advice) {
      for (const lang of LANGS) assert.ok(MESSAGES[lang].advice(item));
    }
  }
});

test("les nombres sont formatés selon la langue", () => {
  assert.match(MESSAGES.en.leakFound(9545824), /9,545,824/);
  assert.match(MESSAGES.fr.leakFound(9545824), /9\s545\s824/);   // \s : espace insécable
});

test("choix de la langue : paramètre, puis préférence, puis navigateur, puis anglais", () => {
  assert.equal(pickLang("en", "fr", ["fr-FR"]), "en");
  assert.equal(pickLang(null, "fr", ["en-US"]), "fr");
  assert.equal(pickLang(null, null, ["fr-CA", "en"]), "fr");
  assert.equal(pickLang("de", null, ["de-DE"]), "en");
});

test("la carte des motifs a une case par caractère, sans aucun caractère", () => {
  const report = analyze("Xq#aaaa");
  const cells = patternCells(report.length, report.patterns);
  assert.deepEqual(cells, [null, null, null, "répétition", "répétition", "répétition", "répétition"]);
  assert.equal(patternedCount(cells), 4);
  assert.ok(!JSON.stringify(cells).includes("a"));
});
