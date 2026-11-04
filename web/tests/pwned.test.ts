/**
 * Tests de la vérification Have I Been Pwned côté navigateur (étape 7.2).
 * AUCUN test n'appelle Internet : fetch est remplacé par une fausse fonction.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  API_URL, PwnedCheckError, fetchRange, parseRange, pwnedCount, sha1Hex, splitHash,
} from "../src/pwned.ts";

// Même vecteur de référence que dans tests/test_pwned.py (SHA-1 public de « password »)
const SHA1_PASSWORD = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"; // gitleaks:allow

test("sha1Hex donne la même empreinte que Python", async () => {
  assert.equal(await sha1Hex("password"), SHA1_PASSWORD);
});

test("sha1Hex encode en UTF-8, comme Python", async () => {
  // Empreinte calculée par Python : hashlib.sha1("é".encode("utf-8")).hexdigest().upper()
  assert.equal(await sha1Hex("é"), "BF15BE717AC1B080B4F1C456692825891FF5073D");
});

test("splitHash garde 5 caractères pour le préfixe", () => {
  assert.deepEqual(splitHash(SHA1_PASSWORD), ["5BAA6", "1E4C9B93F3F0682250B6CF8331B7EE68FD8"]);
});

test("parseRange écarte le padding et les lignes vides", () => {
  const parsed = parseRange("AAAAA:3\r\nbbbbb:12\r\n\r\nCCCCC:0\r\n");
  assert.deepEqual([...parsed], [["AAAAA", 3], ["BBBBB", 12]]);
});

test("parseRange refuse un format inattendu", () => {
  assert.throws(() => parseRange("AAAAA:pas-un-nombre"), PwnedCheckError);
});

test("pwnedCount n'envoie que le préfixe de 5 caractères", async () => {
  const sent: string[] = [];
  const count = await pwnedCount("password", async (prefix) => {
    sent.push(prefix);
    return "1E4C9B93F3F0682250B6CF8331B7EE68FD8:9545824\r\nFFFFF:0\r\n";
  });
  assert.equal(count, 9545824);
  assert.deepEqual(sent, ["5BAA6"]);
});

test("pwnedCount renvoie 0 si le suffixe est absent", async () => {
  assert.equal(await pwnedCount("q7#Lm2!vXp9@Rt4z", async () => "00000000000000000000000000000000000:2\r\n"), 0);
});

test("fetchRange refuse un préfixe invalide (garde-fou)", async () => {
  await assert.rejects(fetchRange(SHA1_PASSWORD), RangeError);
});

test("fetchRange appelle la bonne adresse avec les bonnes options", async () => {
  const calls: { url: string; init: RequestInit | undefined }[] = [];
  const fakeFetch = (async (url: string, init?: RequestInit) => {
    calls.push({ url, init });
    return new Response("ABCDE:1\r\n", { status: 200 });
  }) as typeof fetch;

  assert.equal(await fetchRange("5BAA6", { fetchImpl: fakeFetch }), "ABCDE:1\r\n");
  const [call] = calls;
  assert.equal(call?.url, `${API_URL}5BAA6`);
  assert.deepEqual(call?.init?.headers, { "Add-Padding": "true" });
  assert.equal(call?.init?.credentials, "omit");
  assert.equal(call?.init?.referrerPolicy, "no-referrer");
  assert.equal(call?.init?.cache, "no-store");
});

test("fetchRange sans padding n'envoie aucun en-tête", async () => {
  let headers: HeadersInit | undefined;
  const fakeFetch = (async (_url: string, init?: RequestInit) => {
    headers = init?.headers;
    return new Response("", { status: 200 });
  }) as typeof fetch;
  await fetchRange("5BAA6", { fetchImpl: fakeFetch, padding: false });
  assert.deepEqual(headers, {});
});

test("une panne réseau devient une PwnedCheckError", async () => {
  const failing = (async () => { throw new TypeError("Failed to fetch"); }) as typeof fetch;
  await assert.rejects(fetchRange("5BAA6", { fetchImpl: failing }), PwnedCheckError);
});

test("une réponse HTTP en erreur devient une PwnedCheckError", async () => {
  const error503 = (async () => new Response("", { status: 503 })) as typeof fetch;
  await assert.rejects(fetchRange("5BAA6", { fetchImpl: error503 }), PwnedCheckError);
});

test("un délai dépassé annule la requête", async () => {
  // Fausse API qui ne répond jamais, sauf si la requête est annulée
  const never = ((_url: string, init?: RequestInit) => new Promise<Response>((_resolve, reject) => {
    init?.signal?.addEventListener("abort", () => reject(new DOMException("Aborted", "AbortError")));
  })) as typeof fetch;
  await assert.rejects(fetchRange("5BAA6", { fetchImpl: never, timeoutMs: 20 }), PwnedCheckError);
});
