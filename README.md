# 🔑 Password Checker

[![Tests](https://github.com/Aiyeesha/password-checker/actions/workflows/tests.yml/badge.svg)](https://github.com/Aiyeesha/password-checker/actions/workflows/tests.yml)
![Python](https://img.shields.io/badge/python-3.11%20%7C%203.14-blue)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)
![License](https://img.shields.io/badge/license-MIT-green)

🇬🇧 English · [🇫🇷 Français](README.fr.md)

**▶ Try it in your browser: [aiyeesha.github.io/password-checker/](https://aiyeesha.github.io/password-checker/)** — no installation, nothing sent but 5 hash characters.

A command-line tool that **estimates the real strength of a password** and checks
**whether it has already leaked** — without ever sending it to anyone.

---

## ✨ Features

- **Local analysis**: length, character classes, theoretical entropy.
- **Weak pattern detection**: common words (including *leet speak*, e.g. `P@ssw0rd`),
  keyboard walks (`azerty`, `qwerty`, `asdf`), sequences (`abcd`, `4321`), repetitions (`aaaa`).
- **Effective entropy**: theoretical entropy corrected for those patterns, reflecting a real attack.
- **Breach check** through [Pwned Passwords](https://haveibeenpwned.com/Passwords)
  (Have I Been Pwned), using the **k-anonymity** model.
- **Sourced thresholds**: CNIL (French data protection authority, deliberation 2022-100)
  and NIST SP 800-63B-4.
- **JSON output** for scripts, SIEM ingestion or CI pipelines.
- **Zero external dependencies**: Python standard library only.

## 🔐 How the password stays secret

```
Password ──SHA-1 (local)──► 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
                            └─┬─┘└───────────────┬────────────────┘
                            prefix             suffix
                            (sent)             (never sent)

GET https://api.pwnedpasswords.com/range/5BAA6
  ◄── ~800 to 1,000 suffixes starting with 5BAA6 (+ random padding)
Local suffix comparison ──► found / not found
```

- Only **5 hash characters** leave the machine, shared by hundreds of different passwords.
- The `Add-Padding: true` header also hides the **size** of the response.
- The password is read through a **masked prompt** (`getpass`): it never appears on screen,
  in the shell history or in the process arguments. There is **deliberately no `--password` flag**.
- It **never** appears in the output, the JSON or error messages (enforced by tests).

## 🌐 Web interface

A bilingual (EN/FR) page published on GitHub Pages: [aiyeesha.github.io/password-checker/](https://aiyeesha.github.io/password-checker/).

- The analysis engine is a **TypeScript port** of the Python one. Both are checked against the same
  shared cases (`shared/test-vectors.json`): if they ever diverge, CI fails.
- Each character is drawn as a tile, never shown: tiles that belong to a guessable pattern are
  highlighted, with a distinct texture per pattern type (readable without colour).
- The SHA-1 hash is shown as 40 cells: the 5 that are sent, and the 35 that stay on the device.
- The breach check only runs **on click** (checking on every keystroke would send the prefix of
  every partial password).
- A strict Content Security Policy allows **one** network destination only: `api.pwnedpasswords.com`.
  No analytics, no third-party scripts or fonts, no storage other than the chosen language.

## 🚀 Installation

```powershell
git clone https://github.com/Aiyeesha/password-checker.git
cd password-checker
python -m venv .venv
.\.venv\Scripts\Activate.ps1      # Linux/macOS: source .venv/bin/activate
pip install -e .
```

## 🧭 Usage

```powershell
password-checker              # analysis + breach check
password-checker --offline    # local analysis only, no network call
password-checker --json       # JSON output
password-checker --no-color   # no colours (the NO_COLOR variable is also honoured)
password-checker --version
```

Example (the tool's messages are in French):

```text
Analyse du mot de passe
  Niveau             : TRÈS FAIBLE
  Longueur           : 11 caractères
  Familles           : chiffres, majuscules, minuscules, symboles
  Entropie théorique : 72.3 bits
  Entropie effective : 45.8 bits
  Fuites (HIBP)      : non vérifié (--offline)
Conseils
  - Contient un mot courant (même déguisé en leet speak, ex. « P@ssw0rd »).
  - Moins de 15 caractères : c'est le minimum recommandé par le NIST …
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | "Strong" or "very strong" password, not found in any breach |
| `1` | Password too weak **or** found in breaches |
| `2` | Usage error (empty input, unknown option) |
| `130` | Interrupted (Ctrl+C) |

## 📏 Scoring method

| Score | Level | Effective entropy | Reference |
|-------|-------|-------------------|-----------|
| 0 | very weak | < 50 bits, or fewer than 8 characters | NIST: 8 characters minimum |
| 1 | weak | 50 to 79 bits | CNIL: 50 bits with access restrictions |
| 2 | strong | 80 to 99 bits | CNIL: 80 bits for a standalone password |
| 3 | very strong | ≥ 100 bits | Safety margin |

**Theoretical entropy**: `E = L × log2(N)` (L = length, N = alphabet size).
**Effective entropy**: a common word is worth ≈ 12.9 bits (one word from a 7,776-word Diceware list),
each character of a sequence or repetition beyond the first is worth 1 bit, and a password from the
most-used list is worth 10 bits in total.

## 🏗️ Architecture

```
src/password_checker/
├── strength.py   # analysis: classes, entropy, score, advice (100% offline)
├── patterns.py   # weak pattern detection and effective entropy
├── pwned.py      # Pwned Passwords check (k-anonymity) — the only network module
├── cli.py        # command-line interface
└── __main__.py   # enables "python -m password_checker"

web/src/          # browser version (TypeScript)
├── patterns.ts · strength.ts   # ports of the Python engine
├── pwned.ts      # k-anonymity with Web Crypto + fetch
├── i18n.ts       # English and French texts
└── main.ts       # page logic

shared/test-vectors.json   # cases both engines must agree on
```

Analysis logic is **separated** from network access: `strength.py` and `patterns.py` perform no I/O,
which makes them fully testable.

## ⚠️ Known limitations

- The common word and common password lists are **deliberately short** (educational purpose);
  the Pwned Passwords check covers the vast majority of leaked passwords.
- The effective entropy correction values are **documented conventions**, not a standard.
- The alphabet size for accented or non-Latin characters is an **estimate** (100).
- Python cannot **reliably wipe** a string from memory: the tool only limits its lifetime.
- GitHub Pages cannot send custom HTTP headers: the web page declares its Content Security Policy
  in a `<meta>` tag, where some directives (such as `frame-ancestors`) have no effect.
- SHA-1 is used **only** because it is the API's format; it must never be used to store passwords
  (use Argon2id, scrypt or bcrypt instead).

## 🧪 Development

```powershell
pip install -e ".[dev]"
pytest -v
```

Web interface (Node.js 24):

```powershell
cd web
npm ci
npm run typecheck
npm test
npm run build
python -m http.server 8000 --bind 127.0.0.1   # then open http://localhost:8000
```

- No test calls the Internet: the API and keyboard input are simulated (dependency injection).
- CI (GitHub Actions) runs the tests on **Windows and Linux** with Python 3.11 and 3.14.
- Dependabot proposes action and dependency updates every week.

## 📚 References

- [CNIL — Password recommendation (2022, in French)](https://www.cnil.fr/fr/mots-de-passe-recommandations-pour-maitriser-sa-securite)
- [NIST SP 800-63B-4 — Digital Identity Guidelines](https://pages.nist.gov/800-63-4/sp800-63b.html)
- [Have I Been Pwned — Pwned Passwords API](https://haveibeenpwned.com/API/v3#PwnedPasswords)

## 🛡️ Security

To report a vulnerability, see [SECURITY.md](SECURITY.md).

## 📄 License

MIT — see [LICENSE](LICENSE).
