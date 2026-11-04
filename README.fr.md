# 🔑 Password Checker

[![Tests](https://github.com/Aiyeesha/password-checker/actions/workflows/tests.yml/badge.svg)](https://github.com/Aiyeesha/password-checker/actions/workflows/tests.yml)
![Python](https://img.shields.io/badge/python-3.11%20%7C%203.14-blue)
![Dépendances](https://img.shields.io/badge/d%C3%A9pendances-aucune-brightgreen)
![Licence](https://img.shields.io/badge/licence-MIT-green)

[🇬🇧 English](README.md) · 🇫🇷 Français

Outil en ligne de commande qui **évalue la robustesse réelle d'un mot de passe** et vérifie
**s'il a déjà fuité**, sans jamais l'envoyer à qui que ce soit.

---

## ✨ Fonctionnalités

- **Analyse locale** : longueur, familles de caractères, entropie théorique.
- **Détection des motifs faibles** : mots courants (y compris en *leet speak*, ex. `P@ssw0rd`),
  lignes de clavier (`azerty`, `qsdf`), suites (`abcd`, `4321`), répétitions (`aaaa`).
- **Entropie effective** : l'entropie théorique corrigée de ces motifs, qui reflète une vraie attaque.
- **Vérification des fuites** via [Pwned Passwords](https://haveibeenpwned.com/Passwords)
  (Have I Been Pwned), grâce au modèle de **k-anonymité**.
- **Seuils sourcés** : CNIL (délibération n° 2022-100) et NIST SP 800-63B-4.
- **Sortie JSON** pour l'intégration dans un script, un SIEM ou une chaîne CI.
- **Aucune dépendance externe** : uniquement la bibliothèque standard de Python.

## 🔐 Comment le mot de passe reste secret

```
Mot de passe ──SHA-1 (local)──► 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
                                └─┬─┘└───────────────┬────────────────┘
                              préfixe            suffixe
                              (envoyé)           (jamais envoyé)

GET https://api.pwnedpasswords.com/range/5BAA6
  ◄── ~800 à 1 000 suffixes commençant par 5BAA6 (+ remplissage aléatoire)
Comparaison locale du suffixe ──► trouvé / absent
```

- Seuls **5 caractères d'empreinte** quittent la machine, partagés par des centaines de mots de passe.
- L'en-tête `Add-Padding: true` masque aussi la **taille** de la réponse.
- Le mot de passe est saisi de façon **masquée** (`getpass`) : absent de l'écran, de l'historique
  du terminal et des arguments du processus. Il n'existe **volontairement aucune option `--password`**.
- Il n'apparaît **jamais** dans la sortie, le JSON, ni les messages d'erreur (vérifié par les tests).

## 🚀 Installation

```powershell
git clone https://github.com/Aiyeesha/password-checker.git
cd password-checker
python -m venv .venv
.\.venv\Scripts\Activate.ps1      # Linux/macOS : source .venv/bin/activate
pip install -e .
```

## 🧭 Utilisation

```powershell
password-checker              # analyse + vérification des fuites
password-checker --offline    # analyse locale uniquement, aucun appel réseau
password-checker --json       # sortie JSON
password-checker --no-color   # sans couleurs (également : variable NO_COLOR)
password-checker --version
```

Exemple :

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

### Codes de sortie

| Code | Signification |
|------|---------------|
| `0` | Mot de passe « fort » ou « très fort », absent des fuites |
| `1` | Mot de passe trop faible **ou** présent dans des fuites |
| `2` | Erreur d'utilisation (saisie vide, option inconnue) |
| `130` | Interruption (Ctrl+C) |

## 📏 Méthode d'évaluation

| Score | Niveau | Entropie effective | Référence |
|-------|--------|--------------------|-----------|
| 0 | très faible | < 50 bits, ou moins de 8 caractères | NIST : 8 caractères minimum |
| 1 | faible | 50 à 79 bits | CNIL : 50 bits avec restrictions d'accès |
| 2 | fort | 80 à 99 bits | CNIL : 80 bits pour un mot de passe seul |
| 3 | très fort | ≥ 100 bits | Marge de sécurité |

**Entropie théorique** : `E = L × log2(N)` (L = longueur, N = taille de l'alphabet).
**Entropie effective** : un mot courant vaut ≈ 12,9 bits (un mot d'une liste Diceware de 7 776 mots),
chaque caractère d'une suite ou d'une répétition au-delà du premier vaut 1 bit, et un mot de passe
de la liste des plus utilisés vaut 10 bits au total.

## 🏗️ Architecture

```
src/password_checker/
├── strength.py   # analyse : familles, entropie, score, conseils (100 % hors ligne)
├── patterns.py   # détection des motifs faibles et entropie effective
├── pwned.py      # vérification Pwned Passwords (k-anonymité) — seul module réseau
├── cli.py        # interface en ligne de commande
└── __main__.py   # permet « python -m password_checker »
```

La logique d'analyse est **séparée** de l'accès réseau : `strength.py` et `patterns.py` ne font
aucune entrée/sortie, ce qui les rend entièrement testables.

## ⚠️ Limites connues

- Les listes de mots et de mots de passe courants sont **volontairement courtes** (rôle pédagogique) ;
  la vérification Pwned Passwords couvre la très grande majorité des mots de passe divulgués.
- Les valeurs de correction de l'entropie effective sont des **conventions documentées**, pas une norme.
- La taille d'alphabet des caractères accentués ou non latins est une **estimation** (100).
- Python ne permet pas d'**effacer de façon garantie** une chaîne en mémoire : l'outil se contente
  d'en limiter la durée de vie.
- SHA-1 est utilisé **uniquement** parce que c'est le format de l'API ; il ne doit jamais servir
  à stocker des mots de passe (utiliser Argon2id, scrypt ou bcrypt).

## 🧪 Développement

```powershell
pip install -e ".[dev]"
pytest -v
```

- Aucun test n'appelle Internet : l'API et la saisie clavier sont simulées (injection de dépendance).
- La CI (GitHub Actions) exécute les tests sous **Windows et Linux**, avec Python 3.11 et 3.14.
- Dependabot propose chaque semaine les mises à jour des actions et des dépendances.

## 📚 Références

- [CNIL — Recommandation relative aux mots de passe (2022)](https://www.cnil.fr/fr/mots-de-passe-recommandations-pour-maitriser-sa-securite)
- [NIST SP 800-63B-4 — Digital Identity Guidelines](https://pages.nist.gov/800-63-4/sp800-63b.html)
- [Have I Been Pwned — API Pwned Passwords](https://haveibeenpwned.com/API/v3#PwnedPasswords)

## 🛡️ Sécurité

Pour signaler une vulnérabilité, consultez [SECURITY.md](SECURITY.md).

## 📄 Licence

MIT — voir [LICENSE](LICENSE).
