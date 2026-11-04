# Journal des modifications

Toutes les modifications notables de ce projet sont documentées ici.
Format : [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/) —
versionnage : [Semantic Versioning](https://semver.org/lang/fr/).

## [1.0.0] — 2026-11-04

### Ajouté
- Analyse de robustesse : longueur, familles de caractères, entropie théorique, score de 0 à 3.
- Détection des motifs faibles : mots courants (y compris leet speak), lignes de clavier,
  suites, répétitions ; calcul de l'entropie effective.
- Vérification des fuites via l'API Pwned Passwords (k-anonymité, padding, garde-fou sur le préfixe).
- Commande `password-checker` : saisie masquée, options `--offline`, `--json`, `--no-color`,
  `--version`, codes de sortie documentés.
- Intégration continue (Windows et Linux, Python 3.11 et 3.14) et Dependabot.
- Documentation : README en anglais et en français, politique de sécurité, journal des modifications.

[1.0.0]: https://github.com/Aiyeesha/password-checker/releases/tag/v1.0.0
