# Journal des modifications

Toutes les modifications notables de ce projet sont documentées ici.
Format : [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/) —
versionnage : [Semantic Versioning](https://semver.org/lang/fr/).

## [1.1.0] — 2026-11-04

### Ajouté
- Interface web bilingue (FR/EN) publiée sur GitHub Pages : analyse en direct, carte des motifs
  qui ne révèle aucun caractère, empreinte SHA-1 visualisée (5 caractères envoyés, 35 gardés),
  vérification des fuites sur clic, thème clair/sombre, accessibilité clavier et lecteurs d'écran.
- Moteur TypeScript (portage du moteur Python) et cas de test partagés `shared/test-vectors.json`,
  vérifiés par pytest et par les tests Node.js.
- Vérification des fuites dans le navigateur : SHA-1 via Web Crypto, padding, aucun cookie envoyé.
- Politique de sécurité du contenu stricte : seule l'API Pwned Passwords est joignable.
- CI : tâche « Web · Node 24 » ; workflow de déploiement GitHub Pages ; Dependabot pour npm.

### Modifié
- Mises à jour des actions GitHub (`checkout` v7, `setup-python` v7) et des versions minimales
  de `setuptools` et `pytest`.

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

[1.1.0]: https://github.com/Aiyeesha/password-checker/releases/tag/v1.1.0
[1.0.0]: https://github.com/Aiyeesha/password-checker/releases/tag/v1.0.0
