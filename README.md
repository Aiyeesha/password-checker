# 🔑 Password Checker

Outil en ligne de commande qui analyse la robustesse d'un mot de passe et vérifie,
sans jamais l'envoyer, s'il apparaît dans des fuites de données connues.

> 🚧 Projet en cours de construction.

## Objectifs

- Évaluer un mot de passe : longueur, variété des caractères, motifs faibles, entropie
- Détecter les mots de passe compromis via l'API Have I Been Pwned (modèle de k-anonymité)
- Ne jamais afficher, journaliser ni transmettre le mot de passe en clair

## Installation (développement)

    python -m venv .venv
    .\.venv\Scripts\Activate.ps1
    pip install -e ".[dev]"
    pytest

## Licence

MIT — voir [LICENSE](LICENSE).