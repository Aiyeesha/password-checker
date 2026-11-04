"""
Génère shared/test-vectors.json à partir du moteur Python (la référence).

Ces cas de test sont relus par pytest (tests/test_vectors.py) ET par les tests
TypeScript (web/tests/vectors.test.ts) : si les deux moteurs divergent, la CI échoue.

À relancer UNIQUEMENT après une modification volontaire des règles d'analyse :
    python scripts/generate_test_vectors.py
puis relire le diff du fichier JSON avant de commiter.

Tous les mots de passe ci-dessous sont des exemples fictifs.
"""

import json
from pathlib import Path

from password_checker.strength import analyze

# Chaque cas couvre une règle précise (le commentaire indique laquelle)
PASSWORDS = [
    "",                                   # vide
    "abc",                                # trop court + suite
    "Zx9!Qw2",                            # moins de 8 caractères, 4 familles
    "abcdefghij",                         # longue suite
    "motdepasse",                         # liste des plus courants
    "P@ssw0rd",                           # leet speak d'un mot de passe courant
    "AZERTY",                             # courant, en majuscules
    "motdepassesecret",                   # deux mots du dictionnaire
    "Soleil2026!",                        # mot courant + chiffres
    "Tr0ub4dour&3xyz",                    # suite « xyz » en fin
    "correct horse battery staple",       # phrase de passe (4 mots)
    "q7#Lm2!vXp9@Rt4z",                   # aléatoire, sans motif
    "Xq#aaaa",                            # répétition
    "Xq#abcd",                            # suite croissante
    "Xq#4321",                            # suite décroissante
    "Xq#qsdf",                            # ligne de clavier AZERTY
    "Xq#s0l3il",                          # mot courant en leet speak
    "azertyuiop1234aaa",                  # plusieurs motifs sans chevauchement
    "é",                                  # caractère hors familles
    "Ça-va-très-bien-merci-2026",         # accents + symboles
    "🔐🔐🔐Kx9#mP2!",                     # émojis (1 caractère chacun) + répétition
    "XYZ-tuv-Q8!m",                       # suites en majuscules et minuscules
]


def build_case(password: str) -> dict:
    r = analyze(password)
    return {
        "password": password,
        "length": r.length,
        "classes": sorted(r.classes),
        "pool_size": r.pool_size,
        "entropy_bits": round(r.entropy_bits, 2),
        "effective_entropy_bits": round(r.effective_entropy_bits, 2),
        "is_common": r.is_common,
        "patterns": [{"kind": m.kind, "start": m.start, "length": m.length} for m in r.patterns],
        "score": r.score,
    }


def main() -> None:
    target = Path(__file__).resolve().parent.parent / "shared" / "test-vectors.json"
    payload = {
        "description": "Cas de test communs aux moteurs Python et TypeScript. "
                       "Généré par scripts/generate_test_vectors.py — ne pas modifier à la main.",
        "tolerance_bits": 0.01,
        "cases": [build_case(p) for p in PASSWORDS],
    }
    target.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"{len(PASSWORDS)} cas écrits dans {target}")


if __name__ == "__main__":
    main()
