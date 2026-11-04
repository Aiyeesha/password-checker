"""
Interface en ligne de commande — étape 5.

Utilisation :
    password-checker              analyse + vérification des fuites (Have I Been Pwned)
    password-checker --offline    analyse locale uniquement, aucun appel réseau
    password-checker --json       sortie JSON (script, SIEM, pipeline CI)
    password-checker --no-color   sortie sans couleurs
    password-checker --version    affiche la version

Le mot de passe est TOUJOURS saisi de façon masquée (getpass) : il n'apparaît
ni à l'écran, ni dans l'historique du terminal, ni dans les arguments du
processus (visibles par les autres utilisateurs via le gestionnaire des tâches).

Codes de sortie (utiles dans un script) :
    0   mot de passe « fort » ou « très fort » et absent des fuites connues
    1   mot de passe trop faible OU présent dans des fuites
    2   erreur d'utilisation (option inconnue, saisie vide)
    130 interruption par l'utilisateur (Ctrl+C)
"""

from __future__ import annotations

import argparse                     # lecture des options de la ligne de commande
import getpass                      # saisie masquée
import json                         # sortie --json
import os                           # variable d'environnement NO_COLOR
import sys                          # flux de sortie et détection du terminal
from collections.abc import Callable

from password_checker import __version__
from password_checker.pwned import Fetcher, PwnedCheckError, fetch_range, pwned_count
from password_checker.strength import StrengthReport, analyze

# ─────────────────────────────────────────────────────────────
# 1. Codes de sortie et couleurs
# ─────────────────────────────────────────────────────────────
EXIT_OK = 0
EXIT_WEAK = 1
EXIT_USAGE = 2
EXIT_INTERRUPTED = 130              # convention Unix : 128 + numéro du signal SIGINT (2)

# Codes ANSI : séquences que le terminal interprète comme des couleurs
_COLORS = {"rouge": "\033[91m", "orange": "\033[93m", "vert": "\033[92m", "gras": "\033[1m"}
_RESET = "\033[0m"
_LEVEL_COLORS = {0: "rouge", 1: "orange", 2: "vert", 3: "vert"}

# États possibles de la vérification des fuites
PWNED_FOUND = "trouvé"
PWNED_ABSENT = "absent"
PWNED_SKIPPED = "non vérifié"
PWNED_ERROR = "erreur"


# ─────────────────────────────────────────────────────────────
# 2. Options de la ligne de commande
# ─────────────────────────────────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="password-checker",
        description="Analyse la robustesse d'un mot de passe et vérifie s'il a fuité "
                    "(k-anonymité : seuls 5 caractères d'empreinte quittent la machine).",
    )
    parser.add_argument("--offline", action="store_true",
                        help="n'effectue aucun appel réseau (pas de vérification des fuites)")
    parser.add_argument("--json", action="store_true",
                        help="produit un résultat JSON au lieu d'un rapport lisible")
    parser.add_argument("--no-color", action="store_true",
                        help="désactive les couleurs")
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {__version__}")
    return parser


# ─────────────────────────────────────────────────────────────
# 3. Vérification des fuites, sans jamais faire planter le programme
# ─────────────────────────────────────────────────────────────
def check_pwned(password: str, offline: bool, fetch: Fetcher) -> tuple[str, int | None]:
    """Retourne (état, nombre d'occurrences ou None)."""
    if offline:
        return PWNED_SKIPPED, None
    try:
        count = pwned_count(password, fetch=fetch)
    except PwnedCheckError:
        # Réseau indisponible : on le signale, l'analyse locale reste valable
        return PWNED_ERROR, None
    return (PWNED_FOUND if count > 0 else PWNED_ABSENT), count


def exit_code(report: StrengthReport, pwned_status: str) -> int:
    if report.score < 2 or pwned_status == PWNED_FOUND:
        return EXIT_WEAK
    return EXIT_OK


# ─────────────────────────────────────────────────────────────
# 4. Mise en forme des résultats (le mot de passe n'y figure JAMAIS)
# ─────────────────────────────────────────────────────────────
def to_dict(report: StrengthReport, pwned_status: str, pwned: int | None) -> dict:
    """Résultat structuré pour --json : uniquement des mesures."""
    return {
        "longueur": report.length,
        "familles": sorted(report.classes),          # ensemble -> liste triée (JSON n'a pas d'ensemble)
        "taille_alphabet": report.pool_size,
        "entropie_theorique_bits": round(report.entropy_bits, 1),
        "entropie_effective_bits": round(report.effective_entropy_bits, 1),
        "mot_de_passe_courant": report.is_common,
        "motifs": [{"type": m.kind, "position": m.start, "longueur": m.length}
                   for m in report.patterns],
        "score": report.score,
        "niveau": report.level,
        "conseils": list(report.feedback),
        "fuites": {"statut": pwned_status, "occurrences": pwned},
    }


def _paint(text: str, color: str, enabled: bool) -> str:
    return f"{_COLORS[color]}{text}{_RESET}" if enabled else text


def to_text(report: StrengthReport, pwned_status: str, pwned: int | None, color: bool) -> str:
    """Rapport lisible pour un humain."""
    level = _paint(report.level.upper(), _LEVEL_COLORS[report.score], color)
    lines = [
        _paint("Analyse du mot de passe", "gras", color),
        f"  Niveau             : {level}",
        f"  Longueur           : {report.length} caractères",
        f"  Familles           : {', '.join(sorted(report.classes)) or 'aucune'}",
        f"  Entropie théorique : {report.entropy_bits:.1f} bits",
        f"  Entropie effective : {report.effective_entropy_bits:.1f} bits",
    ]

    # Ligne consacrée aux fuites
    if pwned_status == PWNED_FOUND:
        leak = _paint(f"TROUVÉ dans {pwned:,} fuites connues".replace(",", " "), "rouge", color)
    elif pwned_status == PWNED_ABSENT:
        leak = _paint("absent des fuites connues", "vert", color)
    elif pwned_status == PWNED_ERROR:
        leak = _paint("vérification impossible (réseau indisponible)", "orange", color)
    else:
        leak = "non vérifié (--offline)"
    lines.append(f"  Fuites (HIBP)      : {leak}")

    if pwned_status == PWNED_FOUND:
        lines.append("  → Ce mot de passe est connu des attaquants : ne l'utilisez plus nulle part.")
    if report.feedback:
        lines.append(_paint("Conseils", "gras", color))
        lines += [f"  - {message}" for message in report.feedback]
    return "\n".join(lines)


def _color_enabled(no_color_flag: bool) -> bool:
    """Couleurs seulement dans un vrai terminal, et si l'utilisateur ne les a pas refusées."""
    # NO_COLOR : convention partagée par de nombreux outils (https://no-color.org)
    return not no_color_flag and "NO_COLOR" not in os.environ and sys.stdout.isatty()


# ─────────────────────────────────────────────────────────────
# 5. Point d'entrée
# ─────────────────────────────────────────────────────────────
def main(
    argv: list[str] | None = None,
    *,
    read_password: Callable[[str], str] = getpass.getpass,
    fetch: Fetcher = fetch_range,
) -> int:
    """
    Point d'entrée de la commande `password-checker`.
    `read_password` et `fetch` sont remplaçables pour les tests (aucune saisie, aucun réseau).
    """
    args = build_parser().parse_args(argv)

    try:
        password = read_password("Mot de passe (saisie masquée) : ")
    except (KeyboardInterrupt, EOFError):
        print("\nAnalyse annulée.", file=sys.stderr)
        return EXIT_INTERRUPTED

    if not password:
        print("Aucun mot de passe saisi.", file=sys.stderr)
        return EXIT_USAGE

    report = analyze(password)
    status, count = check_pwned(password, args.offline, fetch)
    # On n'a plus besoin du mot de passe : on supprime la référence au plus tôt.
    # (Python ne garantit pas l'effacement de la mémoire, mais on limite sa durée de vie.)
    del password

    if args.json:
        print(json.dumps(to_dict(report, status, count), ensure_ascii=False, indent=2))
    else:
        print(to_text(report, status, count, _color_enabled(args.no_color)))

    return exit_code(report, status)

