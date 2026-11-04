"""
Moteur d'analyse de robustesse — étapes 2 et 3 : longueur, familles de
caractères, entropie théorique et entropie effective.

Ce module évalue un mot de passe SANS jamais le conserver : le rapport produit
ne contient que des mesures (longueur, familles, entropie, score), jamais le
mot de passe lui-même.

Références utilisées pour les seuils :
- CNIL, délibération n° 2022-100 : 80 bits d'entropie minimum pour un mot de
  passe utilisé seul, 50 bits si l'accès est restreint (blocage, captcha…).
- NIST SP 800-63B-4 : 15 caractères minimum pour un mot de passe utilisé seul,
  8 caractères minimum s'il fait partie d'une authentification multifacteur.

Deux entropies sont calculées :
- l'entropie THÉORIQUE (étape 2), qui suppose des caractères tirés au hasard ;
- l'entropie EFFECTIVE (étape 3), corrigée des motifs faibles détectés par
  le module patterns (dictionnaire, clavier, suites, répétitions, leet speak).
Le score repose sur l'entropie effective, la seule qui reflète une vraie attaque.
"""

# Permet d'écrire les annotations de type sous forme moderne (ex. tuple[str, ...])
from __future__ import annotations

import math                         # log2 pour le calcul d'entropie
import string                       # alphabets prédéfinis (a-z, A-Z, 0-9, ponctuation)
from dataclasses import dataclass   # structure de données immuable pour le rapport

# Détection des motifs faibles (étape 3)
from password_checker.patterns import (
    PatternMatch,
    effective_entropy,
    find_patterns,
    is_common_password,
)

# ─────────────────────────────────────────────────────────────
# 1. Familles de caractères reconnues
# ─────────────────────────────────────────────────────────────
# Chaque famille est un ensemble figé (frozenset) : la recherche
# « ce caractère appartient-il à la famille ? » est instantanée.
CHARACTER_CLASSES: dict[str, frozenset[str]] = {
    "minuscules": frozenset(string.ascii_lowercase),       # 26 caractères
    "majuscules": frozenset(string.ascii_uppercase),       # 26 caractères
    "chiffres": frozenset(string.digits),                  # 10 caractères
    "symboles": frozenset(string.punctuation + " "),       # 32 signes + l'espace = 33
}

# Caractères hors des familles ci-dessus (é, ç, ß, emoji…). Leur alphabet réel
# est immense ; on retient une estimation prudente et documentée.
OTHER_CLASS_NAME = "autres"
OTHER_POOL_SIZE = 100

# ─────────────────────────────────────────────────────────────
# 2. Seuils (voir les références en tête de fichier)
# ─────────────────────────────────────────────────────────────
NIST_MIN_LENGTH = 8                 # en dessous : toujours « très faible »
NIST_MIN_LENGTH_SINGLE_FACTOR = 15  # recommandé sans double authentification
CNIL_RESTRICTED_BITS = 50           # minimum avec restrictions d'accès
CNIL_STANDALONE_BITS = 80           # minimum pour un mot de passe utilisé seul
VERY_STRONG_BITS = 100              # marge confortable au-delà du minimum CNIL

# Libellés des scores 0 à 3, dans l'ordre
LEVELS: tuple[str, ...] = ("très faible", "faible", "fort", "très fort")


# ─────────────────────────────────────────────────────────────
# 3. Le rapport d'analyse
# ─────────────────────────────────────────────────────────────
# frozen=True : le rapport ne peut plus être modifié une fois créé.
# Il ne contient volontairement AUCUN champ pour le mot de passe.
@dataclass(frozen=True)
class StrengthReport:
    length: int                    # nombre de caractères
    classes: frozenset[str]        # familles présentes (ex. {"minuscules", "chiffres"})
    pool_size: int                 # taille de l'alphabet correspondant
    entropy_bits: float            # entropie théorique, en bits (étape 2)
    effective_entropy_bits: float  # entropie corrigée des motifs faibles (étape 3)
    is_common: bool                # figure dans la liste des mots de passe les plus courants
    patterns: tuple[PatternMatch, ...]  # motifs faibles (type, position, longueur — jamais le texte)
    score: int                     # de 0 (très faible) à 3 (très fort)
    feedback: tuple[str, ...]      # conseils lisibles, en français

    @property
    def level(self) -> str:
        """Libellé du score (ex. « faible »)."""
        return LEVELS[self.score]


# ─────────────────────────────────────────────────────────────
# 4. Fonctions élémentaires (chacune testable isolément)
# ─────────────────────────────────────────────────────────────
def detect_classes(password: str) -> frozenset[str]:
    """Retourne le nom des familles de caractères présentes dans le mot de passe."""
    found: set[str] = set()
    for char in password:
        # Cherche la première famille qui contient ce caractère
        for name, members in CHARACTER_CLASSES.items():
            if char in members:
                found.add(name)
                break
        else:
            # Le « else » d'une boucle for s'exécute si aucun « break » n'a eu lieu :
            # le caractère n'appartient à aucune famille connue.
            found.add(OTHER_CLASS_NAME)
    return frozenset(found)


def pool_size(classes: frozenset[str]) -> int:
    """Additionne la taille des alphabets des familles présentes."""
    total = 0
    for name in classes:
        if name == OTHER_CLASS_NAME:
            total += OTHER_POOL_SIZE
        else:
            total += len(CHARACTER_CLASSES[name])
    return total


def entropy_bits(length: int, pool: int) -> float:
    """
    Entropie théorique : E = L × log2(N)
    L = longueur, N = taille de l'alphabet.
    Chaque bit DOUBLE le nombre d'essais nécessaires à une attaque par force brute.
    """
    if length == 0 or pool <= 1:
        return 0.0
    return length * math.log2(pool)


def score_from(entropy: float, length: int) -> int:
    """Convertit l'entropie (et la longueur) en score de 0 à 3."""
    if length < NIST_MIN_LENGTH:
        return 0                       # trop court, quelle que soit l'entropie
    if entropy < CNIL_RESTRICTED_BITS:
        return 0
    if entropy < CNIL_STANDALONE_BITS:
        return 1
    if entropy < VERY_STRONG_BITS:
        return 2
    return 3


# Message associé à chaque type de motif
_PATTERN_ADVICE = {
    "dictionnaire": "Contient un mot courant (même déguisé en leet speak, ex. « P@ssw0rd »).",
    "clavier": "Contient une suite de touches voisines du clavier (ex. « azer », « qsdf »).",
    "suite": "Contient une suite logique de caractères (ex. « abc », « 1234 »).",
    "répétition": "Contient un caractère répété plusieurs fois (ex. « aaa », « 111 »).",
}


def _build_feedback(
    length: int,
    classes: frozenset[str],
    entropy: float,
    is_common: bool = False,
    patterns: tuple[PatternMatch, ...] = (),
) -> tuple[str, ...]:
    """Rédige les conseils. Fonction « privée » (préfixe _) : détail interne du module."""
    messages: list[str] = []

    if length == 0:
        return ("Le mot de passe est vide.",)

    # Le pire cas d'abord : un mot de passe de la liste des plus courants
    if is_common:
        messages.append(
            "Mot de passe parmi les plus utilisés au monde : "
            "il serait trouvé dès les premières secondes d'une attaque."
        )

    # Un conseil par TYPE de motif trouvé (sans jamais citer le texte concerné)
    for kind in dict.fromkeys(m.kind for m in patterns):   # dédoublonne en gardant l'ordre
        messages.append(_PATTERN_ADVICE[kind])

    # Conseils sur la longueur (critère le plus efficace)
    if length < NIST_MIN_LENGTH:
        messages.append(
            f"Trop court : moins de {NIST_MIN_LENGTH} caractères "
            "(minimum absolu du NIST SP 800-63B-4)."
        )
    elif length < NIST_MIN_LENGTH_SINGLE_FACTOR:
        messages.append(
            f"Moins de {NIST_MIN_LENGTH_SINGLE_FACTOR} caractères : c'est le minimum "
            "recommandé par le NIST quand il n'y a pas de double authentification."
        )

    # Conseils sur l'entropie et les familles absentes
    if entropy < CNIL_STANDALONE_BITS:
        messages.append(
            f"Entropie estimée à {entropy:.0f} bits, sous les {CNIL_STANDALONE_BITS} bits "
            "recommandés par la CNIL pour un mot de passe utilisé seul."
        )
        missing = [name for name in CHARACTER_CLASSES if name not in classes]
        if missing:
            messages.append(
                "Piste : allonger le mot de passe (le plus efficace) "
                f"ou ajouter des {', '.join(missing)}."
            )

    return tuple(messages)


# ─────────────────────────────────────────────────────────────
# 5. Point d'entrée public du module
# ─────────────────────────────────────────────────────────────
def analyze(password: str) -> StrengthReport:
    """Analyse un mot de passe et retourne un rapport qui ne le contient pas."""
    # Validation défensive : refuser tout ce qui n'est pas une chaîne
    if not isinstance(password, str):
        raise TypeError("Le mot de passe doit être une chaîne de caractères (str).")

    length = len(password)
    classes = detect_classes(password)
    pool = pool_size(classes)
    entropy = entropy_bits(length, pool)

    # Étape 3 : motifs faibles et entropie corrigée
    common = is_common_password(password)
    patterns = find_patterns(password)
    effective = effective_entropy(password, pool, patterns)

    return StrengthReport(
        length=length,
        classes=classes,
        pool_size=pool,
        entropy_bits=entropy,
        effective_entropy_bits=effective,
        is_common=common,
        patterns=patterns,
        # Le score repose désormais sur l'entropie EFFECTIVE
        score=score_from(effective, length),
        feedback=_build_feedback(length, classes, effective, common, patterns),
    )
