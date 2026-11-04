"""
Détection des motifs faibles — étape 3.

Un humain ne choisit pas ses caractères au hasard : il utilise des mots,
des suites (« abcd », « 1234 »), des lignes de clavier (« azerty »), des
répétitions (« aaaa ») et des substitutions prévisibles (« P@ssw0rd »).
Les outils de cassage (John the Ripper, Hashcat) testent ces motifs en
PREMIER. Ce module les repère pour corriger l'entropie théorique de l'étape 2.

Règle de sécurité : un motif détecté est décrit par son TYPE, sa POSITION et
sa LONGUEUR, jamais par son texte. Afficher « mot trouvé : soleil »
révélerait une partie du mot de passe.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

# ─────────────────────────────────────────────────────────────
# 1. Listes de référence (volontairement courtes, à titre pédagogique)
# ─────────────────────────────────────────────────────────────
# Mots de passe les plus utilisés en France et dans le monde.
# Une version « production » chargerait une liste de plusieurs millions
# d'entrées (ex. SecLists) ; l'étape 4 (Have I Been Pwned) couvre ce besoin.
COMMON_PASSWORDS: frozenset[str] = frozenset({
    "123456", "123456789", "12345678", "1234567", "12345", "123123", "000000",
    "111111", "abc123", "password", "password1", "motdepasse", "azerty",
    "azerty123", "azertyuiop", "qwerty", "qwerty123", "admin", "doudou",
    "loulou", "soleil", "bonjour", "marseille", "chouchou", "jetaime",
    "iloveyou", "welcome", "letmein", "football", "dragon", "princesse",
})

# Mots courants recherchés À L'INTÉRIEUR du mot de passe (4 lettres minimum).
COMMON_WORDS: frozenset[str] = frozenset({
    "password", "motdepasse", "pass", "secret", "admin", "azerty", "qwerty",
    "bonjour", "soleil", "amour", "chocolat", "doudou", "loulou", "chouchou",
    "marseille", "paris", "football", "dragon", "princesse", "jetaime",
    "iloveyou", "welcome", "master", "shadow", "sunshine", "monkey",
    # Exemple célèbre de phrase de passe (bande dessinée xkcd n° 936)
    "correct", "horse", "battery", "staple",
})

# Lignes de clavier AZERTY et QWERTY, lues de gauche à droite.
KEYBOARD_ROWS: tuple[str, ...] = (
    "azertyuiop", "qsdfghjklm", "wxcvbn",      # AZERTY
    "qwertyuiop", "asdfghjkl", "zxcvbnm",      # QWERTY
)

# Substitutions « leet speak » : chaque symbole remplacé par la lettre qu'il imite.
# str.maketrans remplace caractère par caractère : la longueur ne change pas,
# donc les positions restent alignées avec le mot de passe d'origine.
LEET_TABLE = str.maketrans({
    "4": "a", "@": "a", "3": "e", "1": "i", "!": "i",
    "0": "o", "$": "s", "5": "s", "7": "t",
})

# ─────────────────────────────────────────────────────────────
# 2. Valeurs utilisées pour recalculer l'entropie
# ─────────────────────────────────────────────────────────────
COMMON_PASSWORD_BITS = 10.0            # testé dans les premières secondes d'une attaque
DICTIONARY_WORD_BITS = math.log2(7776) # ≈ 12,9 bits : un mot tiré d'une liste Diceware de 7 776 mots
PREDICTABLE_CHAR_BITS = 1.0            # chaque caractère d'une suite/répétition au-delà du 1er
MIN_SEQUENCE_LENGTH = 3                # « abc », « 321 », « aaa »
MIN_KEYBOARD_LENGTH = 4                # « azer », « qsdf »

# Ordre de priorité quand deux motifs se chevauchent (0 = gagne)
_PRIORITY = {"dictionnaire": 0, "clavier": 1, "suite": 2, "répétition": 3}


# ─────────────────────────────────────────────────────────────
# 3. Description d'un motif trouvé (sans son texte)
# ─────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class PatternMatch:
    kind: str       # "dictionnaire", "clavier", "suite" ou "répétition"
    start: int      # position du premier caractère (0 = début)
    length: int     # nombre de caractères concernés


# ─────────────────────────────────────────────────────────────
# 4. Normalisation
# ─────────────────────────────────────────────────────────────
def normalize(password: str) -> str:
    """Minuscules + annulation du leet speak : « P@ssw0rd » devient « password »."""
    return password.lower().translate(LEET_TABLE)


def is_common_password(password: str) -> bool:
    """Vrai si le mot de passe entier figure dans la liste des plus courants."""
    lowered = password.lower()
    return lowered in COMMON_PASSWORDS or normalize(password) in COMMON_PASSWORDS


# ─────────────────────────────────────────────────────────────
# 5. Détecteurs : chacun renvoie des « candidats », qui peuvent se chevaucher
# ─────────────────────────────────────────────────────────────
def _find_all(text: str, needle: str, kind: str) -> list[PatternMatch]:
    """Toutes les occurrences de `needle` dans `text`."""
    found = []
    start = text.find(needle)
    while start != -1:
        found.append(PatternMatch(kind, start, len(needle)))
        start = text.find(needle, start + 1)
    return found


def _dictionary_candidates(password: str) -> list[PatternMatch]:
    found = []
    # On cherche dans les deux formes : « soleil » et « s0l3il » (leet) sont repérés
    for form in {password.lower(), normalize(password)}:
        for word in COMMON_WORDS:
            found += _find_all(form, word, "dictionnaire")
    return found


def _keyboard_candidates(password: str) -> list[PatternMatch]:
    lowered = password.lower()
    found = []
    for row in KEYBOARD_ROWS:
        for line in (row, row[::-1]):          # [::-1] = la ligne lue à l'envers
            for size in range(MIN_KEYBOARD_LENGTH, len(line) + 1):
                for i in range(len(line) - size + 1):
                    found += _find_all(lowered, line[i:i + size], "clavier")
    return found


def _sequence_candidates(password: str) -> list[PatternMatch]:
    """Suites croissantes ou décroissantes : « abcd », « 4321 »."""
    text = password.lower()
    found = []
    i = 0
    while i < len(text) - 1:
        delta = ord(text[i + 1]) - ord(text[i])   # écart entre deux codes de caractères
        if delta in (1, -1) and text[i].isalnum() and text[i + 1].isalnum():
            j = i + 1
            # Prolonge la suite tant que l'écart reste identique
            while (j + 1 < len(text) and text[j + 1].isalnum()
                   and ord(text[j + 1]) - ord(text[j]) == delta):
                j += 1
            if j - i + 1 >= MIN_SEQUENCE_LENGTH:
                found.append(PatternMatch("suite", i, j - i + 1))
                i = j
                continue
        i += 1
    return found


def _repetition_candidates(password: str) -> list[PatternMatch]:
    """Le même caractère répété : « aaa », « 1111 »."""
    found = []
    i = 0
    while i < len(password):
        j = i
        while j + 1 < len(password) and password[j + 1] == password[i]:
            j += 1
        if j - i + 1 >= MIN_SEQUENCE_LENGTH:
            found.append(PatternMatch("répétition", i, j - i + 1))
        i = j + 1
    return found


# ─────────────────────────────────────────────────────────────
# 6. Sélection finale : pas de chevauchement
# ─────────────────────────────────────────────────────────────
def find_patterns(password: str) -> tuple[PatternMatch, ...]:
    """Retourne les motifs retenus, sans chevauchement, triés par position."""
    candidates = (
        _dictionary_candidates(password)
        + _keyboard_candidates(password)
        + _sequence_candidates(password)
        + _repetition_candidates(password)
    )
    # Les plus prioritaires d'abord, puis les plus longs, puis les plus à gauche
    candidates.sort(key=lambda m: (_PRIORITY[m.kind], -m.length, m.start))

    covered: set[int] = set()       # positions déjà attribuées à un motif
    selected: list[PatternMatch] = []
    for match in candidates:
        positions = range(match.start, match.start + match.length)
        if covered.isdisjoint(positions):
            selected.append(match)
            covered.update(positions)
    return tuple(sorted(selected, key=lambda m: m.start))


# ─────────────────────────────────────────────────────────────
# 7. Entropie corrigée
# ─────────────────────────────────────────────────────────────
def effective_entropy(password: str, pool: int, matches: tuple[PatternMatch, ...]) -> float:
    """
    Entropie « réaliste » :
    - caractères hors motif : log2(N) bits chacun (comme à l'étape 2) ;
    - mot du dictionnaire   : ≈ 12,9 bits pour le mot ENTIER, quelle que soit sa longueur ;
    - suite / clavier / répétition : log2(N) pour le 1er caractère, puis 1 bit par caractère.
    Un mot de passe de la liste des plus courants vaut 10 bits, point final.
    """
    if not password or pool <= 1:
        return 0.0
    if is_common_password(password):
        return COMMON_PASSWORD_BITS

    per_char = math.log2(pool)
    covered = sum(m.length for m in matches)
    bits = (len(password) - covered) * per_char
    for match in matches:
        if match.kind == "dictionnaire":
            bits += DICTIONARY_WORD_BITS
        else:
            bits += per_char + (match.length - 1) * PREDICTABLE_CHAR_BITS
    # Par construction, l'entropie corrigée ne dépasse jamais l'entropie théorique
    return min(bits, len(password) * per_char)
