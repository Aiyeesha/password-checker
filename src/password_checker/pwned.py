"""
Vérification des fuites de données — étape 4 : API Pwned Passwords (Have I Been Pwned).

La base Pwned Passwords recense des centaines de millions de mots de passe
réellement divulgués lors de fuites. Le problème : comment vérifier qu'un mot
de passe y figure SANS l'envoyer à un service tiers ?

Réponse : la k-anonymité.
1. On calcule localement l'empreinte SHA-1 du mot de passe (40 caractères hexadécimaux).
2. On n'envoie que les 5 PREMIERS caractères (le « préfixe »).
3. L'API renvoie tous les suffixes connus commençant par ce préfixe (≈ 800 à 1 000).
4. On cherche NOTRE suffixe dans cette liste, localement.
Le service ne voit qu'un préfixe partagé par des centaines de mots de passe
différents : il ne peut pas savoir lequel nous vérifions.

L'en-tête « Add-Padding: true » ajoute de faux résultats (compteur à 0) pour
que la TAILLE de la réponse ne trahisse rien non plus.

Remarque importante : SHA-1 est utilisé ici uniquement parce que c'est le
format de l'API. Il ne faut JAMAIS l'utiliser pour STOCKER des mots de passe
(on utilise pour cela Argon2id, scrypt ou bcrypt).

Documentation : https://haveibeenpwned.com/API/v3#PwnedPasswords
"""

from __future__ import annotations

import hashlib                      # calcul de l'empreinte SHA-1
import re                           # validation du format du préfixe
import urllib.error                 # erreurs réseau de la bibliothèque standard
import urllib.request               # client HTTP de la bibliothèque standard
from collections.abc import Callable

# ─────────────────────────────────────────────────────────────
# 1. Configuration
# ─────────────────────────────────────────────────────────────
# HTTPS imposé dans l'adresse : le préfixe ne circule jamais en clair.
API_URL = "https://api.pwnedpasswords.com/range/{prefix}"
# Identifie poliment le client, comme le demande la documentation de l'API.
USER_AGENT = "password-checker (projet pedagogique open source)"
TIMEOUT_SECONDS = 10                # au-delà, on abandonne au lieu de bloquer
PREFIX_LENGTH = 5

# Un préfixe valide : exactement 5 caractères hexadécimaux majuscules
_PREFIX_PATTERN = re.compile(r"^[0-9A-F]{5}$")

# Type d'une fonction qui, à partir d'un préfixe, renvoie le texte de la réponse.
# Le rendre paramétrable permet de tester SANS appeler Internet (voir les tests).
Fetcher = Callable[[str], str]


class PwnedCheckError(Exception):
    """La vérification n'a pas pu aboutir (réseau, délai dépassé, réponse invalide)."""


# ─────────────────────────────────────────────────────────────
# 2. Empreinte et découpage
# ─────────────────────────────────────────────────────────────
def sha1_hex(password: str) -> str:
    """Empreinte SHA-1 du mot de passe, en hexadécimal MAJUSCULE (format de l'API)."""
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()


def split_hash(full_hash: str) -> tuple[str, str]:
    """Sépare l'empreinte en préfixe (envoyé) et suffixe (gardé localement)."""
    return full_hash[:PREFIX_LENGTH], full_hash[PREFIX_LENGTH:]


# ─────────────────────────────────────────────────────────────
# 3. Appel réseau (la seule fonction qui sort de la machine)
# ─────────────────────────────────────────────────────────────
def fetch_range(prefix: str, timeout: float = TIMEOUT_SECONDS) -> str:
    """Interroge l'API pour un préfixe et renvoie le texte brut de la réponse."""
    # Garde-fou : on refuse d'envoyer autre chose qu'un préfixe de 5 caractères.
    # Ainsi, une erreur de programmation ne peut jamais envoyer l'empreinte complète.
    if not _PREFIX_PATTERN.match(prefix):
        raise ValueError("Le préfixe doit contenir exactement 5 caractères hexadécimaux majuscules.")

    request = urllib.request.Request(
        API_URL.format(prefix=prefix),
        headers={"User-Agent": USER_AGENT, "Add-Padding": "true"},
    )
    try:
        # « with » garantit la fermeture de la connexion, même en cas d'erreur
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.read().decode("utf-8")
    except (urllib.error.URLError, TimeoutError) as error:
        # « from error » conserve la cause d'origine pour le débogage
        raise PwnedCheckError("Service Pwned Passwords injoignable.") from error


# ─────────────────────────────────────────────────────────────
# 4. Lecture de la réponse
# ─────────────────────────────────────────────────────────────
def parse_range(body: str) -> dict[str, int]:
    """
    Transforme les lignes « SUFFIXE:NOMBRE » en dictionnaire {suffixe: nombre}.
    Les entrées de remplissage (nombre = 0) sont écartées.
    """
    results: dict[str, int] = {}
    for line in body.splitlines():
        suffix, _, count = line.strip().partition(":")
        if not count:
            continue                        # ligne vide ou mal formée : ignorée
        try:
            occurrences = int(count)
        except ValueError as error:
            raise PwnedCheckError("Réponse de l'API dans un format inattendu.") from error
        if occurrences > 0:                 # 0 = faux résultat ajouté par le padding
            results[suffix.upper()] = occurrences
    return results


# ─────────────────────────────────────────────────────────────
# 5. Point d'entrée public
# ─────────────────────────────────────────────────────────────
def pwned_count(password: str, fetch: Fetcher = fetch_range) -> int:
    """
    Nombre de fois où ce mot de passe apparaît dans des fuites connues (0 = jamais vu).
    `fetch` est remplaçable : les tests y injectent une fausse réponse.
    """
    prefix, suffix = split_hash(sha1_hex(password))
    return parse_range(fetch(prefix)).get(suffix, 0)
