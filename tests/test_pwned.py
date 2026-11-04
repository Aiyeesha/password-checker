"""
Tests de la vérification Have I Been Pwned (étape 4).

AUCUN de ces tests n'appelle Internet : la réponse de l'API est simulée.
Les tests restent ainsi rapides, reproductibles et utilisables hors ligne,
et ne transmettent rien à un service extérieur.
"""

import urllib.error

import pytest

from password_checker import pwned

# Empreinte SHA-1 connue de « password » (vecteur de référence)
SHA1_PASSWORD = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"  # gitleaks:allow (vecteur de test public : SHA-1 de « password »)


# ─── Empreinte et découpage ────────────────────────────────────
def test_sha1_hex_vecteur_de_reference():
    assert pwned.sha1_hex("password") == SHA1_PASSWORD


def test_split_hash_garde_5_caracteres_pour_le_prefixe():
    prefixe, suffixe = pwned.split_hash(SHA1_PASSWORD)
    assert prefixe == "5BAA6"
    assert suffixe == "1E4C9B93F3F0682250B6CF8331B7EE68FD8"   # 35 caractères


# ─── Lecture de la réponse ─────────────────────────────────────
def test_parse_range_ecarte_le_padding_et_les_lignes_vides():
    reponse = "AAAAA:3\r\nbbbbb:12\r\n\r\nCCCCC:0\r\n"
    assert pwned.parse_range(reponse) == {"AAAAA": 3, "BBBBB": 12}


def test_parse_range_refuse_un_format_inattendu():
    with pytest.raises(pwned.PwnedCheckError):
        pwned.parse_range("AAAAA:pas-un-nombre")


# ─── pwned_count avec une fausse API ───────────────────────────
def test_mot_de_passe_trouve_dans_les_fuites():
    prefixes_recus = []                    # mémorise ce que la « fausse API » a reçu

    def fausse_api(prefixe):
        prefixes_recus.append(prefixe)
        return "1E4C9B93F3F0682250B6CF8331B7EE68FD8:9545824\r\nFFFFF:0\r\n"

    assert pwned.pwned_count("password", fetch=fausse_api) == 9545824
    # La k-anonymité est respectée : seuls 5 caractères sont partis
    assert prefixes_recus == ["5BAA6"]


def test_mot_de_passe_absent_des_fuites():
    def fausse_api(prefixe):
        return "0000000000000000000000000000000000A:2\r\n"

    assert pwned.pwned_count("q7#Lm2!vXp9@Rt4z", fetch=fausse_api) == 0


# ─── fetch_range, sans réseau (urlopen est remplacé) ───────────
def test_fetch_range_refuse_un_prefixe_invalide():
    # Garde-fou : impossible d'envoyer l'empreinte complète par erreur
    with pytest.raises(ValueError):
        pwned.fetch_range(SHA1_PASSWORD)


def test_fetch_range_envoie_les_bons_en_tetes(monkeypatch):
    requetes = []

    class FausseReponse:
        # Une réponse doit pouvoir s'utiliser avec « with » : __enter__ et __exit__
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return b"ABCDE:1\r\n"

    def faux_urlopen(requete, timeout):
        requetes.append(requete)
        return FausseReponse()

    # monkeypatch remplace temporairement urlopen, le temps de ce test uniquement
    monkeypatch.setattr(pwned.urllib.request, "urlopen", faux_urlopen)

    assert pwned.fetch_range("5BAA6") == "ABCDE:1\r\n"
    (requete,) = requetes
    assert requete.full_url == "https://api.pwnedpasswords.com/range/5BAA6"
    # urllib normalise le nom des en-têtes : « Add-Padding » devient « Add-padding »
    assert requete.get_header("Add-padding") == "true"
    assert requete.get_header("User-agent")


def test_fetch_range_transforme_une_panne_reseau_en_erreur_claire(monkeypatch):
    def faux_urlopen(requete, timeout):
        raise urllib.error.URLError("réseau indisponible")

    monkeypatch.setattr(pwned.urllib.request, "urlopen", faux_urlopen)

    with pytest.raises(pwned.PwnedCheckError):
        pwned.fetch_range("5BAA6")
        
