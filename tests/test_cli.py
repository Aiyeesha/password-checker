"""
Tests de l'interface en ligne de commande (étape 5).

La saisie (read_password) et l'API (fetch) sont remplacées par des fonctions
de test : aucun clavier, aucun réseau. `capsys` est un outil de pytest qui
capture ce que le programme affiche, pour pouvoir le vérifier.
"""

import json

import pytest

from password_checker import __version__, cli
from password_checker.pwned import PwnedCheckError

FORT = "q7#Lm2!vXp9@Rt4z"          # aucun motif, ≈ 105 bits
FAIBLE = "motdepasse"              # liste des plus courants


# ─── Fonctions utilitaires ─────────────────────────────────────
def saisie(mot_de_passe):
    """Fabrique une fausse saisie clavier qui renvoie toujours ce mot de passe."""
    return lambda invite: mot_de_passe


def api_absent(prefixe):
    return "00000000000000000000000000000000000:1\r\n"   # notre suffixe n'y est pas


def api_en_panne(prefixe):
    raise PwnedCheckError("réseau indisponible")


# ─── Codes de sortie ───────────────────────────────────────────
def test_mot_de_passe_fort_et_absent_des_fuites_renvoie_0():
    assert cli.main([], read_password=saisie(FORT), fetch=api_absent) == 0


def test_mot_de_passe_faible_renvoie_1():
    assert cli.main(["--offline"], read_password=saisie(FAIBLE)) == 1


def test_mot_de_passe_trouve_dans_les_fuites_renvoie_1(capsys):
    def api_trouve(prefixe):
        from password_checker.pwned import sha1_hex, split_hash
        _, suffixe = split_hash(sha1_hex(FORT))
        return f"{suffixe}:42\r\n"

    assert cli.main(["--no-color"], read_password=saisie(FORT), fetch=api_trouve) == 1
    assert "TROUVÉ dans 42 fuites" in capsys.readouterr().out


def test_saisie_vide_renvoie_2():
    assert cli.main([], read_password=saisie("")) == 2


def test_ctrl_c_renvoie_130():
    def interrompu(invite):
        raise KeyboardInterrupt

    assert cli.main([], read_password=interrompu) == 130


# ─── Mode hors ligne et panne réseau ───────────────────────────
def test_offline_n_appelle_jamais_l_api():
    def api_interdite(prefixe):
        raise AssertionError("l'API ne doit pas être appelée en mode --offline")

    cli.main(["--offline"], read_password=saisie(FORT), fetch=api_interdite)


def test_une_panne_reseau_ne_fait_pas_planter_le_programme(capsys):
    code = cli.main(["--no-color"], read_password=saisie(FORT), fetch=api_en_panne)
    assert code == 0                                   # l'analyse locale reste valable
    assert "vérification impossible" in capsys.readouterr().out


# ─── Sortie JSON ───────────────────────────────────────────────
def test_sortie_json_valide_et_complete(capsys):
    cli.main(["--json", "--offline"], read_password=saisie(FAIBLE))
    resultat = json.loads(capsys.readouterr().out)      # échoue si le JSON est invalide
    assert resultat["niveau"] == "très faible"
    assert resultat["mot_de_passe_courant"] is True
    assert resultat["fuites"] == {"statut": "non vérifié", "occurrences": None}


# ─── Sécurité ──────────────────────────────────────────────────
@pytest.mark.parametrize("options", [["--offline", "--no-color"], ["--offline", "--json"]])
def test_le_mot_de_passe_n_est_jamais_affiche(capsys, options):
    cli.main(options, read_password=saisie(FORT))
    sortie = capsys.readouterr()
    assert FORT not in sortie.out
    assert FORT not in sortie.err


def test_no_color_supprime_les_codes_ansi(capsys):
    cli.main(["--offline", "--no-color"], read_password=saisie(FORT))
    assert "\033[" not in capsys.readouterr().out


# ─── Version ───────────────────────────────────────────────────
def test_option_version(capsys):
    # argparse termine le programme après --version : on intercepte cette sortie
    with pytest.raises(SystemExit):
        cli.main(["--version"])
    assert __version__ in capsys.readouterr().out
    