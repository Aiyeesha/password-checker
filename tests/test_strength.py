"""
Tests du moteur d'analyse (étapes 2 et 3).

Chaque test vérifie UNE règle précise. Si un test échoue, son nom indique
immédiatement quelle règle est cassée.
"""

import math

import pytest

from password_checker.strength import analyze


# ─── Cas limites ───────────────────────────────────────────────
def test_mot_de_passe_vide():
    rapport = analyze("")
    assert rapport.length == 0
    assert rapport.entropy_bits == 0
    assert rapport.score == 0
    assert any("vide" in message for message in rapport.feedback)


def test_refuse_un_type_autre_que_str():
    # pytest.raises vérifie qu'une erreur est bien levée
    with pytest.raises(TypeError):
        analyze(12345)


# ─── Détection des familles et taille de l'alphabet ───────────
def test_minuscules_seules_donnent_un_alphabet_de_26():
    rapport = analyze("abcdefgh")
    assert rapport.classes == frozenset({"minuscules"})
    assert rapport.pool_size == 26
    # pytest.approx tolère les infimes erreurs d'arrondi des nombres décimaux
    assert rapport.entropy_bits == pytest.approx(8 * math.log2(26))


def test_quatre_familles_donnent_un_alphabet_de_95():
    rapport = analyze("aA1!")
    assert rapport.classes == frozenset({"minuscules", "majuscules", "chiffres", "symboles"})
    assert rapport.pool_size == 26 + 26 + 10 + 33


def test_un_caractere_accentue_compte_dans_autres():
    rapport = analyze("é")
    assert rapport.classes == frozenset({"autres"})
    assert rapport.pool_size == 100


# ─── Score ─────────────────────────────────────────────────────
def test_moins_de_8_caracteres_est_toujours_tres_faible():
    rapport = analyze("Zx9!Qw2")          # 7 caractères, 4 familles
    assert rapport.score == 0
    assert any("Trop court" in message for message in rapport.feedback)


# parametrize : le même test rejoué avec plusieurs jeux de données
@pytest.mark.parametrize(
    "mot_de_passe, niveau_attendu",
    [
        ("motdepasse", "très faible"),                    # liste des plus courants : 10 bits
        ("motdepassesecret", "très faible"),              # 2 mots courants ≈ 25,8 bits
        ("Tr0ub4dour&3xyz", "fort"),                      # « xyz » est une suite ≈ 87,4 bits
        ("correct horse battery staple", "faible"),       # 4 mots + 3 espaces ≈ 69,3 bits
        ("q7#Lm2!vXp9@Rt4z", "très fort"),                # 16 caractères sans motif ≈ 105 bits
    ],
)
def test_niveau_selon_l_entropie_effective(mot_de_passe, niveau_attendu):
    # Depuis l'étape 3, le niveau repose sur l'entropie EFFECTIVE (motifs déduits)
    assert analyze(mot_de_passe).level == niveau_attendu


def test_conseille_15_caracteres_entre_8_et_14():
    rapport = analyze("abcdefghij")       # 10 caractères
    assert any("15" in message for message in rapport.feedback)


def test_l_entropie_theorique_reste_disponible():
    # « motdepassesecret » : 16 × log2(26) ≈ 75 bits en théorie, bien moins en réalité
    rapport = analyze("motdepassesecret")
    assert rapport.entropy_bits == pytest.approx(16 * math.log2(26))
    assert rapport.effective_entropy_bits < rapport.entropy_bits


# ─── Sécurité ──────────────────────────────────────────────────
def test_le_rapport_ne_contient_jamais_le_mot_de_passe():
    secret = "S3cr3t-Unique!"
    rapport = analyze(secret)
    # repr() produit la représentation texte complète de l'objet,
    # celle qui apparaîtrait dans un log ou un message d'erreur
    assert secret not in repr(rapport)


def test_le_rapport_ne_cite_pas_le_mot_courant_trouve():
    # Le motif « soleil » est détecté, mais son texte ne doit apparaître nulle part
    rapport = analyze("Xk9#soleil!Tq")
    assert rapport.patterns                     # au moins un motif trouvé
    assert "soleil" not in repr(rapport)