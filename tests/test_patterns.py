"""
Tests de la détection des motifs faibles (étape 3).
"""

import math

import pytest

from password_checker.patterns import (
    COMMON_PASSWORD_BITS,
    DICTIONARY_WORD_BITS,
    effective_entropy,
    find_patterns,
    is_common_password,
    normalize,
)


# ─── Normalisation et liste des plus courants ──────────────────
def test_normalize_annule_le_leet_speak():
    assert normalize("P@ssw0rd") == "password"


@pytest.mark.parametrize("mot_de_passe", ["azerty", "AZERTY", "P@ssw0rd", "s0l3il"])
def test_reconnait_les_mots_de_passe_courants(mot_de_passe):
    assert is_common_password(mot_de_passe)


def test_un_mot_de_passe_aleatoire_n_est_pas_courant():
    assert not is_common_password("q7#Lm2!vXp9@Rt4z")


def test_un_mot_de_passe_courant_vaut_10_bits():
    assert effective_entropy("azerty", 26, find_patterns("azerty")) == COMMON_PASSWORD_BITS


# ─── Chaque type de motif, isolément ───────────────────────────
# Fonction utilitaire : liste des types trouvés, dans l'ordre
def _kinds(password):
    return [m.kind for m in find_patterns(password)]


def test_detecte_une_repetition():
    assert _kinds("Xq#aaaa") == ["répétition"]


@pytest.mark.parametrize("mot_de_passe", ["Xq#abcd", "Xq#4321"])
def test_detecte_une_suite_croissante_ou_decroissante(mot_de_passe):
    assert _kinds(mot_de_passe) == ["suite"]


def test_detecte_une_ligne_de_clavier():
    assert _kinds("Xq#qsdf") == ["clavier"]


def test_detecte_un_mot_meme_en_leet_speak():
    assert _kinds("Xq#s0l3il") == ["dictionnaire"]


def test_position_et_longueur_du_motif():
    (motif,) = find_patterns("Xq#aaaa")     # une seule correspondance attendue
    assert (motif.start, motif.length) == (3, 4)


def test_aucun_motif_dans_un_mot_de_passe_aleatoire():
    assert find_patterns("q7#Lm2!vXp9@Rt4z") == ()


def test_les_motifs_ne_se_chevauchent_pas():
    motifs = find_patterns("azertyuiop1234aaa")
    positions = [p for m in motifs for p in range(m.start, m.start + m.length)]
    assert len(positions) == len(set(positions))   # aucune position comptée deux fois


# ─── Entropie corrigée ─────────────────────────────────────────
def test_un_mot_du_dictionnaire_vaut_12_9_bits_quelle_que_soit_sa_longueur():
    motifs = find_patterns("chocolat")
    assert effective_entropy("chocolat", 26, motifs) == pytest.approx(DICTIONARY_WORD_BITS)


def test_l_entropie_effective_ne_depasse_jamais_la_theorique():
    for mot_de_passe in ["abc", "Xq#aaaa", "q7#Lm2!vXp9@Rt4z", "correct horse"]:
        motifs = find_patterns(mot_de_passe)
        assert effective_entropy(mot_de_passe, 95, motifs) <= len(mot_de_passe) * math.log2(95)