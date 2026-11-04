"""
Cas de test partagés avec le moteur TypeScript (shared/test-vectors.json).

Le moteur Python est la référence : ce test garantit que le fichier partagé
reste cohérent avec lui. Le même fichier est relu par web/tests/vectors.test.ts,
ce qui garantit que les deux moteurs donnent les mêmes résultats.
"""

import json
from pathlib import Path

import pytest

from password_checker.strength import analyze

# Chemin du fichier partagé, calculé à partir de l'emplacement de ce test
VECTORS_FILE = Path(__file__).resolve().parent.parent / "shared" / "test-vectors.json"
VECTORS = json.loads(VECTORS_FILE.read_text(encoding="utf-8"))
TOLERANCE = VECTORS["tolerance_bits"]


# ids=… : chaque cas apparaît sous un nom lisible dans le rapport de pytest
@pytest.mark.parametrize("cas", VECTORS["cases"], ids=lambda c: repr(c["password"]))
def test_le_moteur_python_respecte_les_vecteurs_partages(cas):
    rapport = analyze(cas["password"])
    assert rapport.length == cas["length"]
    assert sorted(rapport.classes) == cas["classes"]
    assert rapport.pool_size == cas["pool_size"]
    assert rapport.entropy_bits == pytest.approx(cas["entropy_bits"], abs=TOLERANCE)
    assert rapport.effective_entropy_bits == pytest.approx(cas["effective_entropy_bits"], abs=TOLERANCE)
    assert rapport.is_common == cas["is_common"]
    assert [
        {"kind": m.kind, "start": m.start, "length": m.length} for m in rapport.patterns
    ] == cas["patterns"]
    assert rapport.score == cas["score"]
