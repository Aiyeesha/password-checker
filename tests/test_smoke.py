"""
Test de fumée (« smoke test ») : la vérification la plus simple possible.

Il ne teste aucune fonctionnalité. Il confirme seulement que le paquet est
correctement installé et importable. S'il échoue, inutile d'aller plus loin.
"""

# Importe le paquet installé (et non un fichier local, grâce au dossier src/)
import password_checker


def test_le_paquet_expose_sa_version():
    # Chaque fonction dont le nom commence par « test_ » est lancée par pytest.
    # « assert » échoue si la condition est fausse.
    assert password_checker.__version__ == "0.1.0"