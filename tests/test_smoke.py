"""
Test de fumée (« smoke test ») : la vérification la plus simple possible.

Il ne teste aucune fonctionnalité. Il confirme que le paquet est correctement
installé, importable, et que la version installée est cohérente.
"""

from importlib.metadata import version   # lit les métadonnées du paquet INSTALLÉ

import password_checker


def test_le_paquet_expose_sa_version():
    assert password_checker.__version__ == "1.0.0"


def test_la_version_installee_correspond_au_code():
    # Si ce test échoue, le paquet n'a pas été réinstallé après un changement
    # de version : relancez « pip install -e ".[dev]" ».
    assert version("password-checker") == password_checker.__version__
