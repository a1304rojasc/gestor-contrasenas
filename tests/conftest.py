"""Fixtures comunes.

IMPORTANTE: los parámetros de KDF de aquí son DELIBERADAMENTE inseguros para
que los tests tarden milisegundos. Nunca los uses fuera de los tests.
"""

import pytest

from gestor import kdf

AJUSTES_RAPIDOS = {
    kdf.ARGON2ID: {"tiempo": 1, "memoria_kib": 8, "paralelismo": 1},
    kdf.PBKDF2: {"iteraciones": 1_000},
}


@pytest.fixture
def ajustes_kdf():
    return AJUSTES_RAPIDOS


@pytest.fixture(params=[kdf.ARGON2ID, kdf.PBKDF2])
def params_kdf(request):
    """Parámetros rápidos con sal nueva; se ejecuta para ambos KDF."""
    return kdf.nuevos_parametros(request.param, **AJUSTES_RAPIDOS[request.param])


@pytest.fixture
def ruta(tmp_path):
    return tmp_path / "boveda.json"
