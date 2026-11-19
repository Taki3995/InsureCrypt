import sys
from pathlib import Path
import pytest

# Añade src/ al path para permitir importaciones directas de los módulos
SRC_PATH = Path(__file__).resolve().parent.parent / "src"
if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))

import auth
import key_manager
import main


@pytest.fixture(autouse=True)
def aislar_almacenamiento(tmp_path, monkeypatch):
    """
    Redirige automáticamente todas las rutas de datos y claves a un directorio
    temporal aislado por cada test para no alterar data/ ni keys/ reales.
    """
    temp_data = tmp_path / "data"
    temp_keys = tmp_path / "keys"

    monkeypatch.setattr(auth, "DATA_DIR", temp_data)
    monkeypatch.setattr(auth, "USERS_FILE", temp_data / "users.json")

    monkeypatch.setattr(main, "DATA_DIR", temp_data)
    monkeypatch.setattr(main, "POLICIES_FILE", temp_data / "policies.json")

    monkeypatch.setattr(key_manager, "KEYS_DIR", temp_keys)
    monkeypatch.setattr(key_manager, "PRIVATE_KEY_PATH", temp_keys / "private_key.pem")
    monkeypatch.setattr(key_manager, "PUBLIC_KEY_PATH", temp_keys / "public_key.pem")

    yield