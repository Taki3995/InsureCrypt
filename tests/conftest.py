import os
import sys
from pathlib import Path
import pytest

# Añade src/ al path para permitir importaciones directas de los módulos
SRC_PATH = Path(__file__).resolve().parent.parent / "src"
if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))

# los imports van despues de meter src/ en el path a proposito (si no no los encuentra), x eso el noqa E402
import auth  # noqa: E402
import key_manager  # noqa: E402
import main  # noqa: E402
import secure_storage  # noqa: E402


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
    monkeypatch.setattr(key_manager, "PRIVATE_KEY_PATH", temp_keys / "private_key.enc")
    monkeypatch.setattr(key_manager, "CERTIFICATE_PATH", temp_keys / "certificate.pem")
    monkeypatch.setattr(key_manager, "INTEGRITY_SALT_PATH", temp_keys / "integrity.salt")

    # clave hmac aleatoria pa cada test (en la app de verdad sale de la maestra al arrancar)
    monkeypatch.setattr(secure_storage, "_clave_integridad", os.urandom(32))

    yield