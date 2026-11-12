# Registro y autenticacion de usuarios

import base64
import json
import os
import hmac
from pathlib import Path
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

DATA_DIR = Path("data")
USERS_FILE = DATA_DIR / "users.json"
SALT_SIZE = 16
PBKDF2_ITERATIONS = 600000  # Estándar actual NIST/OWASP para SHA-256


def inicializar_almacen_usuarios() -> None:
    """Crea la carpeta data/ y el archivo users.json si no existen."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not USERS_FILE.exists():
        with open(USERS_FILE, "w", encoding="utf-8") as f:
            json.dump({}, f)


def _cargar_usuarios() -> dict:
    inicializar_almacen_usuarios()
    with open(USERS_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def _guardar_usuarios(usuarios: dict) -> None:
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(usuarios, f, indent=4)


def _derivar_hash(password: str, salt: bytes) -> bytes:
    """Deriva una clave/hash a partir de la contraseña usando PBKDF2HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def registrar_usuario(dni: str, password: str) -> bool:
    """
    Registra un nuevo cliente/usuario. Genera salt de 16 bytes con os.urandom y almacena salt + hash en Base64.
    """
    usuarios = _cargar_usuarios()
    if dni in usuarios:
        raise ValueError(f"El usuario con DNI/ID '{dni}' ya se encuentra registrado.")

    # Generación de salt criptográficamente segura (os.urandom)
    salt = os.urandom(SALT_SIZE)
    password_hash = _derivar_hash(password, salt)

    usuarios[dni] = {
        "salt": base64.b64encode(salt).decode("utf-8"),
        "hash": base64.b64encode(password_hash).decode("utf-8"),
    }

    _guardar_usuarios(usuarios)
    print(f"[LOG SEGURIDAD] Usuario '{dni}' registrado con éxito.")
    print(f"[LOG SEGURIDAD] Mecanismo: PBKDF2HMAC-SHA256 | Sal: 16 bytes | Iteraciones: {PBKDF2_ITERATIONS}.")
    return True


def autenticar_usuario(dni: str, password: str) -> bool:
    """
    Autentica un usuario existente recalculando el hash con su salt y comparándolo en tiempo constante (hmac.compare_digest).
    """
    usuarios = _cargar_usuarios()
    if dni not in usuarios:
        print(f"[LOG SEGURIDAD] Fallo de autenticación: Usuario '{dni}' no existe.")
        return False

    datos_user = usuarios[dni]
    salt = base64.b64decode(datos_user["salt"])
    hash_almacenado = base64.b64decode(datos_user["hash"])

    hash_calculado = _derivar_hash(password, salt)

    # Comparación en tiempo constante para mitigar ataques de tiempo
    if hmac.compare_digest(hash_almacenado, hash_calculado):
        print(f"[LOG SEGURIDAD] Autenticación exitosa para el usuario '{dni}'.")
        return True
    else:
        print(f"[LOG SEGURIDAD] Fallo de autenticación: Contraseña incorrecta para '{dni}'.")
        return False