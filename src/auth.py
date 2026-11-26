# Registro y autenticacion de usuarios

import base64
import os
import hmac
import re
from pathlib import Path

from crypto_utils import PBKDF2_ITERATIONS, derivar_clave_simetrica
from secure_storage import cargar_json, guardar_json

# rutas desde la raiz del proyecto, asi da igual desde q carpeta se lance la app
DATA_DIR = Path(__file__).resolve().parent.parent / "data"
USERS_FILE = DATA_DIR / "users.json"
SALT_SIZE = 16
# politica de contraseñas (owasp asvs v2.1.1 / v2.1.2): min y max de longitud, sin reglas tipo mayus+simbolo
MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 128
MENSAJE_FALLO_AUTENTICACION = "Fallo de autenticación: DNI/ID o contraseña incorrectos."


def _cargar_usuarios() -> dict:
    """ carga users.json comprobando antes su hmac (si lo han tocado salta IntegridadError) """
    return cargar_json(USERS_FILE, {})


def _guardar_usuarios(usuarios: dict) -> None:
    guardar_json(USERS_FILE, usuarios)


def _derivar_hash(password: str, salt: bytes) -> bytes:
    """
    hash de la contraseña pa guardar/comprobar: pbkdf2-sha256 (600k iteraciones, 32 bytes)
    uso la misma funcion de crypto_utils pa no tener el pbkdf2 repetido en 2 sitios
    """
    return derivar_clave_simetrica(password, salt)


def validar_politica_password(dni: str, password: str) -> None:
    """
    mira q la contraseña sea robusta antes de registrarla, si no lanza ValueError con el motivo
    ojo: se usa tal cual, sin quitar espacios, xq los espacios tb son parte del secreto
    """
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"La contraseña debe tener al menos {MIN_PASSWORD_LENGTH} caracteres.")
    if len(password) > MAX_PASSWORD_LENGTH:
        raise ValueError(f"La contraseña no puede superar los {MAX_PASSWORD_LENGTH} caracteres.")
    if dni.lower() in password.lower():
        raise ValueError("La contraseña no puede contener el DNI/ID del cliente.")


def registrar_usuario(dni: str, password: str) -> bool:
    """
    Registra un nuevo cliente/usuario. Genera salt de 16 bytes con os.urandom y almacena salt + hash en Base64.
    """
    if not dni:
        raise ValueError("El DNI/ID de cliente no puede estar vacío.")
    if not re.fullmatch(r"[A-Za-z0-9]{1,20}", dni):
        raise ValueError("El DNI/ID de cliente solo puede contener letras y números (máximo 20 caracteres).")
    validar_politica_password(dni, password)

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
    recalcula el hash con la sal del usuario y lo compara en tiempo cte (hmac.compare_digest)
    pa no chivar q dnis estan registrados (enumeracion de usuarios) el mensaje de fallo es el mismo
    si el usuario no existe o si la contraseña esta mal, y en los 2 casos se hace el pbkdf2 asi tarda lo mismo
    """
    usuarios = _cargar_usuarios()
    datos_user = usuarios.get(dni)

    if datos_user is None:
        # el usuario no existe: hago el pbkdf2 igual con una sal de relleno y lo tiro, solo pa q tarde lo mismo
        salt, hash_almacenado = os.urandom(SALT_SIZE), None
    else:
        salt = base64.b64decode(datos_user["salt"])
        hash_almacenado = base64.b64decode(datos_user["hash"])

    hash_calculado = _derivar_hash(password, salt)

    # Comparación en tiempo constante para mitigar ataques de tiempo
    if hash_almacenado is not None and hmac.compare_digest(hash_almacenado, hash_calculado):
        print(f"[LOG SEGURIDAD] Autenticación exitosa para el usuario '{dni}'.")
        return True

    print(f"[LOG SEGURIDAD] {MENSAJE_FALLO_AUTENTICACION}")
    return False