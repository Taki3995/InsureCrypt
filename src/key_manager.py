# Generacion segura de claves, almacenamiento protegido de claves, y carga de claves

import os
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

KEYS_DIR = Path("keys")
PRIVATE_KEY_PATH = KEYS_DIR / "private_key.pem"
PUBLIC_KEY_PATH = KEYS_DIR / "public_key.pem"


def inicializar_directorio_claves() -> None:
    """Crea la carpeta keys/ si no existe"""
    KEYS_DIR.mkdir(parents=True, exist_ok=True)


def cargar_o_generar_claves(master_password: str):
    """
    Carga el par de claves ECDSA (SECP256R1) desde disco o genera uno nuevo si no existen los archivos. 
    La clave privada se almacena cifrada con AES.
    """
    inicializar_directorio_claves()

    if PRIVATE_KEY_PATH.exists() and PUBLIC_KEY_PATH.exists():
        try:
            with open(PRIVATE_KEY_PATH, "rb") as f:
                private_key = load_pem_private_key(
                    f.read(),
                    password=master_password.encode()
                )

            with open(PUBLIC_KEY_PATH, "rb") as f:
                public_key = load_pem_public_key(f.read())

            print("[LOG SEGURIDAD] Claves ECDSA cargadas desde disco.")
            print("[LOG SEGURIDAD] Algoritmo: ECDSA | Curva: SECP256R1 | Tamaño: 256 bits.")
            return private_key, public_key

        except TypeError:
            raise ValueError("La clave privada requiere una contraseña maestra para ser desprecintada.")
        except ValueError:
            raise ValueError("Contraseña maestra incorrecta. No se pudo descifrar private_key.pem.")

    # Generación de nuevo par de claves si no existen
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    # Cifrado simétrico AES de la clave privada al serializar a PEM
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(master_password.encode())
    )

    # Serialización de la clave pública (sin cifrar)
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(PRIVATE_KEY_PATH, "wb") as f:
        f.write(pem_private)

    with open(PUBLIC_KEY_PATH, "wb") as f:
        f.write(pem_public)

    print("[LOG SEGURIDAD] Nuevo par de claves ECDSA generado con fuente segura os.urandom.")
    print("[LOG SEGURIDAD] Algoritmo: ECDSA | Curva: SECP256R1 | Clave Privada guardada cifrada con AES en keys/private_key.pem.")
    
    return private_key, public_key