import base64
import json
import os
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

KEY_SIZE_BYTES = 32  # AES-256 (256 bits = 32 bytes)
NONCE_SIZE_BYTES = 12  # Requisito estándar de 96 bits para AES-GCM
PBKDF2_ITERATIONS = 600000  # lo q recomienda owasp ahora pa pbkdf2-sha256 (nist solo pone minimos)


def generar_clave_simetrica() -> bytes:
    """Genera una clave simétrica aleatoria de 256 bits usando os.urandom."""
    return AESGCM.generate_key(bit_length=256)


def derivar_clave_simetrica(password: str, salt: bytes) -> bytes:
    """
    Deriva una clave simétrica AES-256 (32 bytes) en memoria a partir de la
    contraseña del cliente y una sal aleatoria de 16 bytes usando PBKDF2HMAC-SHA256.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE_BYTES,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def cifrar_poliza(datos_poliza: dict, clave_simetrica: bytes, datos_asociados: bytes | None = None) -> dict:
    """
    cifra la poliza con aes-256-gcm (cifrado autenticado)
    los datos_asociados (aad) no se cifran pero entran en el tag, si los cambian falla el descifrado
    devuelve el nonce y el ciphertext (con el tag al final) en base64
    """
    datos_bytes = json.dumps(datos_poliza, sort_keys=True).encode("utf-8")

    # Generación de nonce único (96 bits) usando aleatoriedad segura (os.urandom)
    nonce = os.urandom(NONCE_SIZE_BYTES)
    aesgcm = AESGCM(clave_simetrica)

    # Cifrado autenticado: el ciphertext producido contiene los bytes cifrados + Tag final de 16 bytes
    ciphertext_con_tag = aesgcm.encrypt(nonce, datos_bytes, associated_data=datos_asociados)

    print("[LOG SEGURIDAD] Operación: Cifrado Autenticado de Póliza.")
    print("[LOG SEGURIDAD] Algoritmo: AES-256-GCM | Longitud Clave: 256 bits | Nonce: 96 bits | Tag: 128 bits.")
    print(f"[LOG SEGURIDAD] Nonce (Hex): {nonce.hex()}")
    if datos_asociados:
        print(f"[LOG SEGURIDAD] AAD autenticado: {len(datos_asociados)} bytes (metadatos en claro del registro).")

    return {
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext_con_tag).decode("utf-8"),
    }


def descifrar_poliza(paquete_cifrado: dict, clave_simetrica: bytes, datos_asociados: bytes | None = None) -> dict:
    """
    descifra y comprueba la poliza con aes-256-gcm
    si han tocado los datos, el tag o el aad salta InvalidTag y se rechaza
    """
    try:
        nonce = base64.b64decode(paquete_cifrado["nonce"])
        ciphertext_con_tag = base64.b64decode(paquete_cifrado["ciphertext"])

        aesgcm = AESGCM(clave_simetrica)
        datos_bytes = aesgcm.decrypt(nonce, ciphertext_con_tag, associated_data=datos_asociados)

        print("[LOG SEGURIDAD] Descifrado AES-256-GCM exitoso. Tag de autenticación VALIDADO correctamente.")
        return json.loads(datos_bytes.decode("utf-8"))

    except InvalidTag:
        print("[LOG ERROR SEGURIDAD] Tag de autenticación INVÁLIDO o datos alterados (AES-GCM).")
        raise ValueError("Error de autenticidad: El paquete cifrado ha sido manipulado o la clave es incorrecta.")


def firmar_poliza(datos_poliza: dict, private_key) -> str:
    """
    Genera una firma digital ECDSA-SHA256 sobre la representación JSON de la póliza.
    """
    datos_bytes = json.dumps(datos_poliza, sort_keys=True).encode("utf-8")

    firma = private_key.sign(
        datos_bytes,
        ec.ECDSA(hashes.SHA256()),
    )

    print("[LOG SEGURIDAD] Operación: Firma Digital realizada por la Aseguradora.")
    print("[LOG SEGURIDAD] Algoritmo: ECDSA | Curva: SECP256R1 | Hash: SHA-256.")
    return base64.b64encode(firma).decode("utf-8")


def verificar_firma_poliza(datos_poliza: dict, firma_b64: str, public_key) -> bool:
    """
    Verifica la validez de la firma digital ECDSA sobre los datos de la póliza.
    """
    datos_bytes = json.dumps(datos_poliza, sort_keys=True).encode("utf-8")

    try:
        firma_bytes = base64.b64decode(firma_b64)
        public_key.verify(
            firma_bytes,
            datos_bytes,
            ec.ECDSA(hashes.SHA256()),
        )
        print("[LOG SEGURIDAD] Verificación de Firma Digital ECDSA: VALIDA (No Repudio / Autenticidad garantizada).")
        return True
    except (InvalidSignature, ValueError, TypeError):
        # ValueError/TypeError: la firma ni es base64 o ni es texto, tb cuenta como firma mala
        print("[LOG ERROR SEGURIDAD] Verificación de Firma Digital ECDSA: INVALIDA o MODIFICADA.")
        return False