# Generacion segura de claves, almacenamiento protegido de claves, y carga de claves

import base64
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from cryptography import x509
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import load_der_private_key
from cryptography.x509.oid import NameOID

from crypto_utils import NONCE_SIZE_BYTES, PBKDF2_ITERATIONS, derivar_clave_simetrica

# rutas desde la raiz del proyecto, asi da igual desde q carpeta se lance la app
KEYS_DIR = Path(__file__).resolve().parent.parent / "keys"
PRIVATE_KEY_PATH = KEYS_DIR / "private_key.enc"
CERTIFICATE_PATH = KEYS_DIR / "certificate.pem"
INTEGRITY_SALT_PATH = KEYS_DIR / "integrity.salt"

# cert x509 autofirmado de la aseguradora, liga la clave publica ecdsa con quien es (su identidad)
CERT_SUBJECT = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "InsureCrypt"),
    x509.NameAttribute(NameOID.COMMON_NAME, "InsureCrypt Aseguradora"),
])
CERT_VALIDITY_DAYS = 5 * 365
SALT_SIZE_BYTES = 16
MIN_MASTER_PASSWORD_LENGTH = 12
# aad pa atar el cifrado a lo q es: este paquete solo puede ser la clave privada ecdsa y no otra cosa
AAD_CLAVE_PRIVADA = b"InsureCrypt|ECDSA-P256|private-key"


def inicializar_directorio_claves() -> None:
    """Crea la carpeta keys/ si no existe"""
    KEYS_DIR.mkdir(parents=True, exist_ok=True)


def existe_clave_privada() -> bool:
    """ dice si ya hay clave privada guardada (si no, al arrancar se genera una nueva) """
    return PRIVATE_KEY_PATH.exists()


def _guardar_clave_privada(private_key, master_password: str) -> None:
    """
    cifra la clave privada (pkcs8 der) con aes-256-gcm, con una clave sacada de la maestra
    con pbkdf2-sha256 (600k iteraciones, sal aleatoria de 16 bytes), y la guarda con permisos 600
    """
    der_privada = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    salt = os.urandom(SALT_SIZE_BYTES)
    nonce = os.urandom(NONCE_SIZE_BYTES)
    clave_proteccion = derivar_clave_simetrica(master_password, salt)
    ciphertext = AESGCM(clave_proteccion).encrypt(nonce, der_privada, AAD_CLAVE_PRIVADA)

    contenido = json.dumps({
        "kdf": "PBKDF2HMAC-SHA256",
        "iteraciones": PBKDF2_ITERATIONS,
        "salt": base64.b64encode(salt).decode("utf-8"),
        "cifrado": "AES-256-GCM",
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
    }, indent=4)

    # se crea ya con permisos 600 (solo el dueño lee/escribe) pa q no haya ni un momento con permisos abiertos
    # en windows esto solo toca el atributo de solo lectura, asi q donde vale de verdad es en linux
    descriptor = os.open(PRIVATE_KEY_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as f:
        f.write(contenido)


def _cargar_clave_privada(master_password: str):
    """ descifra la privada y comprueba el tag gcm, si la maestra esta mal o han tocado el fichero se rechaza """
    try:
        paquete = json.loads(PRIVATE_KEY_PATH.read_text(encoding="utf-8"))
        salt = base64.b64decode(paquete["salt"])
        nonce = base64.b64decode(paquete["nonce"])
        ciphertext = base64.b64decode(paquete["ciphertext"])
        iteraciones = paquete["iteraciones"]
    except (KeyError, ValueError, TypeError):
        # TypeError: el json esta bien pero la estructura o los tipos no son los q toca
        raise ValueError("El fichero de clave privada está corrupto o tiene un formato no válido.")

    if len(salt) != SALT_SIZE_BYTES or len(nonce) != NONCE_SIZE_BYTES:
        raise ValueError("El fichero de clave privada está corrupto o tiene un formato no válido.")

    if iteraciones != PBKDF2_ITERATIONS:
        raise ValueError("El fichero de clave privada usa parámetros de derivación no admitidos.")

    clave_proteccion = derivar_clave_simetrica(master_password, salt)
    try:
        der_privada = AESGCM(clave_proteccion).decrypt(nonce, ciphertext, AAD_CLAVE_PRIVADA)
    except InvalidTag:
        raise ValueError(
            "Contraseña maestra incorrecta o fichero de clave privada manipulado. No se pudo descifrar la clave."
        )
    return load_der_private_key(der_privada, password=None)


def _misma_clave_publica(clave_a, clave_b) -> bool:
    formato = (serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return clave_a.public_bytes(*formato) == clave_b.public_bytes(*formato)


def _generar_y_guardar_certificado(private_key) -> x509.Certificate:
    """
    crea un cert x509 autofirmado (ecdsa-sha256) q liga la clave publica con la identidad de la aseguradora
    uso de clave: firma digital y no repudio (content_commitment), validez 5 años
    """
    ahora = datetime.now(timezone.utc)
    certificado = (
        x509.CertificateBuilder()
        .subject_name(CERT_SUBJECT)
        .issuer_name(CERT_SUBJECT)  # autofirmado: emisor = sujeto
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(ahora)
        .not_valid_after(ahora + timedelta(days=CERT_VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=True, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key, hashes.SHA256())
    )
    with open(CERTIFICATE_PATH, "wb") as f:
        f.write(certificado.public_bytes(serialization.Encoding.PEM))
    return certificado


def _cargar_y_verificar_certificado(private_key) -> x509.Certificate:
    """
    carga el cert y lo comprueba antes de usar su clave publica. lanza ValueError si no es de la clave
    privada, si la autofirma no cuadra (lo han tocado), si el sujeto no es el nuestro o si esta caducado/aun no vale
    """
    try:
        certificado = x509.load_pem_x509_certificate(CERTIFICATE_PATH.read_bytes())
    except ValueError:
        raise ValueError("El certificado de la aseguradora está corrupto o no es un X.509 válido.")

    # 1. la clave del cert tiene q ser la de nuestra privada
    if not _misma_clave_publica(certificado.public_key(), private_key.public_key()):
        print("[LOG ERROR SEGURIDAD] certificate.pem NO corresponde a la clave privada.")
        raise ValueError("La clave pública del certificado no corresponde a la clave privada. Posible sustitución.")

    # 2. autofirma: si cambian cualquier cosa del cert (sujeto, fechas, clave...) la firma ya no vale
    try:
        certificado.verify_directly_issued_by(certificado)
    except (InvalidSignature, ValueError, TypeError):
        print("[LOG ERROR SEGURIDAD] Firma del certificado X.509 INVÁLIDA.")
        raise ValueError("El certificado de la aseguradora ha sido manipulado (firma inválida).")

    # 3. q sea la identidad q esperamos
    if certificado.subject != CERT_SUBJECT:
        raise ValueError("El certificado no pertenece a la aseguradora InsureCrypt.")

    # 4. q este dentro de sus fechas
    ahora = datetime.now(timezone.utc)
    if not (certificado.not_valid_before_utc <= ahora <= certificado.not_valid_after_utc):
        raise ValueError(
            "El certificado de la aseguradora no está vigente (caducado o aún no válido). "
            "Para renovarlo con la misma clave, borre keys/certificate.pem."
        )
    return certificado


def _log_certificado(certificado: x509.Certificate) -> None:
    huella = certificado.fingerprint(hashes.SHA256()).hex(":").upper()
    print(
        f"[LOG SEGURIDAD] Certificado X.509 autofirmado verificado | Sujeto: {certificado.subject.rfc4514_string()} | "
        f"Firma: ECDSA-SHA256 | Válido hasta: {certificado.not_valid_after_utc:%Y-%m-%d}."
    )
    print(f"[LOG SEGURIDAD] Huella SHA-256 del certificado: {huella}")


def cargar_o_generar_clave_integridad(master_password: str) -> bytes:
    """
    saca en memoria la clave hmac-sha256 (256 bits) q protege users.json y policies.json
    sale de la maestra con pbkdf2-sha256 (600k) y una sal propia de 16 bytes, distinta de la de la clave privada,
    asi las 2 claves son independientes. en disco solo va la sal (no es secreta), la clave nunca
    """
    inicializar_directorio_claves()
    if INTEGRITY_SALT_PATH.exists():
        salt = INTEGRITY_SALT_PATH.read_bytes()
        if len(salt) != SALT_SIZE_BYTES:
            raise ValueError("La sal de integridad en disco no es válida.")
    else:
        salt = os.urandom(SALT_SIZE_BYTES)
        INTEGRITY_SALT_PATH.write_bytes(salt)

    print(
        f"[LOG SEGURIDAD] Clave de integridad derivada: HMAC-SHA256 | Clave: 256 bits | "
        f"PBKDF2HMAC-SHA256 {PBKDF2_ITERATIONS} iteraciones."
    )
    return derivar_clave_simetrica(master_password, salt)


def cargar_o_generar_claves(master_password: str):
    """
    carga el par ecdsa (secp256r1) y el cert x509, o los crea si no hay clave privada
    devuelve (clave privada, clave publica del cert ya comprobado)
    nunca pisa una clave q ya existe: si falta el cert se vuelve a emitir con la misma privada, y si falta la
    privada pero esta el cert se para (las firmas de antes dependen de ese par)
    """
    inicializar_directorio_claves()

    if PRIVATE_KEY_PATH.exists():
        private_key = _cargar_clave_privada(master_password)

        if CERTIFICATE_PATH.exists():
            certificado = _cargar_y_verificar_certificado(private_key)
        else:
            certificado = _generar_y_guardar_certificado(private_key)
            print("[LOG SEGURIDAD] certificate.pem no existía: reemitido con la clave privada existente.")

        print("[LOG SEGURIDAD] Claves ECDSA cargadas desde disco. Par de claves verificado.")
        print("[LOG SEGURIDAD] Algoritmo: ECDSA | Curva: SECP256R1 | Tamaño: 256 bits.")
        _log_certificado(certificado)
        return private_key, certificado.public_key()

    if CERTIFICATE_PATH.exists():
        raise ValueError(
            "Existe certificate.pem pero falta la clave privada. No se genera un par nuevo para no "
            "invalidar las firmas existentes; restaure la clave privada desde una copia de seguridad."
        )

    if len(master_password) < MIN_MASTER_PASSWORD_LENGTH:
        raise ValueError(
            f"La contraseña maestra debe tener al menos {MIN_MASTER_PASSWORD_LENGTH} caracteres."
        )

    # par nuevo, lo genera el csprng de openssl x debajo de cryptography
    private_key = ec.generate_private_key(ec.SECP256R1())

    _guardar_clave_privada(private_key, master_password)
    certificado = _generar_y_guardar_certificado(private_key)

    print("[LOG SEGURIDAD] Nuevo par de claves ECDSA generado con el CSPRNG de OpenSSL.")
    print("[LOG SEGURIDAD] Algoritmo: ECDSA | Curva: SECP256R1 | Tamaño: 256 bits.")
    print(
        f"[LOG SEGURIDAD] Clave privada cifrada con AES-256-GCM (clave PBKDF2HMAC-SHA256, "
        f"{PBKDF2_ITERATIONS} iteraciones, sal 16 bytes) en keys/{PRIVATE_KEY_PATH.name} con permisos 600."
    )
    _log_certificado(certificado)

    return private_key, certificado.public_key()
