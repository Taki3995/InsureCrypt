import base64
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

import auth
import crypto_utils
import key_manager
import main
import secure_storage


# Pruebas mínimas
def test_generacion_y_carga_claves_ecdsa():
    """ genera el par ecdsa, guarda la privada cifrada (aes-gcm + pbkdf2 600k) y al recargarla sale la misma """
    master_pass = "MasterSeguros2026!"
    priv_1, pub_1 = key_manager.cargar_o_generar_claves(master_pass)

    assert key_manager.PRIVATE_KEY_PATH.exists()
    assert key_manager.CERTIFICATE_PATH.exists()

    # el fichero tiene q ir cifrado con los parametros buenos y sin la clave en claro
    paquete = json.loads(key_manager.PRIVATE_KEY_PATH.read_text(encoding="utf-8"))
    assert paquete["cifrado"] == "AES-256-GCM"
    assert paquete["kdf"] == "PBKDF2HMAC-SHA256"
    assert paquete["iteraciones"] == 600000
    assert len(base64.b64decode(paquete["salt"])) == 16
    assert len(base64.b64decode(paquete["nonce"])) == 12
    assert "PRIVATE KEY" not in key_manager.PRIVATE_KEY_PATH.read_text(encoding="utf-8")

    # permisos 600 (solo el dueño), en windows esto no aplica asi q solo se mira en linux
    if os.name != "nt":
        assert stat.S_IMODE(key_manager.PRIVATE_KEY_PATH.stat().st_mode) == 0o600

    # recargo desde disco y tiene q salir el mismo par
    priv_2, pub_2 = key_manager.cargar_o_generar_claves(master_pass)
    assert pub_1.public_numbers() == pub_2.public_numbers()
    assert priv_1.private_numbers().private_value == priv_2.private_numbers().private_value


def test_registro_y_autenticacion_exitosa():
    """ registro con pbkdf2 + sal de 16 bytes y login bien, y 2 clientes con la misma contraseña tienen sal y hash distintos """
    dni = "12345678A"
    password = "PasswordSegura2026!"

    assert auth.registrar_usuario(dni, password) is True
    auth.registrar_usuario("87654321B", password)

    # en users.json no puede estar la contraseña en claro y la sal mide 16 bytes
    usuarios = json.loads(auth.USERS_FILE.read_text(encoding="utf-8"))["datos"]
    assert dni in usuarios
    assert password not in json.dumps(usuarios)
    assert len(base64.b64decode(usuarios[dni]["salt"])) == 16
    assert usuarios[dni]["salt"] != usuarios["87654321B"]["salt"]
    assert usuarios[dni]["hash"] != usuarios["87654321B"]["hash"]

    assert auth.autenticar_usuario(dni, password) is True


def test_contrasena_con_espacios_se_respeta_en_la_aplicacion(monkeypatch, capsys):
    """ flujo real de main(): una contraseña con espacios al ppio y al final se usa tal cual (antes el .strip() la cambiaba) """
    password = "  frase larga con espacios  "
    claves = iter(["MasterPass2026!", "MasterPass2026!", password, password])
    menus = iter(["1", "13131313R", "2", "13131313R", "3", "3"])
    monkeypatch.setattr(main.getpass, "getpass", lambda _: next(claves))
    monkeypatch.setattr("builtins.input", lambda _: next(menus))

    main.main()

    assert "Autenticación exitosa para el usuario '13131313R'" in capsys.readouterr().out
    # sin los espacios es otra contraseña distinta
    assert auth.autenticar_usuario("13131313R", password.strip()) is False


def test_rutas_de_datos_ancladas_a_la_raiz_del_proyecto(tmp_path):
    """ data/ y keys/ no dependen de desde donde se lance la app, importando desde otra carpeta siguen en la raiz """
    src = Path(main.__file__).resolve().parent
    codigo = (
        "import auth, key_manager, main\n"
        "print(auth.USERS_FILE); print(main.POLICIES_FILE); print(key_manager.PRIVATE_KEY_PATH)"
    )
    resultado = subprocess.run(
        [sys.executable, "-c", codigo], capture_output=True, text=True, cwd=tmp_path,
        env={**os.environ, "PYTHONPATH": str(src)}, timeout=60,
    )
    raiz = src.parent
    assert [Path(linea) for linea in resultado.stdout.splitlines()] == [
        raiz / "data" / "users.json", raiz / "data" / "policies.json", raiz / "keys" / "private_key.enc",
    ]


def test_cifrado_y_descifrado_autenticado_aes_gcm():
    """Verifica confidencialidad y descifrado íntegro con AES-256-GCM."""
    clave = crypto_utils.derivar_clave_simetrica("ClientePass2026!", os.urandom(16))
    poliza_original = {
        "id_poliza": "POL-001",
        "titular_dni": "12345678A",
        "tipo_seguro": "Coche",
        "detalle_cobertura": "Matrícula 1234-BCD Todo Riesgo",
        "capital_asegurado": 20000.0,
    }

    paquete = crypto_utils.cifrar_poliza(poliza_original, clave)
    assert "Matrícula 1234-BCD" not in paquete["ciphertext"]

    poliza_recuperada = crypto_utils.descifrar_poliza(paquete, clave)
    assert poliza_recuperada == poliza_original


def test_no_reutilizacion_nonces_aes_gcm():
    """Verifica que dos cifrados consecutivos generan nonces únicos de 96 bits."""
    clave = crypto_utils.generar_clave_simetrica()
    datos = {"id_poliza": "POL-002", "capital": 5000}

    paquete_1 = crypto_utils.cifrar_poliza(datos, clave)
    paquete_2 = crypto_utils.cifrar_poliza(datos, clave)

    nonce_1 = base64.b64decode(paquete_1["nonce"])
    nonce_2 = base64.b64decode(paquete_2["nonce"])

    assert len(nonce_1) == 12
    assert len(nonce_2) == 12
    assert nonce_1 != nonce_2
    assert paquete_1["ciphertext"] != paquete_2["ciphertext"]


def test_firma_y_verificacion_digital_ecdsa():
    """ firma ecdsa-sha256 y verificacion ok, y cambiar el orden de las claves del dict no rompe la firma """
    priv_key, pub_key = key_manager.cargar_o_generar_claves("MasterPass2026!")
    poliza = {
        "id_poliza": "POL-003",
        "titular_dni": "87654321B",
        "tipo_seguro": "Vida",
        "capital_asegurado": 100000.0,
    }

    firma_b64 = crypto_utils.firmar_poliza(poliza, priv_key)
    assert crypto_utils.verificar_firma_poliza(poliza, firma_b64, pub_key) is True

    # mismo contenido en otro orden -> sort_keys hace q se serialice igual
    poliza_desordenada = dict(reversed(list(poliza.items())))
    assert crypto_utils.verificar_firma_poliza(poliza_desordenada, firma_b64, pub_key) is True


# Pruebas Extra
def test_firma_almacenada_dentro_del_cifrado(monkeypatch):
    """ el registro guardado no lleva la firma en claro, va cifrada junto a los datos de la poliza """
    priv_key, pub_key = key_manager.cargar_o_generar_claves("MasterPass2026!")
    dni, password = "66666666D", "ClienteValido2026!"
    auth.registrar_usuario(dni, password)
    entradas = iter(["1", "Beneficiario Hijo", "50000"])
    monkeypatch.setattr("builtins.input", lambda _: next(entradas))
    main.contratar_poliza(dni, password, priv_key)

    registro = json.loads(main.POLICIES_FILE.read_text(encoding="utf-8"))["datos"][0]
    assert set(registro) == {"id_poliza", "titular_dni", "salt_kdf", "nonce", "ciphertext"}

    clave = crypto_utils.derivar_clave_simetrica(password, base64.b64decode(registro["salt_kdf"]))
    aad = f"{registro['id_poliza']}|{dni}".encode("utf-8")
    contenido = crypto_utils.descifrar_poliza(registro, clave, aad)
    assert set(contenido) == {"datos", "firma_aseguradora"}
    assert crypto_utils.verificar_firma_poliza(contenido["datos"], contenido["firma_aseguradora"], pub_key)


def test_hmac_ficheros_y_derivacion_de_su_clave():
    """
    los datos se guardan con un hmac-sha256 de 32 bytes y se recuperan iguales, y la clave hmac
    sale de la maestra (misma maestra -> misma clave, otra maestra -> otra clave)
    """
    usuarios = {"12345678A": {"salt": "c2Fs", "hash": "aGFzaA=="}}
    secure_storage.guardar_json(auth.USERS_FILE, usuarios)

    envoltorio = json.loads(auth.USERS_FILE.read_text(encoding="utf-8"))
    assert set(envoltorio) == {"datos", "hmac"}
    assert len(base64.b64decode(envoltorio["hmac"])) == 32
    assert secure_storage.cargar_json(auth.USERS_FILE, {}) == usuarios

    clave_1 = key_manager.cargar_o_generar_clave_integridad("MasterPass2026!")
    clave_2 = key_manager.cargar_o_generar_clave_integridad("MasterPass2026!")
    clave_otra = key_manager.cargar_o_generar_clave_integridad("OtraMaestra2026!")
    assert len(clave_1) == 32
    assert clave_1 == clave_2
    assert clave_1 != clave_otra
    assert len(key_manager.INTEGRITY_SALT_PATH.read_bytes()) == 16


def test_certificado_x509_autofirmado():
    """
    el cert de la aseguradora es x509 autofirmado con ecdsa-sha256, liga la clave publica con su identidad,
    uso de clave firma + no repudio y 5 años. si se borra se vuelve a emitir con la misma clave privada
    """
    priv_key, pub_key = key_manager.cargar_o_generar_claves("MasterPass2026!")
    cert = x509.load_pem_x509_certificate(key_manager.CERTIFICATE_PATH.read_bytes())

    assert cert.subject == cert.issuer == key_manager.CERT_SUBJECT
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "InsureCrypt Aseguradora"
    cert.verify_directly_issued_by(cert)  # si la autofirma esta mal esto lanza excepcion
    assert cert.signature_hash_algorithm.name == "sha256"
    assert isinstance(cert.public_key(), ec.EllipticCurvePublicKey)
    assert cert.public_key().curve.name == "secp256r1"
    assert cert.public_key().public_numbers() == priv_key.public_key().public_numbers()
    assert cert.public_key().public_numbers() == pub_key.public_numbers()

    uso = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    assert uso.digital_signature and uso.content_commitment
    assert (cert.not_valid_after_utc - cert.not_valid_before_utc).days == 5 * 365

    # borro el cert -> se reemite sin tocar la privada y con la misma clave publica
    privada_en_disco = key_manager.PRIVATE_KEY_PATH.read_bytes()
    key_manager.CERTIFICATE_PATH.unlink()
    _, pub_2 = key_manager.cargar_o_generar_claves("MasterPass2026!")
    assert key_manager.PRIVATE_KEY_PATH.read_bytes() == privada_en_disco
    assert key_manager.CERTIFICATE_PATH.exists()
    assert pub_2.public_numbers() == pub_key.public_numbers()


def test_dos_polizas_tienen_id_sal_y_nonce_distintos(monkeypatch):
    """ 2 polizas del mismo cliente: id de 64 bits (16 hex) distinto, y sal y nonce distintos (o sea clave aes distinta) """
    priv_key, _ = key_manager.cargar_o_generar_claves("MasterPass2026!")
    auth.registrar_usuario("14141414S", "ClienteValido2026!")
    entradas = iter(["1", "Beneficiario A", "1000", "1", "Beneficiario B", "2000"])
    monkeypatch.setattr("builtins.input", lambda _: next(entradas))
    main.contratar_poliza("14141414S", "ClienteValido2026!", priv_key)
    main.contratar_poliza("14141414S", "ClienteValido2026!", priv_key)

    poliza_1, poliza_2 = main._cargar_polizas()
    for poliza in (poliza_1, poliza_2):
        assert re.fullmatch(r"POL-[0-9A-F]{16}", poliza["id_poliza"])
    assert poliza_1["id_poliza"] != poliza_2["id_poliza"]
    assert poliza_1["salt_kdf"] != poliza_2["salt_kdf"]
    assert poliza_1["nonce"] != poliza_2["nonce"]


def test_flujo_completo_end_to_end_cli(monkeypatch, capsys):
    """Prueba el ciclo completo contratar -> guardar -> consultar en main.py."""
    priv_key, pub_key = key_manager.cargar_o_generar_claves("MasterPass2026!")
    dni = "55555555C"
    password = "ClienteValido2026!"
    auth.registrar_usuario(dni, password)

    # Simula entradas por teclado para contratar póliza de Hogar (opción 3)
    entradas_usuario = iter(["3", "Piso en Madrid Centro", "120000"])
    monkeypatch.setattr("builtins.input", lambda _: next(entradas_usuario))

    main.contratar_poliza(dni, password, priv_key)
    main.consultar_polizas(dni, password, pub_key)

    salida_consola = capsys.readouterr().out
    assert "AAD autenticado" in salida_consola
    assert "contratada, firmada y cifrada correctamente" in salida_consola
    assert "Piso en Madrid Centro" in salida_consola
    assert "120000.0 €" in salida_consola
