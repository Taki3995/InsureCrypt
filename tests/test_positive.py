import base64
import json
import os

import auth
import crypto_utils
import key_manager
import main


# Pruebas mínimas
def test_generacion_y_carga_claves_ecdsa():
    """Verifica generación del par ECDSA, cifrado PEM en disco y posterior carga."""
    master_pass = "MasterSeguros2026!"
    priv_1, pub_1 = key_manager.cargar_o_generar_claves(master_pass)

    assert key_manager.PRIVATE_KEY_PATH.exists()
    assert key_manager.PUBLIC_KEY_PATH.exists()

    # Comprueba que el fichero privado está cifrado en formato PKCS#8
    contenido_pem = key_manager.PRIVATE_KEY_PATH.read_text(encoding="utf-8")
    assert "-----BEGIN ENCRYPTED PRIVATE KEY-----" in contenido_pem

    # Recarga desde disco y verifica que las claves públicas coinciden
    priv_2, pub_2 = key_manager.cargar_o_generar_claves(master_pass)
    assert pub_1.public_numbers() == pub_2.public_numbers()
    assert priv_1.private_numbers().private_value == priv_2.private_numbers().private_value


def test_registro_y_autenticacion_exitosa():
    """Verifica registro con PBKDF2HMAC-SHA256 + salt de 16 bytes y login correcto."""
    dni = "12345678A"
    password = "PasswordSegura2026!"

    assert auth.registrar_usuario(dni, password) is True

    # Verifica que en users.json no existe la contraseña en plano y el salt mide 16 bytes
    usuarios = json.loads(auth.USERS_FILE.read_text(encoding="utf-8"))
    assert dni in usuarios
    assert password not in json.dumps(usuarios)
    assert len(base64.b64decode(usuarios[dni]["salt"])) == 16

    assert auth.autenticar_usuario(dni, password) is True


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
    """Verifica firma ECDSA-SHA256 y validación positiva con clave pública."""
    priv_key, pub_key = key_manager.cargar_o_generar_claves("MasterPass2026!")
    poliza = {
        "id_poliza": "POL-003",
        "titular_dni": "87654321B",
        "tipo_seguro": "Vida",
        "capital_asegurado": 100000.0,
    }

    firma_b64 = crypto_utils.firmar_poliza(poliza, priv_key)
    assert crypto_utils.verificar_firma_poliza(poliza, firma_b64, pub_key) is True


# Pruebas Extra
def test_serializacion_determinista_en_firma():
    """Verifica que distinto orden de claves en el dict no invalida la firma."""
    priv_key, pub_key = key_manager.cargar_o_generar_claves("MasterPass2026!")
    poliza_orden_1 = {"a_id": "POL-004", "b_capital": 3000}
    poliza_orden_2 = {"b_capital": 3000, "a_id": "POL-004"}

    firma_b64 = crypto_utils.firmar_poliza(poliza_orden_1, priv_key)
    assert crypto_utils.verificar_firma_poliza(poliza_orden_2, firma_b64, pub_key) is True


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
    assert "contratada, firmada y cifrada correctamente" in salida_consola
    assert "Piso en Madrid Centro" in salida_consola
    assert "120000.0 €" in salida_consola