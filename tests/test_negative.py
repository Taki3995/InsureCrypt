# Pruebas de fallos de seguridad como contraseñas incorrectas, firmas alteradas, etc
import base64
import json
import os
import pytest

import auth
import crypto_utils
import key_manager
import main


def _alterar_un_byte_b64(cadena_b64: str, indice: int) -> str:
    """Decodifica Base64, invierte 1 bit en la posición indicada y recodifica."""
    datos = bytearray(base64.b64decode(cadena_b64))
    datos[indice] ^= 0x01
    return base64.b64encode(bytes(datos)).decode("utf-8")


# Pruebas mínimas
def test_contrasena_maestra_incorrecta_pem():
    """Verifica rechazo explícito al desprecintar private_key.pem con clave errónea."""
    key_manager.cargar_o_generar_claves("ClaveMaestraCorrecta!")

    with pytest.raises(ValueError, match="Contraseña maestra incorrecta"):
        key_manager.cargar_o_generar_claves("ClaveMaestraFalsa!")


def test_autenticacion_contrasena_incorrecta():
    """Verifica que el login falla ante una contraseña incorrecta."""
    auth.registrar_usuario("11111111A", "MiClaveReal2026!")
    assert auth.autenticar_usuario("11111111A", "MiClaveFalsa2026!") is False


def test_modificacion_ciphertext_aes_gcm():
    """Verifica rechazo (InvalidTag -> ValueError) al alterar 1 byte del ciphertext."""
    clave = crypto_utils.generar_clave_simetrica()
    paquete = crypto_utils.cifrar_poliza({"id": "POL-10", "capital": 5000}, clave)

    # Altera el primer byte del texto cifrado
    paquete["ciphertext"] = _alterar_un_byte_b64(paquete["ciphertext"], 0)

    with pytest.raises(ValueError, match="Error de autenticidad"):
        crypto_utils.descifrar_poliza(paquete, clave)


def test_modificacion_tag_autenticacion_aes_gcm():
    """Verifica rechazo explícito al alterar 1 byte del Tag GCM (últimos 16 bytes)."""
    clave = crypto_utils.generar_clave_simetrica()
    paquete = crypto_utils.cifrar_poliza({"id": "POL-11", "capital": 9000}, clave)

    # En AESGCM, el tag de 16 bytes reside al final de ciphertext_con_tag (índice -1)
    paquete["ciphertext"] = _alterar_un_byte_b64(paquete["ciphertext"], -1)

    with pytest.raises(ValueError, match="Error de autenticidad"):
        crypto_utils.descifrar_poliza(paquete, clave)


def test_descifrado_con_clave_o_contrasena_incorrecta():
    """Verifica rechazo al intentar descifrar con una contraseña distinta."""
    sal = os.urandom(16)
    clave_real = crypto_utils.derivar_clave_simetrica("PasswordPropietario!", sal)
    clave_atacante = crypto_utils.derivar_clave_simetrica("PasswordAtacante!", sal)

    paquete = crypto_utils.cifrar_poliza({"id": "POL-12", "secreto": "Datos"}, clave_real)

    with pytest.raises(ValueError, match="Error de autenticidad"):
        crypto_utils.descifrar_poliza(paquete, clave_atacante)


def test_firma_digital_alterada():
    """Verifica rechazo (InvalidSignature -> False) al modificar 1 byte de la firma ECDSA."""
    priv_key, pub_key = key_manager.cargar_o_generar_claves("MasterPass2026!")
    poliza = {"id_poliza": "POL-13", "capital_asegurado": 15000.0}

    firma_valida = crypto_utils.firmar_poliza(poliza, priv_key)
    firma_alterada = _alterar_un_byte_b64(firma_valida, -1)

    assert crypto_utils.verificar_firma_poliza(poliza, firma_alterada, pub_key) is False


def test_datos_poliza_modificados_post_firma():
    """Verifica que alterar los datos de la póliza tras firmarla invalida la firma."""
    priv_key, pub_key = key_manager.cargar_o_generar_claves("MasterPass2026!")
    poliza_original = {"id_poliza": "POL-14", "capital_asegurado": 15000.0}

    firma_b64 = crypto_utils.firmar_poliza(poliza_original, priv_key)

    # Un atacante intenta inflar el capital asegurado a 999.999 €
    poliza_manipulada = {"id_poliza": "POL-14", "capital_asegurado": 999999.0}
    assert crypto_utils.verificar_firma_poliza(poliza_manipulada, firma_b64, pub_key) is False


# Pruebas Extra
def test_registro_usuario_duplicado():
    """Impide sobrescribir un usuario ya registrado con el mismo DNI."""
    auth.registrar_usuario("22222222B", "ClaveInicial2026!")

    with pytest.raises(ValueError, match="ya se encuentra registrado"):
        auth.registrar_usuario("22222222B", "OtraClave2026!")


def test_autenticacion_usuario_inexistente():
    """Verifica rechazo ante un identificador que no existe en users.json."""
    assert auth.autenticar_usuario("99999999Z", "CualquierClave2026!") is False


def test_ataque_sustitucion_paquete_entre_clientes(monkeypatch, capsys):
    """
    Simula que un atacante trasplanta el paquete cifrado y firmado de un cliente a otro cliente distinto en policies.json; 
    el sistema debe rechazar la póliza.
    """
    priv_key, pub_key = key_manager.cargar_o_generar_claves("MasterPass2026!")
    auth.registrar_usuario("10000001A", "MismaClaveCompartida!")
    auth.registrar_usuario("20000002B", "MismaClaveCompartida!")

    entradas = iter(["1", "Beneficiario Cliente A", "50000"])
    monkeypatch.setattr("builtins.input", lambda _: next(entradas))
    main.contratar_poliza("10000001A", "MismaClaveCompartida!", priv_key)

    # El atacante modifica el metadato exterior 'titular_dni' en policies.json
    polizas = json.loads(main.POLICIES_FILE.read_text(encoding="utf-8"))
    polizas[0]["titular_dni"] = "20000002B"
    main.POLICIES_FILE.write_text(json.dumps(polizas), encoding="utf-8")

    # Al consultar como Cliente B, la validación interna detecta que el titular firmado no coincide
    main.consultar_polizas("20000002B", "MismaClaveCompartida!", pub_key)
    salida = capsys.readouterr().out
    assert "RECHAZADA: El titular no coincide" in salida