# Pruebas de fallos de seguridad como contraseñas incorrectas, firmas alteradas, etc
import base64
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

import auth
import crypto_utils
import key_manager
import main
import secure_storage


def _alterar_un_byte_b64(cadena_b64: str, indice: int) -> str:
    """Decodifica Base64, invierte 1 bit en la posición indicada y recodifica."""
    datos = bytearray(base64.b64decode(cadena_b64))
    datos[indice] ^= 0x01
    return base64.b64encode(bytes(datos)).decode("utf-8")


# Pruebas mínimas
def test_contrasena_maestra_incorrecta(monkeypatch, capsys):
    """ con la maestra mal no se descifra la clave privada, ni llamando directo ni desde la app (no llega al menu) """
    key_manager.cargar_o_generar_claves("ClaveMaestraCorrecta!")

    with pytest.raises(ValueError, match="Contraseña maestra incorrecta"):
        key_manager.cargar_o_generar_claves("ClaveMaestraFalsa!")

    monkeypatch.setattr(main.getpass, "getpass", lambda _: "ClaveMaestraFalsa!")
    monkeypatch.setattr("builtins.input", lambda _: pytest.fail("no deberia llegar al menu"))
    main.main()
    assert "[ERROR CRÍTICO] Contraseña maestra incorrecta" in capsys.readouterr().out


def test_mismo_mensaje_contrasena_incorrecta_y_usuario_inexistente(capsys):
    """
    el login falla con contraseña mala y con un dni q no existe, y los 2 fallos sacan exactamente lo mismo
    pa no revelar si el dni esta registrado (enumeracion de usuarios)
    """
    auth.registrar_usuario("12121212L", "ClienteValido2026!")
    capsys.readouterr()

    assert auth.autenticar_usuario("12121212L", "ClaveEquivocada2026!") is False
    salida_contrasena_mala = capsys.readouterr().out
    assert auth.autenticar_usuario("34343434M", "ClaveEquivocada2026!") is False
    salida_usuario_inexistente = capsys.readouterr().out

    assert salida_contrasena_mala.replace("12121212L", "X") == salida_usuario_inexistente.replace("34343434M", "X")
    assert "no existe" not in salida_usuario_inexistente
    assert "DNI/ID o contraseña incorrectos" in salida_usuario_inexistente


def test_pbkdf2_se_calcula_aunque_usuario_no_exista(monkeypatch):
    """ enumeracion x tiempo: con un dni q no existe tb se hace el pbkdf2 entero, asi tarda lo mismo """
    llamadas = []
    derivar_original = auth._derivar_hash

    def derivar_contando(password, salt):
        llamadas.append(len(salt))
        return derivar_original(password, salt)

    monkeypatch.setattr(auth, "_derivar_hash", derivar_contando)
    assert auth.autenticar_usuario("56565656N", "CualquierClave2026!") is False
    assert llamadas == [16]


def _alterar_tag(paquete):
    # el tag de gcm son los ultimos 16 bytes del ciphertext
    paquete["ciphertext"] = _alterar_un_byte_b64(paquete["ciphertext"], -1)


def _truncar_ciphertext(paquete):
    datos = base64.b64decode(paquete["ciphertext"])[:-1]
    paquete["ciphertext"] = base64.b64encode(datos).decode("utf-8")


@pytest.mark.parametrize(
    "manipular",
    [
        lambda p: p.update(ciphertext=_alterar_un_byte_b64(p["ciphertext"], 0)),
        _alterar_tag,
        lambda p: p.update(nonce=_alterar_un_byte_b64(p["nonce"], 0)),
        _truncar_ciphertext,
    ],
    ids=["ciphertext", "tag", "nonce", "truncado"],
)
def test_paquete_aes_gcm_manipulado_rechazado(manipular):
    """ cambiar 1 byte del ciphertext, del tag o del nonce, o quitarle un byte, hace q falle el descifrado """
    clave = crypto_utils.generar_clave_simetrica()
    paquete = crypto_utils.cifrar_poliza({"id": "POL-10", "capital": 5000}, clave)
    manipular(paquete)

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


@pytest.mark.parametrize("firma", ["%%%no-es-base64%%%", None], ids=["no-base64", "no-es-texto"])
def test_firma_mal_formada_rechazada(firma):
    """ una firma q ni es base64 o ni es texto da False (firma invalida) en vez de petar """
    _, pub_key = key_manager.cargar_o_generar_claves("MasterPass2026!")
    assert crypto_utils.verificar_firma_poliza({"id_poliza": "POL-19"}, firma, pub_key) is False


# Pruebas Extra
def _byte_alterado(texto):
    paquete = json.loads(texto)
    paquete["ciphertext"] = _alterar_un_byte_b64(paquete["ciphertext"], 0)
    return json.dumps(paquete)


def _nonce_corto(texto):
    paquete = json.loads(texto)
    paquete["nonce"] = "AAAA"
    return json.dumps(paquete)


def _iteraciones_rebajadas(texto):
    paquete = json.loads(texto)
    paquete["iteraciones"] = 1000
    return json.dumps(paquete)


@pytest.mark.parametrize(
    "manipular, motivo",
    [
        (_byte_alterado, "manipulado"),
        (lambda _: "[]", "corrupto"),
        (_nonce_corto, "corrupto"),
        (_iteraciones_rebajadas, "no admitidos"),
    ],
    ids=["byte-alterado", "lista", "nonce-corto", "iteraciones-rebajadas"],
)
def test_fichero_clave_privada_manipulado_o_mal_formado(manipular, motivo):
    """
    private_key.enc con un byte cambiado (falla el tag aunque la maestra este bien), con estructura rara,
    con un nonce corto o diciendo q tiene menos iteraciones -> se rechaza con un error controlado, sin traza
    """
    key_manager.cargar_o_generar_claves("MasterPass2026!")
    texto = key_manager.PRIVATE_KEY_PATH.read_text(encoding="utf-8")
    key_manager.PRIVATE_KEY_PATH.write_text(manipular(texto), encoding="utf-8")

    with pytest.raises(ValueError, match=motivo):
        key_manager.cargar_o_generar_claves("MasterPass2026!")


def _emitir_certificado(private_key, sujeto: x509.Name, inicio: datetime, fin: datetime) -> None:
    """ escribe en CERTIFICATE_PATH un cert autofirmado con lo q le pases (pa simular ataques) """
    cert = (
        x509.CertificateBuilder().subject_name(sujeto).issuer_name(sujeto)
        .public_key(private_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(inicio).not_valid_after(fin)
        .sign(private_key, hashes.SHA256())
    )
    key_manager.CERTIFICATE_PATH.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def _cert_de_otra_clave(priv_key):
    # cert valido y bien autofirmado, con la misma identidad, pero de otro par de claves
    key_manager._generar_y_guardar_certificado(ec.generate_private_key(ec.SECP256R1()))


def _cert_manipulado(priv_key):
    # cambio 1 letra del sujeto -> la autofirma deja de cuadrar
    cert = x509.load_pem_x509_certificate(key_manager.CERTIFICATE_PATH.read_bytes())
    der = cert.public_bytes(serialization.Encoding.DER).replace(b"Aseguradora", b"AseguradorX")
    key_manager.CERTIFICATE_PATH.write_bytes(
        x509.load_der_x509_certificate(der).public_bytes(serialization.Encoding.PEM)
    )


def _cert_caducado(priv_key):
    ahora = datetime.now(timezone.utc)
    _emitir_certificado(priv_key, key_manager.CERT_SUBJECT, ahora - timedelta(days=400), ahora - timedelta(days=1))


def _cert_aun_no_valido(priv_key):
    ahora = datetime.now(timezone.utc)
    _emitir_certificado(priv_key, key_manager.CERT_SUBJECT, ahora + timedelta(days=1), ahora + timedelta(days=30))


def _cert_de_otra_identidad(priv_key):
    ahora = datetime.now(timezone.utc)
    otra = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Otra Empresa")])
    _emitir_certificado(priv_key, otra, ahora, ahora + timedelta(days=30))


@pytest.mark.parametrize(
    "estropear, motivo",
    [
        (_cert_de_otra_clave, "no corresponde"),
        (_cert_manipulado, "manipulado"),
        (_cert_caducado, "no está vigente"),
        (_cert_aun_no_valido, "no está vigente"),
        (_cert_de_otra_identidad, "no pertenece"),
    ],
    ids=["otra-clave", "manipulado", "caducado", "aun-no-valido", "otra-identidad"],
)
def test_certificado_no_valido_rechazado(estropear, motivo):
    """ si el cert es de otra clave, esta tocado, caducado, aun no vale o es de otra identidad, la app no arranca """
    priv_key, _ = key_manager.cargar_o_generar_claves("MasterPass2026!")
    estropear(priv_key)

    with pytest.raises(ValueError, match=motivo):
        key_manager.cargar_o_generar_claves("MasterPass2026!")


def test_no_sobrescribe_par_si_falta_privada():
    """ si falta la privada pero esta el cert, no se genera un par nuevo ni se pisa el cert """
    key_manager.cargar_o_generar_claves("MasterPass2026!")
    certificado_original = key_manager.CERTIFICATE_PATH.read_bytes()
    key_manager.PRIVATE_KEY_PATH.unlink()

    with pytest.raises(ValueError, match="falta la clave privada"):
        key_manager.cargar_o_generar_claves("MasterPass2026!")
    assert key_manager.CERTIFICATE_PATH.read_bytes() == certificado_original
    assert not key_manager.PRIVATE_KEY_PATH.exists()


def test_contrasena_maestra_debil_rechazada():
    """ no se genera el par de claves con una maestra demasiado corta """
    with pytest.raises(ValueError, match="al menos 12"):
        key_manager.cargar_o_generar_claves("corta")
    assert not key_manager.PRIVATE_KEY_PATH.exists()


def test_confirmacion_contrasena_maestra_no_coincide(monkeypatch, capsys):
    """ la 1a vez, si al confirmar la maestra no coincide, no se crea nada """
    respuestas = iter(["MasterPass2026!", "MasterPass2026?"])
    monkeypatch.setattr(main.getpass, "getpass", lambda _: next(respuestas))

    main.main()

    assert "no coinciden" in capsys.readouterr().out
    assert not key_manager.PRIVATE_KEY_PATH.exists()
    assert not key_manager.CERTIFICATE_PATH.exists()


def test_registro_usuario_duplicado():
    """Impide sobrescribir un usuario ya registrado con el mismo DNI."""
    auth.registrar_usuario("22222222B", "ClaveInicial2026!")

    with pytest.raises(ValueError, match="ya se encuentra registrado"):
        auth.registrar_usuario("22222222B", "OtraClave2026!")


@pytest.mark.parametrize(
    "password, motivo",
    [
        ("Corta2026!", "al menos 12"),
        ("x" * 129, "no puede superar"),
        ("Mi78787878Pclave!", "no puede contener el DNI"),
        ("mi78787878pclave!", "no puede contener el DNI"),
    ],
)
def test_politica_contrasena_rechaza_debiles(password, motivo):
    """ contraseñas cortas, larguisimas o q llevan el dni (en mayus o minus) no se registran """
    with pytest.raises(ValueError, match=motivo):
        auth.registrar_usuario("78787878P", password)
    assert not auth.USERS_FILE.exists()


@pytest.mark.parametrize(
    "dni, motivo",
    [
        ("", "no puede estar vacío"),
        ("1234 5678A", "solo puede contener letras y números"),
        ("../../etc", "solo puede contener letras y números"),
        ("A" * 21, "solo puede contener letras y números"),
    ],
    ids=["vacio", "con-espacio", "ruta", "largo"],
)
def test_dni_no_valido_rechazado(dni, motivo):
    """ el dni no puede ir vacio y solo admite letras y numeros (max 20), nada de espacios, separadores o rutas """
    with pytest.raises(ValueError, match=motivo):
        auth.registrar_usuario(dni, "ClienteValido2026!")
    assert not auth.USERS_FILE.exists()


def test_ataque_sustitucion_paquete_entre_clientes(monkeypatch, capsys):
    """ un atacante mueve el paquete cifrado y firmado de un cliente a otro en policies.json -> se rechaza """
    priv_key, pub_key = key_manager.cargar_o_generar_claves("MasterPass2026!")
    auth.registrar_usuario("10000001A", "MismaClaveCompartida!")
    auth.registrar_usuario("20000002B", "MismaClaveCompartida!")

    entradas = iter(["1", "Beneficiario Cliente A", "50000"])
    monkeypatch.setattr("builtins.input", lambda _: next(entradas))
    main.contratar_poliza("10000001A", "MismaClaveCompartida!", priv_key)

    # cambia el titular_dni de fuera. lo guardo con hmac valido (como si tuviera tb esa clave)
    # pa ver q la capa del aad lo para ella sola
    polizas = main._cargar_polizas()
    polizas[0]["titular_dni"] = "20000002B"
    main._guardar_polizas(polizas)

    # al consultar como el cliente B el aad (id_poliza|titular_dni) ya no cuadra y falla el tag
    main.consultar_polizas("20000002B", "MismaClaveCompartida!", pub_key)
    salida = capsys.readouterr().out
    assert "RECHAZADA: Error de autenticidad" in salida
    assert "Beneficiario Cliente A" not in salida


def test_cliente_modifica_su_poliza_y_recifra(monkeypatch, capsys):
    """
    un cliente q sabe su contraseña descifra su poliza, se sube el capital y la vuelve a cifrar bien
    (tag y aad validos). la firma de la aseguradora ya no cuadra y se rechaza. se guarda con hmac valido
    pa ver q la capa de la firma lo para ella sola
    """
    priv_key, pub_key = key_manager.cargar_o_generar_claves("MasterPass2026!")
    dni, password = "40000004D", "ClienteValido2026!"
    auth.registrar_usuario(dni, password)
    entradas = iter(["1", "Beneficiario Hija", "10000"])
    monkeypatch.setattr("builtins.input", lambda _: next(entradas))
    main.contratar_poliza(dni, password, priv_key)

    polizas = main._cargar_polizas()
    registro = polizas[0]
    clave = crypto_utils.derivar_clave_simetrica(password, base64.b64decode(registro["salt_kdf"]))
    aad = f"{registro['id_poliza']}|{dni}".encode("utf-8")
    contenido = crypto_utils.descifrar_poliza(registro, clave, aad)

    contenido["datos"]["capital_asegurado"] = 9999999.0
    registro.update(crypto_utils.cifrar_poliza(contenido, clave, aad))
    main._guardar_polizas(polizas)
    capsys.readouterr()

    main.consultar_polizas(dni, password, pub_key)
    salida = capsys.readouterr().out
    assert "Tag de autenticación VALIDADO" in salida
    assert "RECHAZADA: Firma digital inválida" in salida
    assert "9999999" not in salida


def test_titular_firmado_distinto_del_registro(capsys):
    """
    defensa en profundidad: poliza firmada pa un titular pero cifrada bien bajo el registro de otro cliente
    (tag, aad y hmac validos) -> se rechaza xq el titular firmado no coincide
    """
    priv_key, pub_key = key_manager.cargar_o_generar_claves("MasterPass2026!")
    datos = {"id_poliza": "POL-20", "titular_dni": "18181818W", "capital_asegurado": 5000.0}
    firma_b64 = crypto_utils.firmar_poliza(datos, priv_key)

    sal = os.urandom(16)
    clave = crypto_utils.derivar_clave_simetrica("ClienteValido2026!", sal)
    paquete = crypto_utils.cifrar_poliza(
        {"datos": datos, "firma_aseguradora": firma_b64}, clave, b"POL-20|19191919X"
    )
    main._guardar_polizas([{
        "id_poliza": "POL-20", "titular_dni": "19191919X",
        "salt_kdf": base64.b64encode(sal).decode("utf-8"), **paquete,
    }])
    capsys.readouterr()

    main.consultar_polizas("19191919X", "ClienteValido2026!", pub_key)
    salida = capsys.readouterr().out
    assert "no coinciden con el registro" in salida
    assert "Capital Asegurado" not in salida


@pytest.mark.skipif(
    os.name == "nt", reason="en windows getpass lee las teclas de la consola, no de stdin, asi q cerrar la entrada no le afecta"
)
def test_salida_limpia_si_se_cierra_la_entrada(tmp_path):
    """
    lanza la app como proceso de verdad y le cierra la entrada (como un ctrl+d): tiene q acabar con un mensaje
    limpio y sin traza (lo de las rutas se mira en test_rutas_de_datos_ancladas_a_la_raiz_del_proyecto)
    """
    resultado = subprocess.run(
        [sys.executable, str(main.Path(main.__file__).resolve())],
        input="", capture_output=True, text=True, cwd=tmp_path, timeout=60,
    )
    assert resultado.returncode == 0
    assert "Ejecución interrumpida" in resultado.stdout
    assert "Traceback" not in resultado.stderr


# pruebas de integridad de los ficheros (hmac-sha256)
def _editar_sin_recalcular_hmac(ruta, modificar) -> None:
    """ simula a alguien q edita el fichero a mano: cambia los datos pero no puede rehacer el hmac """
    envoltorio = json.loads(ruta.read_text(encoding="utf-8"))
    modificar(envoltorio["datos"])
    ruta.write_text(json.dumps(envoltorio), encoding="utf-8")


def _contratar_poliza_de_prueba(monkeypatch, dni, password, priv_key) -> None:
    entradas = iter(["2", "Coche 2222-BBB", "12000"])
    monkeypatch.setattr("builtins.input", lambda _: next(entradas))
    main.contratar_poliza(dni, password, priv_key)


def test_users_json_suplantacion_detectada_por_hmac():
    """
    un atacante pone en users.json la sal y el hash de una contraseña q el sabe en lugar de los de la victima,
    pa entrar como ella. el hmac del fichero ya no cuadra y el login se corta
    """
    auth.registrar_usuario("60000006F", "ClienteVictima2026!")
    sal_atacante = os.urandom(16)
    hash_atacante = auth._derivar_hash("ClaveDelAtacante2026!", sal_atacante)

    def suplantar(usuarios):
        usuarios["60000006F"] = {
            "salt": base64.b64encode(sal_atacante).decode("utf-8"),
            "hash": base64.b64encode(hash_atacante).decode("utf-8"),
        }

    _editar_sin_recalcular_hmac(auth.USERS_FILE, suplantar)

    with pytest.raises(secure_storage.IntegridadError, match="manipulado"):
        auth.autenticar_usuario("60000006F", "ClaveDelAtacante2026!")


@pytest.mark.parametrize(
    "modificar",
    [lambda polizas: polizas.append(dict(polizas[0])), lambda polizas: polizas.clear()],
    ids=["repeticion", "borrado"],
)
def test_policies_json_modificado_detectado_por_hmac(monkeypatch, modificar):
    """ duplicar un registro de poliza (ataque de repeticion) o borrarlo invalida el hmac del fichero """
    priv_key, pub_key = key_manager.cargar_o_generar_claves("MasterPass2026!")
    auth.registrar_usuario("70000007G", "ClienteValido2026!")
    _contratar_poliza_de_prueba(monkeypatch, "70000007G", "ClienteValido2026!", priv_key)

    _editar_sin_recalcular_hmac(main.POLICIES_FILE, modificar)

    with pytest.raises(secure_storage.IntegridadError, match="manipulado"):
        main.consultar_polizas("70000007G", "ClienteValido2026!", pub_key)


def test_registro_repetido_rechazado_aunque_hmac_valido(monkeypatch, capsys):
    """ defensa en profundidad: aunque el duplicado llegara con hmac valido, la copia se rechaza y solo sale 1 vez """
    priv_key, pub_key = key_manager.cargar_o_generar_claves("MasterPass2026!")
    auth.registrar_usuario("90000009J", "ClienteValido2026!")
    _contratar_poliza_de_prueba(monkeypatch, "90000009J", "ClienteValido2026!", priv_key)

    polizas = main._cargar_polizas()
    polizas.append(dict(polizas[0]))
    main._guardar_polizas(polizas)
    capsys.readouterr()

    main.consultar_polizas("90000009J", "ClienteValido2026!", pub_key)
    salida = capsys.readouterr().out
    assert "RECHAZADA: Registro repetido" in salida
    assert salida.count("Coche 2222-BBB") == 1


def test_intercambio_de_ficheros_detectado_por_hmac():
    """ copiar users.json (con su hmac valido) en el sitio de policies.json se rechaza xq el hmac lleva el nombre """
    auth.registrar_usuario("11111112K", "ClienteValido2026!")
    main.POLICIES_FILE.write_bytes(auth.USERS_FILE.read_bytes())

    with pytest.raises(secure_storage.IntegridadError, match="manipulado"):
        main._cargar_polizas()


def _hmac_alterado(envoltorio):
    envoltorio["hmac"] = _alterar_un_byte_b64(envoltorio["hmac"], 0)
    return envoltorio


@pytest.mark.parametrize(
    "estropear, motivo",
    [(_hmac_alterado, "manipulado"), (lambda envoltorio: envoltorio["datos"], "formato válido")],
    ids=["hmac-alterado", "sin-hmac"],
)
def test_users_json_no_valido_rechazado(estropear, motivo):
    """ si se cambia la propia etiqueta hmac, o el fichero va sin hmac (formato antiguo), no se acepta """
    auth.registrar_usuario("15151515T", "ClienteValido2026!")
    envoltorio = json.loads(auth.USERS_FILE.read_text(encoding="utf-8"))
    auth.USERS_FILE.write_text(json.dumps(estropear(envoltorio)), encoding="utf-8")

    with pytest.raises(secure_storage.IntegridadError, match=motivo):
        auth.autenticar_usuario("15151515T", "ClienteValido2026!")


def test_sal_de_integridad_sustituida():
    """ si se borra o cambia keys/integrity.salt sale otra clave hmac y los ficheros ya no se verifican """
    secure_storage.establecer_clave_integridad(key_manager.cargar_o_generar_clave_integridad("MasterPass2026!"))
    auth.registrar_usuario("16161616U", "ClienteValido2026!")

    key_manager.INTEGRITY_SALT_PATH.unlink()
    secure_storage.establecer_clave_integridad(key_manager.cargar_o_generar_clave_integridad("MasterPass2026!"))

    with pytest.raises(secure_storage.IntegridadError, match="manipulado"):
        auth.autenticar_usuario("16161616U", "ClienteValido2026!")


def test_aplicacion_se_detiene_si_users_json_manipulado(monkeypatch, capsys):
    """ flujo entero de main(): despues de tocar users.json a mano, el login para la app """
    # 1a ejecucion: genera claves y registra un cliente
    claves = iter(["MasterPass2026!", "MasterPass2026!", "ClienteValido2026!"])
    menus = iter(["1", "50000005E", "3"])
    monkeypatch.setattr(main.getpass, "getpass", lambda _: next(claves))
    monkeypatch.setattr("builtins.input", lambda _: next(menus))
    main.main()

    _editar_sin_recalcular_hmac(auth.USERS_FILE, lambda usuarios: usuarios["50000005E"].update(hash="AAAA"))
    capsys.readouterr()

    # 2a ejecucion: intento de login
    claves = iter(["MasterPass2026!", "ClienteValido2026!"])
    menus = iter(["2", "50000005E"])
    main.main()

    salida = capsys.readouterr().out
    assert "[ERROR CRÍTICO] El fichero users.json ha sido manipulado" in salida
    assert "La aplicación se detiene" in salida
    assert "Autenticación exitosa" not in salida


def test_fichero_con_unicode_invalido_detiene_la_aplicacion(monkeypatch, capsys):
    """
    un users.json con unicode raro no se puede ni autenticar. tiene q contar como fichero manipulado
    y parar la app, no como un error normal de registro q la deja seguir
    """
    auth.USERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    auth.USERS_FILE.write_text('{"datos": {"\\ud800": 1}, "hmac": "AAAA"}', encoding="utf-8")

    with pytest.raises(secure_storage.IntegridadError, match="formato válido"):
        auth.autenticar_usuario("17171717V", "ClienteValido2026!")

    claves = iter(["MasterPass2026!", "MasterPass2026!", "ClienteValido2026!"])
    menus = iter(["1", "17171717V"])
    monkeypatch.setattr(main.getpass, "getpass", lambda _: next(claves))
    monkeypatch.setattr("builtins.input", lambda _: next(menus))
    main.main()

    salida = capsys.readouterr().out
    assert "La aplicación se detiene" in salida
    assert "registrado con éxito" not in salida


def test_registros_con_estructura_corrupta_no_rompen_la_consulta(capsys):
    """ registros sin campos o con tipos raros se rechazan uno a uno sin cortar la app """
    _, pub_key = key_manager.cargar_o_generar_claves("MasterPass2026!")
    dni = "20202020Y"
    main._guardar_polizas([
        "esto no es un registro",
        {"titular_dni": dni},
        {"titular_dni": dni, "id_poliza": "POL-21", "salt_kdf": 5, "nonce": "AAAA", "ciphertext": "AAAA"},
        {"titular_dni": dni, "id_poliza": "POL-22"},
    ])
    capsys.readouterr()

    main.consultar_polizas(dni, "ClienteValido2026!", pub_key)
    salida = capsys.readouterr().out
    assert "sin identificador" in salida
    assert "POL-21 RECHAZADA: Estructura corrupta" in salida
    assert "POL-22 RECHAZADA: Estructura corrupta" in salida


def test_cliente_no_ve_polizas_de_otro(monkeypatch, capsys):
    """ cada cliente solo ve sus polizas """
    priv_key, pub_key = key_manager.cargar_o_generar_claves("MasterPass2026!")
    for dni, detalle in (("21212121Z", "Casa del cliente A"), ("23232323B", "Casa del cliente B")):
        auth.registrar_usuario(dni, "ClienteValido2026!")
        entradas = iter(["3", detalle, "90000"])
        monkeypatch.setattr("builtins.input", lambda _, e=entradas: next(e))
        main.contratar_poliza(dni, "ClienteValido2026!", priv_key)
    capsys.readouterr()

    main.consultar_polizas("23232323B", "ClienteValido2026!", pub_key)
    salida = capsys.readouterr().out
    assert "Casa del cliente B" in salida
    assert "Casa del cliente A" not in salida
    # la ajena ni se intenta procesar (no vale con q la rechace otra capa)
    assert salida.count("Procesando póliza") == 1
    assert "RECHAZADA" not in salida


# pruebas de validar las entradas
@pytest.mark.parametrize("capital", ["nan", "inf", "-500", "abc", "100000001"])
def test_capital_no_valido_rechazado(monkeypatch, capsys, capital):
    """
    el capital tiene q ser un numero finito, positivo y no exagerado. float() traga 'nan' e 'inf',
    y si pasaran la aseguradora firmaria una poliza con un capital sin sentido
    """
    priv_key, _ = key_manager.cargar_o_generar_claves("MasterPass2026!")
    entradas = iter(["1", "Beneficiario", capital])
    monkeypatch.setattr("builtins.input", lambda _: next(entradas))

    main.contratar_poliza("24242424C", "ClienteValido2026!", priv_key)

    assert "debe ser un número positivo" in capsys.readouterr().out
    assert not main.POLICIES_FILE.exists()


@pytest.mark.parametrize(
    "entradas, motivo",
    [
        (["9"], "Tipo de seguro no válido"),
        (["1", "   "], "entre 1 y 200 caracteres"),
        (["1", "x" * 201], "entre 1 y 200 caracteres"),
    ],
    ids=["tipo-invalido", "detalle-vacio", "detalle-largo"],
)
def test_datos_de_poliza_no_validos_rechazados(monkeypatch, capsys, entradas, motivo):
    """ un tipo de seguro q no existe o un detalle vacio o muy largo cancelan la contratacion """
    priv_key, _ = key_manager.cargar_o_generar_claves("MasterPass2026!")
    respuestas = iter(entradas)
    monkeypatch.setattr("builtins.input", lambda _: next(respuestas))

    main.contratar_poliza("25252525D", "ClienteValido2026!", priv_key)

    assert motivo in capsys.readouterr().out
    assert not main.POLICIES_FILE.exists()
