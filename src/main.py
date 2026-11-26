# Orquestador
import base64
import getpass
import math
import os
import secrets
from datetime import datetime
from pathlib import Path

from auth import MAX_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH, autenticar_usuario, registrar_usuario
from crypto_utils import (
    cifrar_poliza,
    derivar_clave_simetrica,
    descifrar_poliza,
    firmar_poliza,
    verificar_firma_poliza,
)
from key_manager import cargar_o_generar_clave_integridad, cargar_o_generar_claves, existe_clave_privada
from secure_storage import IntegridadError, cargar_json, establecer_clave_integridad, guardar_json

# rutas desde la raiz del proyecto, asi da igual desde q carpeta se lance la app
DATA_DIR = Path(__file__).resolve().parent.parent / "data"
POLICIES_FILE = DATA_DIR / "policies.json"
TIPOS_SEGURO_VALIDOS = {"1": "Vida", "2": "Coche", "3": "Hogar"}
MAX_DETALLE_LENGTH = 200
MAX_CAPITAL = 100_000_000  # euros


def _cargar_polizas() -> list:
    """ carga policies.json comprobando antes su hmac (si lo han tocado salta IntegridadError) """
    return cargar_json(POLICIES_FILE, [])


def _guardar_polizas(polizas: list) -> None:
    guardar_json(POLICIES_FILE, polizas)


def _aad_registro(id_poliza: str, titular_dni: str) -> bytes:
    """
    aad de aes-gcm: ata el ciphertext a los datos q van en claro en el registro
    si alguien cambia el id_poliza o el titular_dni en policies.json el tag deja de valer
    """
    return f"{id_poliza}|{titular_dni}".encode("utf-8")


def contratar_poliza(dni_cliente: str, password_cliente: str, private_key) -> None:
    """Captura los datos de una póliza, la firma con ECDSA y la cifra con AES-256-GCM."""
    print("\n--- CONTRATACIÓN DE NUEVA PÓLIZA ---")
    print("Seleccione el tipo de seguro:")
    print("1. Seguro de Vida")
    print("2. Seguro de Coche")
    print("3. Seguro de Hogar")
    opcion_tipo = input("Opción (1-3): ").strip()

    if opcion_tipo not in TIPOS_SEGURO_VALIDOS:
        print("[ERROR] Tipo de seguro no válido. Operación cancelada.")
        return

    tipo_seguro = TIPOS_SEGURO_VALIDOS[opcion_tipo]
    detalle = input("Detalle del bien asegurado o beneficiario: ").strip()
    if not detalle or len(detalle) > MAX_DETALLE_LENGTH:
        print(f"[ERROR] El detalle de cobertura debe tener entre 1 y {MAX_DETALLE_LENGTH} caracteres.")
        return

    try:
        capital = float(input("Capital asegurado (€): ").strip())
        # float() se traga 'nan', 'inf' y cosas como '1e400' sin dar error, isfinite los quita
        if not math.isfinite(capital) or not 0 < capital <= MAX_CAPITAL:
            raise ValueError
    except ValueError:
        print(f"[ERROR] El capital asegurado debe ser un número positivo (máximo {MAX_CAPITAL:,.0f} €).")
        return

    # id de 64 bits aleatorios (csprng), casi imposible q se repita (y los ids repetidos se rechazan)
    id_poliza = f"POL-{secrets.token_hex(8).upper()}"
    datos_poliza = {
        "id_poliza": id_poliza,
        "titular_dni": dni_cliente,
        "tipo_seguro": tipo_seguro,
        "detalle_cobertura": detalle,
        "capital_asegurado": capital,
        "fecha_emision": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

    # 1. Firma digital del contrato por parte de la aseguradora (ECDSA-SHA256)
    firma_b64 = firmar_poliza(datos_poliza, private_key)

    # 2. Derivación en memoria de la clave simétrica AES-256
    salt_kdf = os.urandom(16)
    clave_simetrica = derivar_clave_simetrica(password_cliente, salt_kdf)

    # 3. cifrado autenticado (aes-256-gcm) de datos + firma (1o firmo y luego cifro, asi la firma no va en claro)
    #    y lo q va en claro en el registro se mete como aad
    contenido = {"datos": datos_poliza, "firma_aseguradora": firma_b64}
    paquete_cifrado = cifrar_poliza(contenido, clave_simetrica, _aad_registro(id_poliza, dni_cliente))

    registro_almacenado = {
        "id_poliza": id_poliza,
        "titular_dni": dni_cliente,
        "salt_kdf": base64.b64encode(salt_kdf).decode("utf-8"),
        "nonce": paquete_cifrado["nonce"],
        "ciphertext": paquete_cifrado["ciphertext"],
    }

    polizas = _cargar_polizas()
    polizas.append(registro_almacenado)
    _guardar_polizas(polizas)
    print(f"\n[OK] Póliza {id_poliza} ({tipo_seguro}) contratada, firmada y cifrada correctamente.")


def consultar_polizas(dni_cliente: str, password_cliente: str, public_key) -> None:
    """Descifra (AES-GCM) y verifica la firma digital (ECDSA) de las pólizas del cliente."""
    print(f"\n--- PÓLIZAS DEL CLIENTE ({dni_cliente}) ---")
    polizas = _cargar_polizas()
    mis_polizas = [p for p in polizas if isinstance(p, dict) and p.get("titular_dni") == dni_cliente]

    if not mis_polizas:
        print("No tiene pólizas contratadas actualmente.")
        return

    ids_procesados = set()
    for registro in mis_polizas:
        id_poliza = registro.get("id_poliza")
        if not isinstance(id_poliza, str):
            print("\n[ALERTA SEGURIDAD] Registro de póliza RECHAZADO: Estructura corrupta (sin identificador).")
            continue
        print(f"\nProcesando póliza {id_poliza}...")

        # defensa en profundidad contra repeticion: el hmac del fichero ya pilla un registro duplicado,
        # pero si aun asi llegara uno, la copia se rechaza en vez de salir 2 veces
        if id_poliza in ids_procesados:
            print(f"[ALERTA SEGURIDAD] Póliza {id_poliza} RECHAZADA: Registro repetido (posible ataque de repetición).")
            continue
        ids_procesados.add(id_poliza)

        try:
            # 1. Reconstrucción de la clave simétrica en memoria mediante KDF
            salt_kdf = base64.b64decode(registro["salt_kdf"])
            clave_simetrica = derivar_clave_simetrica(password_cliente, salt_kdf)

            # 2. descifrar y comprobar integridad/autenticidad (tag gcm sobre ciphertext + aad)
            contenido = descifrar_poliza(
                {"nonce": registro["nonce"], "ciphertext": registro["ciphertext"]},
                clave_simetrica,
                _aad_registro(id_poliza, registro["titular_dni"]),
            )
            datos_poliza = contenido["datos"]

            # 3. Verificación automática de la firma digital de la aseguradora (ECDSA)
            es_firma_valida = verificar_firma_poliza(
                datos_poliza, contenido["firma_aseguradora"], public_key
            )
            if not es_firma_valida:
                print(f"[ALERTA SEGURIDAD] Póliza {id_poliza} RECHAZADA: Firma digital inválida.")
                continue

            # defensa en profundidad: el aad ya ata el titular, pero miro tb el titular y el id q van firmados
            if datos_poliza.get("titular_dni") != dni_cliente or datos_poliza.get("id_poliza") != id_poliza:
                print(f"[ALERTA SEGURIDAD] Póliza {id_poliza} RECHAZADA: El titular o el ID firmados no coinciden con el registro.")
                continue

            print(f"  ID Póliza        : {datos_poliza['id_poliza']}")
            print(f"  Tipo de Seguro   : {datos_poliza['tipo_seguro']}")
            print(f"  Cobertura        : {datos_poliza['detalle_cobertura']}")
            print(f"  Capital Asegurado: {datos_poliza['capital_asegurado']} €")
            print(f"  Fecha Emisión    : {datos_poliza['fecha_emision']}")

        except ValueError as e:
            print(f"[ALERTA SEGURIDAD] Póliza {id_poliza} RECHAZADA: {e}")
        except (KeyError, TypeError, AttributeError):
            # faltan campos o tienen un tipo raro: fuera ese registro, pero la app sigue
            print(f"[ALERTA SEGURIDAD] Póliza {id_poliza} RECHAZADA: Estructura corrupta.")


def menu_sesion_usuario(dni: str, password: str, private_key, public_key) -> None:
    """Menú interactivo para un cliente autenticado."""
    while True:
        print(f"\n=== PANEL DE CLIENTE: {dni} ===")
        print("1. Contratar nueva póliza")
        print("2. Consultar y verificar mis pólizas")
        print("3. Cerrar sesión")
        opcion = input("Seleccione una opción: ").strip()

        if opcion == "1":
            contratar_poliza(dni, password, private_key)
        elif opcion == "2":
            consultar_polizas(dni, password, public_key)
        elif opcion == "3":
            # las claves derivadas solo estan en variables locales y se dejan de usar, pero python no deja
            # asegurar q se borran de memoria, asi q el log no lo dice
            print("[LOG SEGURIDAD] Sesión cerrada.")
            break
        else:
            print("[ERROR] Opción no válida.")


def main() -> None:
    print("====================================================")
    print("   INSURECRYPT - Gestión Segura de Pólizas (UC3M)   ")
    print("====================================================")

    master_password = getpass.getpass("Introduzca la contraseña maestra de la aseguradora: ")
    if not master_password:
        print("[ERROR CRÍTICO] La contraseña maestra no puede estar vacía.")
        return

    # 1a vez: se va a generar el par de claves y una errata aqui no tiene arreglo, asi q se pide confirmar
    if not existe_clave_privada():
        print("[LOG SEGURIDAD] No existe clave privada: se generará un nuevo par de claves ECDSA.")
        confirmacion = getpass.getpass("Confirme la contraseña maestra: ")
        if confirmacion != master_password:
            print("[ERROR CRÍTICO] Las contraseñas maestras no coinciden. No se ha generado ninguna clave.")
            return

    try:
        private_key, public_key = cargar_o_generar_claves(master_password)
        establecer_clave_integridad(cargar_o_generar_clave_integridad(master_password))
    except ValueError as e:
        print(f"[ERROR CRÍTICO] {e}")
        return

    # si un fichero no pasa el hmac no seguimos currando con datos q no son de fiar
    try:
        menu_principal(private_key, public_key)
    except IntegridadError as e:
        print(f"[ERROR CRÍTICO] {e} La aplicación se detiene para no procesar datos manipulados.")


def menu_principal(private_key, public_key) -> None:
    """ menu del ppio: registro y login de clientes """
    while True:
        print("\n--- MENÚ PRINCIPAL ---")
        print("1. Registrar cliente")
        print("2. Iniciar sesión")
        print("3. Salir")
        opcion = input("Seleccione una opción: ").strip()

        if opcion == "1":
            dni = input("Introduzca su DNI/ID de cliente: ").strip()
            # aqui nada de .strip(), los espacios son parte de la contraseña q eligio el usuario
            password = getpass.getpass(
                f"Cree una contraseña ({MIN_PASSWORD_LENGTH}-{MAX_PASSWORD_LENGTH} caracteres, sin incluir su DNI): "
            )
            try:
                registrar_usuario(dni, password)
            except ValueError as e:
                print(f"[ERROR] {e}")

        elif opcion == "2":
            dni = input("DNI/ID de cliente: ").strip()
            password = getpass.getpass("Contraseña: ")
            if autenticar_usuario(dni, password):
                menu_sesion_usuario(dni, password, private_key, public_key)

        elif opcion == "3":
            print("Saliendo de InsureCrypt...")
            break
        else:
            print("[ERROR] Opción no válida.")


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        # ctrl+c o se acaba la entrada: salimos limpio, sin traza
        print("\n[INFO] Ejecución interrumpida. Saliendo de InsureCrypt.")