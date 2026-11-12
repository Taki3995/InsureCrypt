# Orquestador
import base64
import getpass
import json
import os
import uuid
from datetime import datetime
from pathlib import Path

from auth import autenticar_usuario, registrar_usuario
from crypto_utils import (
    cifrar_poliza,
    derivar_clave_simetrica,
    descifrar_poliza,
    firmar_poliza,
    verificar_firma_poliza,
)
from key_manager import cargar_o_generar_claves

DATA_DIR = Path("data")
POLICIES_FILE = DATA_DIR / "policies.json"
TIPOS_SEGURO_VALIDOS = {"1": "Vida", "2": "Coche", "3": "Hogar"}


def inicializar_almacen_polizas() -> None:
    """Crea la carpeta data/ y el archivo policies.json si no existen."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not POLICIES_FILE.exists():
        with open(POLICIES_FILE, "w", encoding="utf-8") as f:
            json.dump([], f)


def _cargar_polizas() -> list:
    inicializar_almacen_polizas()
    with open(POLICIES_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def _guardar_polizas(polizas: list) -> None:
    with open(POLICIES_FILE, "w", encoding="utf-8") as f:
        json.dump(polizas, f, indent=4)


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
    if not detalle:
        print("[ERROR] El detalle de cobertura no puede estar vacío.")
        return

    try:
        capital = float(input("Capital asegurado (€): ").strip())
        if capital <= 0:
            raise ValueError
    except ValueError:
        print("[ERROR] El capital asegurado debe ser un número positivo.")
        return

    id_poliza = f"POL-{uuid.uuid4().hex[:8].upper()}"
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

    # 3. Cifrado autenticado de los datos de la póliza (AES-256-GCM)
    paquete_cifrado = cifrar_poliza(datos_poliza, clave_simetrica)

    registro_almacenado = {
        "id_poliza": id_poliza,
        "titular_dni": dni_cliente,
        "salt_kdf": base64.b64encode(salt_kdf).decode("utf-8"),
        "nonce": paquete_cifrado["nonce"],
        "ciphertext": paquete_cifrado["ciphertext"],
        "firma_aseguradora": firma_b64,
    }

    polizas = _cargar_polizas()
    polizas.append(registro_almacenado)
    _guardar_polizas(polizas)
    print(f"\n[OK] Póliza {id_poliza} ({tipo_seguro}) contratada, firmada y cifrada correctamente.")


def consultar_polizas(dni_cliente: str, password_cliente: str, public_key) -> None:
    """Descifra (AES-GCM) y verifica la firma digital (ECDSA) de las pólizas del cliente."""
    print(f"\n--- PÓLIZAS DEL CLIENTE ({dni_cliente}) ---")
    polizas = _cargar_polizas()
    mis_polizas = [p for p in polizas if p.get("titular_dni") == dni_cliente]

    if not mis_polizas:
        print("No tiene pólizas contratadas actualmente.")
        return

    for registro in mis_polizas:
        id_poliza = registro["id_poliza"]
        print(f"\nProcesando póliza {id_poliza}...")
        try:
            # 1. Reconstrucción de la clave simétrica en memoria mediante KDF
            salt_kdf = base64.b64decode(registro["salt_kdf"])
            clave_simetrica = derivar_clave_simetrica(password_cliente, salt_kdf)

            # 2. Descifrado y validación de integridad/autenticidad (Tag AES-GCM)
            datos_poliza = descifrar_poliza(
                {"nonce": registro["nonce"], "ciphertext": registro["ciphertext"]},
                clave_simetrica,
            )

            # 3. Verificación automática de la firma digital de la aseguradora (ECDSA)
            es_firma_valida = verificar_firma_poliza(
                datos_poliza, registro["firma_aseguradora"], public_key
            )
            if not es_firma_valida:
                print(f"[ALERTA SEGURIDAD] Póliza {id_poliza} RECHAZADA: Firma digital inválida.")
                continue

            # Validación adicional de vinculación de titularidad
            if datos_poliza.get("titular_dni") != dni_cliente:
                print(f"[ALERTA SEGURIDAD] Póliza {id_poliza} RECHAZADA: El titular no coincide.")
                continue

            print(f"  ID Póliza        : {datos_poliza['id_poliza']}")
            print(f"  Tipo de Seguro   : {datos_poliza['tipo_seguro']}")
            print(f"  Cobertura        : {datos_poliza['detalle_cobertura']}")
            print(f"  Capital Asegurado: {datos_poliza['capital_asegurado']} €")
            print(f"  Fecha Emisión    : {datos_poliza['fecha_emision']}")

        except ValueError as e:
            print(f"[ALERTA SEGURIDAD] Póliza {id_poliza} RECHAZADA: {e}")
        except KeyError:
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
            print("[LOG SEGURIDAD] Sesión cerrada. Claves de sesión eliminadas de memoria.")
            break
        else:
            print("[ERROR] Opción no válida.")


def main() -> None:
    print("====================================================")
    print("   INSURECRYPT - Gestión Segura de Pólizas (UC3M)   ")
    print("====================================================")

    master_password = getpass.getpass("Introduzca la contraseña maestra de la aseguradora: ").strip()
    if not master_password:
        print("[ERROR CRÍTICO] La contraseña maestra no puede estar vacía.")
        return

    try:
        private_key, public_key = cargar_o_generar_claves(master_password)
    except ValueError as e:
        print(f"[ERROR CRÍTICO] {e}")
        return

    while True:
        print("\n--- MENÚ PRINCIPAL ---")
        print("1. Registrar cliente")
        print("2. Iniciar sesión")
        print("3. Salir")
        opcion = input("Seleccione una opción: ").strip()

        if opcion == "1":
            dni = input("Introduzca su DNI/ID de cliente: ").strip()
            password = getpass.getpass("Cree una contraseña (mínimo 8 caracteres): ").strip()
            if not dni or len(password) < 8:
                print("[ERROR] El DNI no puede estar vacío y la contraseña debe tener al menos 8 caracteres.")
                continue
            try:
                registrar_usuario(dni, password)
            except ValueError as e:
                print(f"[ERROR] {e}")

        elif opcion == "2":
            dni = input("DNI/ID de cliente: ").strip()
            password = getpass.getpass("Contraseña: ").strip()
            if autenticar_usuario(dni, password):
                menu_sesion_usuario(dni, password, private_key, public_key)

        elif opcion == "3":
            print("Saliendo de InsureCrypt...")
            break
        else:
            print("[ERROR] Opción no válida.")


if __name__ == "__main__":
    main()