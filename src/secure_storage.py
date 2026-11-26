# guardar/cargar los json con integridad: cada fichero va junto con un hmac-sha256 de lo q tiene dentro

import base64
import json
from pathlib import Path
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac

HMAC_KEY_SIZE_BYTES = 32  # hmac-sha256 con clave de 256 bits

# clave de integridad de la sesion, sale de la maestra al arrancar y solo esta en memoria
_clave_integridad: bytes | None = None


class IntegridadError(Exception):
    """ el fichero no pasa el hmac: lo han tocado o esta corrupto """


def establecer_clave_integridad(clave: bytes) -> None:
    """ pone la clave hmac q se usa pa proteger y comprobar los ficheros """
    global _clave_integridad
    if len(clave) != HMAC_KEY_SIZE_BYTES:
        raise ValueError("La clave de integridad debe tener 256 bits.")
    _clave_integridad = clave


def _nuevo_hmac(ruta: Path, datos) -> hmac.HMAC:
    """
    prepara el hmac-sha256 de un fichero. mete el nombre del fichero + el contenido serializado siempre igual,
    asi no se puede poner el contenido de un fichero en el sitio del otro
    """
    if _clave_integridad is None:
        raise RuntimeError("Clave de integridad no establecida: no se pueden leer ni escribir datos protegidos.")
    contenido = json.dumps(datos, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    h = hmac.HMAC(_clave_integridad, hashes.SHA256())
    h.update(ruta.name.encode("utf-8") + b"\n" + contenido.encode("utf-8"))
    return h


def guardar_json(ruta: Path, datos) -> None:
    """ guarda los datos con su hmac-sha256 """
    etiqueta = _nuevo_hmac(ruta, datos).finalize()
    ruta.parent.mkdir(parents=True, exist_ok=True)
    with open(ruta, "w", encoding="utf-8") as f:
        json.dump({"datos": datos, "hmac": base64.b64encode(etiqueta).decode("utf-8")}, f, indent=4)


def cargar_json(ruta: Path, valor_inicial):
    """
    carga un fichero comprobando antes su hmac-sha256 (comparacion en tiempo cte)
    si aun no existe devuelve valor_inicial, y si el hmac no cuadra lanza IntegridadError
    """
    if not ruta.exists():
        return valor_inicial

    try:
        envoltorio = json.loads(ruta.read_text(encoding="utf-8"))
        datos = envoltorio["datos"]
        etiqueta = base64.b64decode(envoltorio["hmac"])
    except (ValueError, KeyError, TypeError):
        print(f"[LOG ERROR SEGURIDAD] {ruta.name}: formato no válido o sin HMAC.")
        raise IntegridadError(f"El fichero {ruta.name} no tiene un formato válido o carece de HMAC.")

    try:
        calculo = _nuevo_hmac(ruta, datos)
    except (ValueError, TypeError):
        # contenido q ni se puede serializar pa calcular el hmac (p. ej. unicode roto): cuenta como manipulado,
        # nunca como un error normal q deje seguir a la app
        print(f"[LOG ERROR SEGURIDAD] {ruta.name}: contenido no válido.")
        raise IntegridadError(f"El fichero {ruta.name} no tiene un formato válido o carece de HMAC.")

    try:
        calculo.verify(etiqueta)
    except InvalidSignature:
        print(f"[LOG ERROR SEGURIDAD] {ruta.name}: HMAC-SHA256 INVÁLIDO. Fichero manipulado.")
        raise IntegridadError(f"El fichero {ruta.name} ha sido manipulado (HMAC inválido).")

    print(f"[LOG SEGURIDAD] Integridad de {ruta.name} verificada: HMAC-SHA256 | Clave: 256 bits.")
    return datos
