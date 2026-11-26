# InsureCrypt

Aplicación de consola para la gestión segura de pólizas de seguros (práctica final de Criptografía y Seguridad Informática, UC3M). Los clientes se registran, contratan pólizas y las consultan. Cada póliza la firma la aseguradora (ECDSA) y se cifra con una clave derivada de la contraseña del cliente (AES-256-GCM). Los ficheros de datos están protegidos con HMAC-SHA256.

Las mejoras realizadas se resumen en la sección [Mejoras realizadas](#mejoras-realizadas); el detalle y los motivos están en [CAMBIOS.md](CAMBIOS.md).

## Estructura

| Fichero | Responsabilidad |
|---|---|
| `src/main.py` | Orquestador e interfaz de consola: menús, contratación y consulta de pólizas. |
| `src/auth.py` | Registro y autenticación de clientes, política de contraseñas. |
| `src/crypto_utils.py` | Primitivas: PBKDF2, cifrado/descifrado AES-256-GCM, firma/verificación ECDSA. |
| `src/key_manager.py` | Generación, almacenamiento protegido y carga del par de claves ECDSA y de la clave de integridad. |
| `src/secure_storage.py` | Lectura/escritura de los ficheros JSON con verificación HMAC-SHA256. |
| `tests/` | Pruebas positivas (`test_positive.py`) y negativas (`test_negative.py`). |

Ficheros que genera la aplicación (excluidos del repositorio en `.gitignore`):
- `keys/private_key.enc`: clave privada ECDSA cifrada (permisos 600).
- `keys/certificate.pem`: certificado X.509 autofirmado de la aseguradora (contiene la clave pública ECDSA).
- `keys/integrity.salt`: sal para derivar la clave HMAC (no es secreta).
- `data/users.json`: clientes registrados (sal + hash de cada contraseña), protegido con HMAC.
- `data/policies.json`: pólizas cifradas, protegido con HMAC.

## Instalación y ejecución

**Dependencias** (versiones fijadas en `requirements.txt`):
- `cryptography==42.0.5`: única librería criptográfica.
- `pytest==8.1.1`: pruebas.
- `ruff==0.3.5`: linter.

El entorno de referencia es Python 3.11 (imagen `python:3.11-slim`).

### Opción A: Dev Container en VS Code (recomendada)
1. Instalar Docker Desktop (Windows/macOS) o Docker Engine (Linux), y la extensión **Dev Containers** de VS Code.
2. Abrir Docker Desktop y esperar a que el servicio esté activo.
3. En VS Code, pulsar F1 y elegir **"Dev Containers: Reopen in Container"**.
4. En la terminal del contenedor:
   ```bash
   pytest -v              # ejecutar todas las pruebas
   python src/main.py     # ejecutar la aplicación
   ```

### Opción B: Docker desde la línea de comandos
Desde la carpeta del proyecto:
```bash
docker build -t insurecrypt -f .devcontainer/Dockerfile .
docker run --rm -v "${PWD}:/app" -w /app insurecrypt python -m pytest -v
docker run --rm -it -v "${PWD}:/app" -w /app insurecrypt python src/main.py
```

### Opción C: Entorno virtual local
```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
pytest -v
python src/main.py
```
En Windows se salta una prueba (la de cerrar la entrada, porque allí `getpass` lee directamente de la consola) y la comprobación de permisos 600 no se hace (los permisos POSIX no aplican): 68 pasan y 1 se salta.

### Uso
1. **Primer arranque.** Se pide crear la **contraseña maestra** de la aseguradora (mínimo 12 caracteres) y confirmarla. Con ella se cifra la clave privada y se deriva la clave HMAC. En los siguientes arranques se pide la misma.
2. **Registrar cliente.** DNI/ID y contraseña: entre 12 y 128 caracteres, sin contener el DNI. Los espacios cuentan.
3. **Iniciar sesión.** Desde el panel del cliente se puede contratar una póliza (vida, coche u hogar) o consultar las propias, que se descifran y verifican automáticamente.

Para empezar de cero, basta con borrar las carpetas `data/` y `keys/`.

## Checklist de requisitos

**1. Registro y autenticación de usuarios** (`auth.py`)
- Contraseñas almacenadas con PBKDF2-HMAC-SHA256 (600.000 iteraciones, recomendación de OWASP), sal aleatoria de 16 bytes por usuario (`os.urandom`) y comparación en tiempo constante (`hmac.compare_digest`).
- Política de contraseñas: entre 12 y 128 caracteres (OWASP ASVS V2.1.1/V2.1.2), sin contener el DNI, sin reglas de composición. Las contraseñas no se recortan.
- Contra la enumeración de usuarios: mismo mensaje de fallo si el DNI no existe o la contraseña es incorrecta, y en ambos casos se calcula PBKDF2 para que la respuesta tarde lo mismo.
- Mejora opcional no implementada: segundo factor (algo que tenemos / algo que somos).

**2. Cifrado y descifrado** (`crypto_utils.py`, `main.py`)
- AES-256-GCM (cifrado autenticado) para cada póliza, con nonce aleatorio de 96 bits por cifrado. La clave de cada póliza se deriva de la contraseña del cliente con una sal propia, así que no se reutilizan ni claves ni nonces.
- Los metadatos en claro del registro (`id_poliza|titular_dni`) se autentican como AAD.
- Los logs muestran algoritmo, longitudes de clave, nonce y tag, y tamaño del AAD; nunca claves ni contraseñas.

**3. Autenticación de mensajes (MAC)** (`secure_storage.py`)
- Cada póliza: tag GCM de 128 bits (incluye el AAD).
- Ficheros `users.json` y `policies.json`: HMAC-SHA256 con clave de 256 bits, que también cubre el nombre del fichero. Detecta modificación, borrado, duplicación (repetición) e intercambio de registros. Si un HMAC falla, la aplicación se detiene.

**4. Firma digital** (`crypto_utils.py`, `main.py`)
- ECDSA sobre la curva P-256 (SECP256R1) con SHA-256. La aseguradora firma cada póliza al contratarla. Se firma y después se cifra, así que la firma queda dentro del texto cifrado.
- La verificación es automática al consultar: una firma inválida o alterada hace que se rechace la póliza.
- La clave pública se distribuye en un certificado X.509 autofirmado (`CN=InsureCrypt Aseguradora`, ECDSA-SHA256, 5 años, uso de clave "firma digital" y "no repudio"). Al arrancar se verifica su autofirma, su identidad, su validez y que corresponda a la clave privada. El log muestra su huella SHA-256.

**5. Generación y almacenamiento de claves** (`key_manager.py`)
- Clave de cada póliza (AES-256): derivada en memoria de la contraseña del cliente, nunca almacenada.
- Clave privada ECDSA: generada con el CSPRNG de OpenSSL. Se guarda cifrada con AES-256-GCM, con una clave PBKDF2-SHA256 de 600.000 iteraciones derivada de la contraseña maestra, y con permisos 600. Al cargarla se comprueba que el certificado corresponde a la clave privada, y nunca se sobrescribe un par existente (si falta el certificado, se reemite con la misma clave).
- Clave HMAC (256 bits): derivada en memoria de la contraseña maestra con su propia sal, nunca almacenada.

**Otras consideraciones**
- Toda la aleatoriedad (sales, nonces, claves, IDs de póliza) procede de fuentes criptográficamente seguras (`os.urandom`, `secrets` o el CSPRNG de OpenSSL).
- Los fallos de tag, firma o HMAC detienen el procesamiento de los datos afectados. Ctrl+C sale de forma limpia.
- Validación de entradas: DNI/ID alfanumérico (máximo 20), detalle de 1 a 200 caracteres y capital finito, positivo y de 100 millones como máximo.

## Mejoras realizadas

Resumen de lo que se cambió respecto a la primera versión (detalle y motivos en [CAMBIOS.md](CAMBIOS.md)).

**1. Registro y autenticación de usuarios**
- Antes, el login delataba si un DNI estaba registrado (mensaje distinto y respuesta inmediata, 0,1 ms frente a 123 ms). Ahora hay un único mensaje de fallo y un PBKDF2 de relleno, así que los dos casos tardan lo mismo.
- La política de contraseñas pasó de "mínimo 8" en la interfaz a 12–128 caracteres sin el DNI, comprobada en `auth.py`.
- Se eliminó `.strip()`, que modificaba en silencio las contraseñas con espacios.

**2. Cifrado y descifrado**
- `id_poliza` y `titular_dni`, que se guardan en claro, se autentican ahora como AAD de AES-GCM: moverlos o cambiarlos invalida el tag.

**3. Autenticación de mensajes (MAC)**
- Nuevo `secure_storage.py`: HMAC-SHA256 sobre `users.json` y `policies.json`. Antes se podía suplantar a un cliente editando `users.json`, o borrar y duplicar pólizas sin que se notara.
- Además, se rechaza cualquier `id_poliza` repetido (ataque de repetición).

**4. Firma digital**
- La firma se guarda dentro del texto cifrado (firmar y después cifrar). Antes estaba en claro y permitía confirmar contenidos adivinados.
- Al cargar las claves se comprueba que la clave pública corresponde a la privada.
- `public_key.pem` se sustituyó por un certificado X.509 autofirmado que vincula la clave pública con la identidad de la aseguradora. Se rechaza si está manipulado, caducado, emitido a otra identidad o con otra clave.

**5. Generación y almacenamiento de claves**
- La clave privada estaba protegida con PBKDF2 de solo 2048 iteraciones (PEM con `BestAvailableEncryption`). Ahora se cifra con AES-256-GCM, con PBKDF2 de 600.000 iteraciones y permisos 600.
- Ya no se sobrescribe la clave privada si falta la pública. La contraseña maestra exige un mínimo de 12 caracteres y se confirma en el primer arranque.
- La clave HMAC se deriva de la contraseña maestra y nunca se almacena.

**Calidad del software**
- Rutas relativas a la raíz del proyecto, salida limpia con Ctrl+C, PBKDF2 en un único sitio y logs corregidos (ya no dicen "os.urandom", ni "NIST/OWASP", ni "claves eliminadas de memoria").
- `requirements.txt` sin dependencias que no se usan (`bcrypt`, `ipykernel`).
- El ID de póliza pasó de 32 a 64 bits aleatorios (`secrets.token_hex(8)`), para que no haya colisiones.
- Validación de entradas: el capital debe ser un número finito y positivo (antes aceptaba `nan` e `inf`), con límites de tamaño en el detalle y de formato en el DNI.
- Los ficheros mal formados (clave privada, datos o registros de póliza) se rechazan con un error controlado, sin trazas.
- De 17 a 69 pruebas (44 funciones), y `ruff` sin avisos.

**Limitaciones conocidas**
- No se detecta la restauración de una copia antigua completa de los ficheros (rollback), ni el borrado de un fichero entero.
- El registro revela si un DNI ya existe.
- No se comprueban las contraseñas contra listas de contraseñas filtradas.
- Python no garantiza el borrado de las claves de la memoria.
- El certificado es autofirmado: no lo respalda una autoridad de certificación, así que la confianza depende de conocer su huella.
- No hay límite de intentos de inicio de sesión.
- Todas las claves derivadas de contraseñas usan la misma función PBKDF2 y solo las distingue la sal (sin separación de dominios).
- Solo la clave privada tiene permisos 600, y la escritura de los ficheros no es atómica.

## Pruebas

```bash
pytest -v
```

Hay 69 pruebas en 44 funciones: 12 positivas y 57 negativas (32 funciones negativas, 10 de ellas con varios casos). Cada prueba incluye un docstring que explica qué demuestra.

**Positivas** (`tests/test_positive.py`)
- Claves: generación y carga del par ECDSA con la privada cifrada (AES-256-GCM, 600.000 iteraciones); campos del certificado X.509 (sujeto, ECDSA-SHA256, P-256, uso de clave, 5 años); reemisión del certificado si falta; permisos 600 (solo en Linux); derivación de la clave de integridad.
- Autenticación: registro y login correctos (sal de 16 bytes, sin la contraseña en claro); contraseña con espacios respetada en la aplicación real.
- Cifrado: cifrado y descifrado AES-256-GCM; nonces de 96 bits distintos en cada cifrado; la firma se guarda dentro del texto cifrado.
- Firma: firma y verificación ECDSA; serialización determinista (el orden de las claves no invalida la firma).
- Integridad: guardado y verificación con HMAC; derivación de la clave HMAC.
- Flujo completo: contratar y consultar una póliza desde `main.py`; dos pólizas tienen ID de 64 bits, sal y nonce distintos.
- Otras: dos clientes con la misma contraseña tienen sal y hash distintos; las rutas de datos apuntan a la raíz del proyecto aunque se lance desde otra carpeta.

**Negativas** (`tests/test_negative.py`)
- Credenciales: contraseña maestra incorrecta (también desde la aplicación); contraseña de cliente incorrecta y usuario inexistente, con el mismo mensaje; PBKDF2 ejecutado aunque el usuario no exista; contraseñas débiles (corta, larga, con el DNI); DNI vacío o con formato no válido; usuario duplicado.
- Cifrado: texto cifrado, tag o nonce alterados, o texto cifrado truncado; clave incorrecta; traslado de una póliza a otro cliente (AAD).
- Firma: firma alterada; firma mal formada; datos modificados tras firmar; cliente que modifica su póliza y la vuelve a cifrar; titular firmado distinto del registro.
- Claves: `private_key.enc` manipulado, mal formado o con iteraciones rebajadas; certificado de otra clave, manipulado, caducado, aún no válido o de otra identidad; no se sobrescribe el par si falta la privada; contraseña maestra débil; confirmación de la contraseña maestra que no coincide.
- Integridad y repetición: suplantación en `users.json`; registro de póliza duplicado (repetición) o borrado; copia repetida rechazada aunque el HMAC sea válido; intercambio de ficheros; etiqueta HMAC alterada o fichero sin HMAC; `integrity.salt` sustituida; la aplicación se detiene si `users.json` está manipulado.
- Entradas: capital no válido (`nan`, `inf`, negativo, no numérico, desmesurado); tipo de seguro inválido; detalle vacío o demasiado largo.
- Robustez: salida limpia si se cierra la entrada; registros de póliza con estructura corrupta; fichero con Unicode no válido; un cliente no ve las pólizas de otro.
