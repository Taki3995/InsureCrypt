# CAMBIOS

Resumen de los cambios de seguridad y calidad hechos al proyecto, ordenados por pasos. En cada punto se indica el problema, qué se cambió (fichero y función) y por qué.

**Estado:** 69 de 69 pruebas pasan (44 funciones) en el contenedor Docker (al empezar había 17) y `ruff check` no da avisos.
**Aviso:** los formatos de `keys/` y `data/` han cambiado; las carpetas creadas antes de estos cambios hay que borrarlas.

| Paso | Tema | Secciones del enunciado |
|---|---|---|
| 2 | Protección de las claves de la aseguradora | 4. Firma digital, 5. Claves |
| 3 | AAD en el cifrado y firma dentro del cifrado | 2. Cifrado, 4. Firma digital |
| 4 | HMAC de los ficheros y ataques de repetición | 3. MAC, 5. Claves, Otras consideraciones |
| 5 | Autenticación de usuarios | 1. Registro y autenticación |
| 6 | Calidad, dependencias y documentación | Calidad del software |
| 7 | Certificado X.509 de la aseguradora e ID de póliza de 64 bits | 4. Firma digital, 5. Claves, Otras consideraciones |
| 8 | Correcciones tras una revisión independiente | Calidad del software, Otras consideraciones |
| 9 | Recorte de las pruebas y revisión final | Calidad del software |

---

## Paso 2 — Protección de las claves de la aseguradora

- **Clave privada mal protegida.** Se guardaba en PEM con `BestAvailableEncryption`, que (comprobado con `openssl asn1parse`) usa PBKDF2 de solo **2048 iteraciones** y AES-CBC sin autenticar. La librería no permite subir las iteraciones en PKCS#8.
  → Ahora se cifra con **AES-256-GCM** usando una clave **PBKDF2-SHA256 de 600.000 iteraciones** derivada de la contraseña maestra, con sal y nonce aleatorios, y se guarda en `keys/private_key.enc` (`key_manager._guardar_clave_privada` / `_cargar_clave_privada`). Si la contraseña es incorrecta o el fichero se ha manipulado, el tag GCM falla y la aplicación no arranca. La contraseña maestra debe tener al menos 12 caracteres.
  *Contrapartida:* ya no es un PEM estándar que se pueda abrir con `openssl`.
- **Clave pública sin vincular.** No se comprobaba que `public_key.pem` correspondiera a la privada.
  → Se calcula la pública a partir de la privada y se compara; si no coinciden, error (`cargar_o_generar_claves`). En el paso 7, `public_key.pem` se sustituyó por un certificado X.509.
- **Riesgo de perder la clave privada.** Si faltaba la pública, se generaba un par nuevo que **sobrescribía la privada** e invalidaba todas las firmas.
  → Nunca se sobrescribe un par: si falta la pública se reconstruye, y si falta la privada se detiene. En el primer arranque la contraseña maestra se pide dos veces (`main.main`).
- **Permisos.** El fichero de la clave privada se crea directamente con permisos **600**. En Windows este modo apenas tiene efecto; la protección real se obtiene en Linux o Docker.
- **Logs incorrectos.** Decían "generada con os.urandom" (la genera el CSPRNG de OpenSSL) y "cifrada con AES" sin más detalle. Corregidos.

*¿Por qué 600.000 iteraciones?* Es la recomendación actual de OWASP para PBKDF2-HMAC-SHA256; NIST solo fija mínimos (1.000–10.000). Cada iteración encarece cada intento de fuerza bruta offline, y al usuario legítimo solo le cuesta ~0,1 s.

**Pruebas:** formato y parámetros del fichero cifrado; reconstrucción de la pública; permisos 600; contraseña maestra incorrecta; fichero de clave manipulado; clave pública sustituida; no se sobrescribe el par; contraseña maestra débil; confirmación que no coincide.

---

## Paso 3 — AAD en el cifrado y firma dentro del cifrado

- **Metadatos sin proteger.** Cada registro guarda en claro `id_poliza` y `titular_dni`, pero GCM cifraba sin datos asociados, así que se podían cambiar sin que el cifrado lo notara.
  → Se pasan como **AAD** (`id_poliza|titular_dni`). El AAD no se cifra, pero entra en el tag: si alguien cambia esos campos, el descifrado falla (`crypto_utils.cifrar_poliza` / `descifrar_poliza`, `main._aad_registro`).
- **Firma en claro.** La firma ECDSA se guardaba fuera del cifrado. Como los datos de una póliza son predecibles, un atacante podía probar combinaciones y confirmar la correcta verificándola contra la firma (un "oráculo").
  → **Firmar y después cifrar:** se cifra `{datos, firma}` y el registro ya no contiene la firma (`main.contratar_poliza` / `consultar_polizas`).

*¿Por qué hacen falta GCM y firma?* El **tag GCM** detiene a quien no conoce la contraseña del cliente. La **firma** detiene al propio cliente: puede descifrar su póliza, subirse el capital y volver a cifrarla con un tag válido, pero no puede volver a firmarla. Eso da **no repudio**.

**Pruebas:** la firma ya no está en claro; AAD distinto; cambio de `id_poliza`; póliza trasladada a otro cliente; cliente que modifica su póliza y la vuelve a cifrar (la firma la rechaza).

---

## Paso 4 — HMAC de los ficheros y ataques de repetición

- **Ficheros sin integridad.** Cualquiera con acceso a `users.json` podía sustituir la sal y el hash de una víctima por los suyos, entrar como ella y **contratar pólizas a su nombre que la aseguradora firmaba**. También se podían borrar o duplicar pólizas sin que se notara.
  → Nuevo módulo **`secure_storage.py`**. Cada fichero se guarda como `{datos, hmac}` con **HMAC-SHA256** (clave de 256 bits). Al cargar se verifica, en tiempo constante, antes de usar nada. El HMAC incluye el nombre del fichero para que no se pueda poner uno en el lugar del otro. Si falla, la aplicación **se detiene** (`IntegridadError`, que a propósito no es un `ValueError` para que no se capture como un error normal).
- **Clave HMAC.** No se guarda: se **deriva de la contraseña maestra** con PBKDF2 (600.000 iteraciones) y una sal propia, `keys/integrity.salt` (`key_manager.cargar_o_generar_clave_integridad`).
- **Repetición.** Duplicar un registro rompe el HMAC. Además, al consultar se rechaza cualquier `id_poliza` repetido (defensa en profundidad).

| Capa | Detiene a… |
|---|---|
| HMAC del fichero | quien no tiene la contraseña maestra (borrar, duplicar o modificar registros) |
| Tag GCM + AAD | quien no tiene la contraseña del cliente (mover pólizas, cambiar IDs) |
| Firma ECDSA | quien sí tiene la contraseña del cliente (inventar o alterar su póliza) |

**Pruebas:** suplantación en `users.json`; registro duplicado (repetición); registro borrado; copia repetida rechazada aunque el HMAC sea válido; intercambio de ficheros; fichero sin HMAC; la aplicación se detiene. Los tests de las capas GCM y firma guardan con un HMAC válido para probar cada capa por separado.

---

## Paso 5 — Autenticación de usuarios

- **Enumeración de usuarios.** El login decía "usuario no existe" o "contraseña incorrecta", y además un DNI inexistente respondía al instante, sin calcular PBKDF2. Así se podía averiguar quién es cliente.
  → Un **único mensaje** de fallo y un **PBKDF2 de relleno** cuando el DNI no existe (`auth.autenticar_usuario`). Medido en Docker: antes 123 ms frente a **0,1 ms**; ahora 126 ms frente a 123 ms.
- **Contraseñas débiles.** Solo se exigían 8 caracteres, y la comprobación estaba en la interfaz.
  → `auth.validar_politica_password`: **12–128 caracteres** (OWASP ASVS) y **sin el DNI**. No se exigen reglas de composición (mayúscula, símbolo…), que NIST y OWASP desaconsejan.
- **`.strip()` en las contraseñas.** Eliminaba los espacios del principio y del final, cambiando el secreto sin avisar.
  → Eliminado en las cuatro lecturas de contraseña (`main.py`).

**Pruebas:** mismo mensaje en los dos fallos; PBKDF2 ejecutado aunque el usuario no exista; contraseñas débiles (4 casos); DNI vacío; contraseñas con espacios (también en la aplicación real).

---

## Paso 6 — Calidad, dependencias y documentación

- **Rutas.** `data/` y `keys/` dependían de la carpeta desde la que se lanzaba la aplicación: desde `src/` se creaban carpetas nuevas y vacías. Ahora se calculan desde la ubicación del código.
- **Ctrl+C / fin de entrada.** Antes salía una traza de error; ahora un mensaje limpio.
- **PBKDF2 duplicado.** `auth.py` tenía su propia copia; ahora usa la de `crypto_utils`. El comentario "NIST/OWASP" se corrigió a "OWASP".
- **Log de cierre de sesión.** Decía "claves eliminadas de memoria", algo que Python no puede garantizar. Ahora dice solo "Sesión cerrada.".
- **Dependencias.** Se quitaron `bcrypt` (librería criptográfica que no se usaba) e `ipykernel`. Se comprobó reconstruyendo la imagen Docker desde cero.
- **README** reescrito: estructura, instalación desde un entorno limpio, uso, checklist y pruebas. `ruff` sin avisos.

**Pruebas:** la aplicación lanzada como proceso real sale limpia al cerrarse la entrada. Los 46 tests anteriores siguen pasando sin cambios. (La prueba de las rutas se añadió en el paso 8.)

---

## Paso 7 — Certificado X.509 de la aseguradora e ID de póliza de 64 bits

- **Clave pública sin identidad.** `public_key.pem` era una clave suelta: nada la vinculaba con "la aseguradora InsureCrypt". El enunciado pide, cuando haga falta vincular la clave pública con una identidad, usar "certificados y una PKI".
  → `keys/public_key.pem` se sustituye por **`keys/certificate.pem`**: un **certificado X.509 autofirmado** (`key_manager._generar_y_guardar_certificado`) con:
  - Sujeto y emisor `CN=InsureCrypt Aseguradora, O=InsureCrypt, C=ES`.
  - La misma clave ECDSA P-256, firmado con **ECDSA-SHA256**.
  - Validez de 5 años.
  - Uso de clave: **firma digital** y **no repudio** (`content_commitment`).
  - No es una autoridad de certificación (`CA:FALSE`).
- **Verificación al arrancar** (`key_manager._cargar_y_verificar_certificado`). Antes de usar la clave pública del certificado, se comprueba que:
  1. corresponde a la clave privada;
  2. su autofirma es válida (cambiar cualquier campo la invalida);
  3. el sujeto es el de la aseguradora;
  4. está dentro de su periodo de validez.

  Si algo falla, la aplicación no arranca. El log muestra el sujeto, la fecha de caducidad y la **huella SHA-256** del certificado.
- **Se mantienen las reglas del paso 2.** Si falta el certificado, se reemite con la misma clave privada; así también se renueva cuando caduca: basta con borrarlo. Si falta la clave privada pero existe el certificado, la aplicación se detiene.
- **ID de póliza.** Pasa de 8 caracteres de un UUID (**32 bits**) a `secrets.token_hex(8)` (**64 bits**, generado con el CSPRNG) (`main.contratar_poliza`). Desde el paso 4 se rechazan los IDs repetidos, así que una colisión haría que se rechazara una póliza legítima. Con 64 bits la probabilidad es despreciable.

*Límite del certificado autofirmado:* cualquiera puede crear uno, así que por sí solo no prueba nada. Sirve como **raíz de confianza** si quien verifica conoce su huella por otro canal ("fijar" el certificado). Por eso se muestra en el log. En un sistema real lo firmaría una autoridad de certificación (CA). Aun así, la aplicación detecta que se sustituya o se manipule, porque se compara con la clave privada y se verifica su firma.

**Pruebas:** campos del certificado (sujeto, firma ECDSA-SHA256, curva P-256, uso de clave, 5 años); reemisión si falta; ID de 64 bits. Negativas: certificado de otra clave (sustitución); certificado manipulado; caducado; emitido a otra identidad.

---

## Paso 8 — Correcciones tras una revisión independiente

Un revisor que no había participado en los cambios leyó todo el código y los tests, y ejecutó la aplicación. No encontró fallos críticos (ningún tag, firma o HMAC inválido deja continuar), pero sí estos problemas:

- **El capital aceptaba `nan`, `inf` y `1e400`.** `float()` los convierte sin error y `nan <= 0` es falso, así que pasaban la validación y la aseguradora **firmaba** una póliza con capital "nan €".
  → Se exige un número finito (`math.isfinite`), positivo y de 100 millones como máximo. El detalle se limita a 200 caracteres (`main.contratar_poliza`) y el DNI/ID a letras y números, 20 como máximo (`auth.registrar_usuario`).
- **Ficheros mal formados provocaban trazas de error**, sin necesidad de conocer ninguna clave:
  - Un `private_key.enc` con estructura o tipos inesperados (por ejemplo, una lista, o `"salt": 5`) daba `TypeError`; con un nonce corto mostraba un mensaje interno de la librería.
    → `key_manager._cargar_clave_privada` captura esos casos y comprueba los tamaños de la sal y del nonce: "fichero corrupto".
  - Un `users.json` con texto Unicode no válido hacía fallar el cálculo del HMAC fuera del bloque que lo controlaba. Lo más grave: durante el registro, ese error se trataba como un error corriente y **la aplicación seguía en marcha**.
    → `secure_storage.cargar_json` convierte cualquier fallo al preparar el HMAC en `IntegridadError`, y la aplicación se detiene.
  - Registros de póliza con campos ausentes o de tipos inesperados, o una firma que no es texto.
    → `main.consultar_polizas` rechaza ese registro ("Estructura corrupta") y sigue con los demás; `crypto_utils.verificar_firma_poliza` devuelve "firma inválida".
- **Tests que no probaban lo que decían, y protecciones sin test.** El test de "salida limpia" no detectaba que las rutas volvieran a depender de la carpeta actual. Varias protecciones podían quitarse sin que fallara ningún test.
  → 39 pruebas nuevas (de 52 a 91). Se rompieron a propósito 15 protecciones, una a una, y ahora cada una hace fallar al menos un test.

**Pruebas nuevas:**
- Entradas: capital no válido (9 casos, incluidos `nan`, `inf` y `1e400`); tipo de seguro inválido; detalle vacío o demasiado largo; DNI con formato no válido.
- Ficheros de claves: `private_key.enc` mal formado (4 casos); iteraciones rebajadas; certificado aún no válido; contraseña maestra incorrecta desde la aplicación.
- Integridad: campo `hmac` alterado; `integrity.salt` sustituida; fichero con Unicode no válido (la aplicación se detiene).
- Cifrado y firma: nonce alterado; texto cifrado truncado; firma verificada con otra clave pública; firma mal formada (5 casos); titular firmado distinto del registro; registros con estructura corrupta.
- Aislamiento: un cliente no ve, ni se intentan procesar, las pólizas de otro.
- Positivas: las sales de usuarios y pólizas varían; las rutas de datos apuntan a la raíz del proyecto aunque se lance desde otra carpeta.

**Hallazgos del revisor que no se han corregido** (ver "Limitaciones conocidas"): sin límite de intentos de inicio de sesión; todas las claves derivadas de una contraseña usan la misma función y solo las distingue la sal; solo la clave privada tiene permisos 600; la escritura de los ficheros no es atómica.

---

## Paso 9 — Recorte de las pruebas y revisión final

- **Demasiadas pruebas para explicarlas.** Tras el paso 8 había 91 ejecuciones en 68 funciones, muchas casi repetidas (por ejemplo, un test para el texto cifrado alterado, otro para el tag, otro para el nonce y otro para el truncado).
  → Se fusionaron las que prueban lo mismo en tests con varios casos (`pytest.mark.parametrize`) y se quitaron casos redundantes. Quedan **44 funciones y 69 ejecuciones** (12 positivas y 57 negativas). Se mantienen todas las pruebas negativas que pide el enunciado (texto cifrado, tag o MAC modificados, firma alterada, clave o contraseña incorrecta, repetición) y al menos un test por cada protección.
- **Comprobación.** Se volvieron a romper a propósito, una a una, 34 protecciones de todos los pasos. Cada una hace fallar al menos un test, salvo una que es equivalente: si se quita `math.isfinite` del capital, el límite máximo ya rechaza `nan` e `inf` (cualquier comparación con `nan` es falsa e `inf` supera el máximo). Se deja `isfinite` porque deja clara la intención.
- **Comentarios del código** reescritos en un estilo más informal, de apuntes propios.

---

## Cómo se ha verificado

- **Pruebas** en el contenedor Docker del proyecto (Python 3.11, cryptography 42.0.5) después de cada paso.
- **Las pruebas detectan de verdad.** Se desactivó a propósito cada protección (34 en total, de todos los pasos: verificación HMAC, rechazo de duplicados, PBKDF2 de relleno, política de contraseñas, `.strip()`, cada comprobación del certificado, el ID de 64 bits, la validación de entradas, etc.), y cada vez falló al menos un test (salvo la mutación equivalente de `isfinite`, ver paso 9).
- **Aplicación real.** En cada paso se ejecutó `main.py` con entradas simuladas, incluyendo manipulaciones hechas a mano en los ficheros y un Ctrl+C real.

## Limitaciones conocidas

- **Rollback:** restaurar una copia antigua completa de los ficheros, con su HMAC válido, no se detecta.
- **Borrado del fichero entero:** se trata como si estuviera vacío.
- **El registro** revela si un DNI ya existe ("ya registrado"); es inevitable sin un canal externo.
- **Lista de contraseñas filtradas:** no se comprueba (NIST lo recomienda).
- **Borrado de claves de la memoria:** Python no lo garantiza.
- **Certificado autofirmado:** no lo respalda ninguna autoridad de certificación; la confianza depende de conocer su huella.
- **Intentos de inicio de sesión:** no hay límite ni bloqueo; el único freno es el coste de PBKDF2 (~0,12 s por intento).
- **Derivación de claves sin separación de dominios:** el hash de login, la clave de cada póliza, la que cifra la clave privada y la clave HMAC salen de la misma función PBKDF2 y solo las distingue la sal. Caso límite: si un cliente usara la misma contraseña que la maestra, quien pudiera escribir en `keys/integrity.salt` podría hacer que la clave HMAC coincidiera con el hash de ese cliente, que está en `users.json`. Se evitaría derivando cada clave con una etiqueta propia (HKDF).
- **Permisos:** solo `private_key.enc` se crea con permisos 600; el resto de ficheros no contienen secretos en claro, pero son legibles por otros usuarios del sistema.
- **Escritura no atómica:** un corte a mitad de guardar un fichero lo dejaría corrupto, y la aplicación se detendría por HMAC inválido.
