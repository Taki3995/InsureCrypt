**Docker
- Instalar Docker Desktop (windows o macos) o Docker engine (Linux)
- Instalar extension Dev containers en vscode
- Para Docker Desktop abrir app y cuando el servicio este activo apretar f1 en vscode y poner "Dev Containers: Reopen in Container"

# Checklist
**1. registro y autenticacion de usuarios** !!!
- en archivo auth.py, usa autenticacion basada en contraseñas robustas (algo que sabemos) almacenadas con PBKDF2HMAC-SHA256 (600.000 iteraciones), salt unico de 16 bytes creado con os.urandom y comparacion en tiempo constante hmac.compare_digest.
- actualmente usando lo minimo pedido (aunque las 600mil iteraciones le dan un plus), podemos mejorarlo:
    - Basado en algo que tenemos: token, pudiendo ser un mensaje al móvil, un tipo de
tarjeta, etc. Hay múltiples alternativas.
    - Basado en algo que somos: rasgo biométrico, desde la huella dactilar, hasta la imagen
facial o el iris, entre otros.

**2. Cifrado/descifrado simétrico y/o asimétrico (o con cifrado autenticado)** !!!
- en crypto_utils.py, usando AES-256-GCM. Genera un nonce de 96 bits por cada poliza sin reutilizar, y muetra logs de depuracion con algoritmo, tamaño de clave y nonce, sin exponer nada secreto.
- podriamos tener un HMAC-SHA256 sobre policies.json para mejorar.

**3. Generación/verificación de etiquetas de autenticación de mensajes (e.g., mediante HMAC con una función hash segura) (o con cifrado autenticado)**
- cubierto usando el modo autenticado de AES-GCM, que verifica el tag de 128 bits antes de devolver cualquier dato, y rechaza el paquete si detect alteraciones
- LISTO

**4. Generación/verificación de firma digital** !!!
- Se implementa la firma con ECDSA sobre la curva eliptica estndar SECP256R1 (NIST P-256) con SHA-256. al consultar cualquier poliiza el sistema la verifica automaticamente par ver si ha sido alterada, y si si, se rechaza y bloquea el acceso a dicha poliza.
- es lo minimo pedido, se puede mejorar

**5. Generación y almacenamiento de claves** !!!
- Clave simetrica AES-256 que se deriva directamente a la memoria con PBKDF2HMAC-SHA256 a partir de la contraseña del cliente y salt unico de cada poliaz, descartandose al cerrar la sesion. Simetrica para proteger datos, ya que por si sola no garantiza no repudio, solo integridad y confidencialidad.
- clave asimetrica ECDSA se genera con os.urandom y se gurada cifrada con AES. solicita la contraseña maestra por consola, y la clave publica se exporta a keys/public_key.pem para verificar. asimetrica para firmas
- Minimo pediddo, se puede mejorar


**otros**
- todos los salts y nonces usan os.urandom
- fallos de tag o firma detienen el flujo de ejecucion 


# **Tests**
## Tests Positivos
**Pedidos en el enunciado**
- test_generacion_y_carga_claves_ecdsa: Comprueba que el sistema genera el par de claves asimétricas ECDSA (SECP256R1), cifra la clave privada en disco (-----BEGIN ENCRYPTED PRIVATE KEY-----) y la recupera correctamente con la contraseña maestra.  

- test_registro_y_autenticacion_exitosa: Verifica que un cliente se registra almacenando salt aleatoria de 16 bytes y hash derivado (nunca la contraseña en claro) y que inicia sesión con éxito.   

- test_cifrado_y_descifrado_autenticado_aes_gcm: Comprueba que una póliza cifrada con AES-256-GCM oculta los datos originales y se descifra recuperando el diccionario exacto.   

- test_no_reutilizacion_nonces_aes_gcm: Cifra dos veces la misma póliza con la misma clave y verifica que ambos nonces tienen 96 bits (12 bytes) y son distintos entre sí, asegurando que nunca se reutiliza un nonce.   

- test_firma_y_verificacion_digital_ecdsa: Verifica que la aseguradora firma la póliza con ECDSA-SHA256 y que verificar_firma_poliza valida la firma usando la clave pública.   

**Extras**
- test_serializacion_determinista_en_firma: Verifica que aunque las claves del diccionario de la póliza se construyan en distinto orden en memoria, sort_keys=True mantiene la firma válida sin falsos rechazos.

- test_flujo_completo_end_to_end_cli: Simula la ejecución completa en main.py (contratar_poliza seguido de consultar_polizas), verificando que la integración entre derivación de clave, firma, cifrado, persistencia JSON y verificación funciona de extremo a extremo.

## Tests Negativos
**Pedidos en el Enunciado**
- test_contrasena_maestra_incorrecta_pem: Intenta desprecintar private_key.pem con una contraseña maestra incorrecta y verifica que lanza ValueError sin exponer claves.

- test_autenticacion_contrasena_incorrecta: Intenta iniciar sesión con una contraseña incorrecta y comprueba que devuelve False.

- test_modificacion_ciphertext_aes_gcm: Altera 1 byte del bloque cifrado (ciphertext) y comprueba que descifrar_poliza lanza ValueError (capturando InvalidTag) rechazando los datos.   

- test_modificacion_tag_autenticacion_aes_gcm: Altera 1 byte dentro de los últimos 16 bytes del paquete (la etiqueta de autenticación GCM) y verifica que el descifrado falla explícitamente con ValueError.   

- test_descifrado_con_clave_o_contrasena_incorrecta: Intenta descifrar una póliza derivando la clave a partir de una contraseña equivocada y verifica que lanza ValueError.   

- test_firma_digital_alterada: Modifica 1 byte de la firma digital ECDSA y verifica que verificar_firma_poliza devuelve False (capturando InvalidSignature).   

- test_datos_poliza_modificados_post_firma: Altera el importe de la póliza después de haber sido firmada y verifica que la firma ECDSA rechaza el documento (False).   


**Extras**
- test_registro_usuario_duplicado: Comprueba que intentar registrar un DNI ya existente lanza ValueError impidiendo sobrescribir credenciales.

- test_autenticacion_usuario_inexistente: Comprueba que intentar autenticar un DNI no registrado devuelve False.

- test_ataque_sustitucion_paquete_entre_clientes: Simula que un atacante copia el bloque cifrado y firmado de un cliente hacia el registro de otro cliente en policies.json, comprobando que consultar_polizas detecta el fraude y bloquea la visualización.


## EJECUTAR PRUEBAS
ejecutar el siguiente comando en terminal:

```bash
pytest -v
```

hace que pytest imprima el nombre individual de cada una de las 17 funciones de prueba junto con su estado (PASSED o FAILED)
