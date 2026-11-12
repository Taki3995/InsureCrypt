**Docker
- Instalar Docker Desktop (windows o macos) o Docker engine (Linux)
- Instalar extension Dev containers en vscode
- Para Docker Desktop abrir app y cuando el servicio este activo apretar f1 en vscode y poner "Dev Containers: Reopen in Container"

**Checklist
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