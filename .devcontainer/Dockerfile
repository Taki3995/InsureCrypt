FROM python:3.11-slim

# Evitar que Python escriba archivos .pyc y forzar salida estándar
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Crear un usuario sin privilegios para cumplir estándares de seguridad
RUN useradd -m -s /bin/bash vscode

# Definimos la carpeta de trabajo dentro del contenedor
WORKDIR /app

# Cambiamos el propietario de la carpeta al nuevo usuario
RUN chown vscode:vscode /app

# Copiamos el archivo de dependencias desde el host al contenedor
COPY requirements.txt .

# Instalamos las librerías y dependencias criptográficas con versiones exactas
RUN pip install --no-cache-dir -r requirements.txt

# Cambiamos al usuario sin privilegios para la ejecución
USER vscode