FROM python:3.11-slim

# Definimos la carpeta de trabajo dentro del contenedor
WORKDIR /app

# Copiamos el archivo de dependencias desde tu computadora al contenedor
COPY requirements.txt .

# Instalamos las librerías que pusiste en requirements.txt
RUN pip install --no-cache-dir -r requirements.txt