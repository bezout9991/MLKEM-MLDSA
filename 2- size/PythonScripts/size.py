import csv
import os
import re
from collections import defaultdict

# Ruta al directorio con los CSV de entrada
directorio_entrada = '.'  # <-- cámbialo por la ruta real si es necesario
# Ruta donde guardar los CSV de salida (puede ser el mismo)
directorio_salida = '.'   

os.makedirs(directorio_salida, exist_ok=True)

# Estructura: {sig_alg: [[KEM_ALG, Suma_TCP, Suma_TLS, Suma_Total], ...]}
agrupado_por_firma = defaultdict(list)

# Regex para extraer algoritmos del nombre del archivo
patron_nombre = re.compile(r"SIG_ALG=(.+?) and KEM_ALG=(.+?)\.csv")

# Función de orden personalizada para los KEMs
def orden_kem(kem):
    kem = kem.lower()

    if '_' in kem:
        return (2, kem)
    elif kem.startswith('p'):
        return (0, kem)
    elif kem.startswith('x'):
        return (1, kem)     
    elif 'mlkem' in kem:
        return (3, kem)
    else:
        return (4, kem)  # Cualquier otro al final

# Recorrer archivos del directorio
for nombre_archivo in os.listdir(directorio_entrada):
    if not nombre_archivo.endswith('.csv'):
        continue

    match = patron_nombre.match(nombre_archivo)
    if not match:
        continue

    sig_alg, kem_alg = match.groups()
    suma_quic = 0

    ruta_completa = os.path.join(directorio_entrada, nombre_archivo)

    with open(ruta_completa, mode='r', newline='', encoding='utf-8') as f:
        lector = csv.DictReader(f)
        for fila in lector:
            protocolo = fila["_ws.col.protocol"]
            try:
                longitud = int(fila["frame.len"])
            except ValueError:
                continue

            if protocolo == "QUIC":
                suma_quic += longitud

    
    agrupado_por_firma[sig_alg].append([kem_alg, suma_quic])

# Crear un archivo por cada algoritmo de firma
for sig_alg, filas in agrupado_por_firma.items():
    nombre_salida = os.path.join(directorio_salida, f"{sig_alg}.csv")
    
    # Ordenar los KEMs según la prioridad personalizada
    filas_ordenadas = sorted(filas, key=lambda x: orden_kem(x[0]))

    with open(nombre_salida, mode='w', newline='', encoding='utf-8') as f:
        escritor = csv.writer(f)
        escritor.writerow(['KEM_ALG', 'Suma_QUIC'])
        for fila in filas_ordenadas:
            escritor.writerow(fila)

    print(f"Archivo generado: {nombre_salida}")
