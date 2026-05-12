#!/usr/bin/env python3
import csv
import os
import re
import sys
from collections import defaultdict
import re

# --- Argumentos ---------------------------------------------------------------------
if len(sys.argv) != 4:
    print(f"Uso: {sys.argv[0]} <directorio_entrada> <directorio_salida> <protocolo>")
    print(f"Ejemplo: {sys.argv[0]} ./csvs ./output quic")
    sys.exit(1)

directorio_entrada = sys.argv[1]
directorio_salida = sys.argv[2]
protocolo_objetivo = sys.argv[3].lower()

if protocolo_objetivo not in ("quic", "tls"):
    print("❌ El protocolo debe ser 'quic' o 'tls'")
    sys.exit(1)

if not os.path.isdir(directorio_entrada):
    print(f"❌ El directorio de entrada '{directorio_entrada}' no existe.")
    sys.exit(1)

os.makedirs(directorio_salida, exist_ok=True)

# --- RegExp para nombres de archivo --------------------------------------------------
patron_nombre = re.compile(r"SIG_ALG=(.+?) and KEM_ALG=(.+?)\.csv")

# --- Detección para QUIC -------------------------------------------------------------
def es_initial_quic(info: str) -> bool:
    return 'Initial' in info

def es_end_quic(info: str) -> bool:
    return 'Protected Payload' in info and 'DCID=' not in info

# --- Detección para TLS --------------------------------------------------------------
def es_client_hello(info: str) -> bool:
    return 'Client Hello' in info

def es_server_finished(info: str) -> bool:
    return (
        'Encrypted Handshake Message' in info
        or 'Finished' in info
        or 'Change Cipher Spec' in info
    )

# --- Orden de KEM ---------------------------------------------------------------------
def orden_kem(kem: str):
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
        return (4, kem)

# --- Estructura de datos --------------------------------------------------------------
agrupado_por_firma = defaultdict(list)

# --- Procesamiento --------------------------------------------------------------------
for nombre_csv in os.listdir(directorio_entrada):
    if not nombre_csv.endswith('.csv'):
        continue

    m = patron_nombre.match(nombre_csv)
    if not m:
        print(f"⚠️ Nombre no coincide con patrón esperado: {nombre_csv}")
        continue

    sig_alg, kem_alg = m.groups()
    ruta_csv = os.path.join(directorio_entrada, nombre_csv)

    with open(ruta_csv, newline='', encoding='utf-8') as f:
        lector = csv.DictReader(f)

        dentro = False
        handshake_id = 0
        bytes_total = 0
        completos = 0
        incompletos = 0

        for fila in lector:
            info  = fila.get('_ws.col.Info', '') or fila.get('_ws.col.info', '')
            proto = fila.get('_ws.col.Protocol', '') or fila.get('_ws.col.protocol', '')
            try:
                length = int(fila.get('frame.len', 0))
            except ValueError:
                continue

            VENTANA_REINTENTOS = 0.5  # en segundos
            ultimo_initial_ts = None



            # --- Inicialización para QUIC ---
            pat_dcid = re.compile(r"DCID=([a-fA-F0-9]+)")
            dcids_vistos = set()
            VENTANA_REINTENTOS = 2.0  # segundos
            ultimo_initial_ts = None

            if protocolo_objetivo == "quic":
                try:
                    ts_actual = float(fila.get("frame.time_relative", 0))
                except ValueError:
                    ts_actual = 0

                if proto.lower() == 'quic' and es_initial_quic(info):
                    match = pat_dcid.search(info)
                    dcid = match.group(1) if match else None

                    if dcid is None:
                        continue

                    if dcid in dcids_vistos:
                        continue  # 🚫 duplicado exacto
                    if ultimo_initial_ts is not None and ts_actual - ultimo_initial_ts < VENTANA_REINTENTOS:
                        continue  # 🚫 probablemente reintento con nuevo DCID

                    dcids_vistos.add(dcid)

                    if dentro:
                        agrupado_por_firma[sig_alg].append([kem_alg, handshake_id, -1])
                        incompletos += 1

                    dentro = True
                    handshake_id += 1
                    bytes_total = length
                    ultimo_initial_ts = ts_actual
                    continue

                if dentro and proto.lower() == 'quic':
                    bytes_total += length
                    if es_end_quic(info):
                        agrupado_por_firma[sig_alg].append([kem_alg, handshake_id, bytes_total])
                        completos += 1
                        dentro = False
                        ultimo_initial_ts = None


            elif protocolo_objetivo == "tls":
                if not dentro and proto.lower().startswith('tlsv1.') and es_client_hello(info):
                    dentro = True
                    handshake_id += 1
                    bytes_total = length
                    continue

                if dentro and proto.lower().startswith('tlsv1.'):
                    bytes_total += length
                    if es_server_finished(info):
                        agrupado_por_firma[sig_alg].append([kem_alg, handshake_id, bytes_total])
                        completos += 1
                        dentro = False

        # Si el último quedó abierto (incompleto), también lo guardamos
        if dentro:
            agrupado_por_firma[sig_alg].append([kem_alg, handshake_id, -1])
            incompletos += 1

        print(f"📊 {nombre_csv} → {completos} completos, {incompletos} incompletos")

# --- Escritura de archivos de salida --------------------------------------------------
for sig_alg, filas in agrupado_por_firma.items():
    filas_ordenadas = sorted(filas, key=lambda x: (orden_kem(x[0]), x[1]))
    salida = os.path.join(directorio_salida, f"{sig_alg}_{protocolo_objetivo}_handshakes.csv")
    with open(salida, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['KEM_ALG', 'Handshake_ID', 'Bytes_Total'])
        w.writerows(filas_ordenadas)
    print(f"✅ Archivo generado: {salida}")
