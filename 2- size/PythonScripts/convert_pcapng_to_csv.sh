#!/bin/bash

# Directorio que contiene los archivos .pcapng (puedes cambiarlo o usar "." para el actual)
DIRECTORIO="./"

# Campos a extraer
CAMPOS=(
  -e frame.number
  -e frame.time_relative
  -e frame.len
  -e eth.src
  -e eth.dst
  -e ip.src
  -e ip.dst
  -e _ws.col.Protocol
  -e _ws.col.Info
)

# Recorre cada archivo .pcapng del directorio
for archivo in "$DIRECTORIO"/*.pcapng; do
  # Obtener el nombre base sin extensión
  nombre_base=$(basename "$archivo" .pcapng)
  salida_csv="${DIRECTORIO}/${nombre_base}.csv"

  echo "Convirtiendo: $archivo -> $salida_csv"

  # Ejecutar tshark para convertir a CSV
  tshark -n -r "$archivo" \
    -T fields \
    "${CAMPOS[@]}" \
    -E header=y \
    -E separator=, \
    -E quote=d \
    -E occurrence=f > "$salida_csv"
done

echo "Conversión completada."
