import re
import csv
import sys
import os
from collections import defaultdict

if len(sys.argv) != 4:
    print(f"Uso: {sys.argv[0]} <archivo_logs> <tag> <dir_output>")
    sys.exit(1)

log_file    = sys.argv[1]
tag         = sys.argv[2]
dir_output  = sys.argv[3]

os.makedirs(dir_output, exist_ok=True)

# Leer archivo completo
with open(log_file, 'r') as f:
    content = f.read()

# Expresiones regulares
pattern = re.compile(
    r"Running .*?with SIG_ALG=(\w+) and KEM_ALG=([-\w]+)\s+(.*?)(?=Running|\Z)",
    re.DOTALL
)
execution_pattern = re.compile(r"Execution (\d+) - (TLS|QUIC)", re.IGNORECASE)
handshake_pattern = re.compile(r"Handshake duration: ([\d.]+|NaN) ms", re.IGNORECASE)

# Estructuras de datos
resultados = defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: [""] * 500)))
orden_kems = defaultdict(lambda: defaultdict(list))

# Parsear el contenido
for match in pattern.finditer(content):
    sig_alg = match.group(1)
    kem_alg = match.group(2)
    block = match.group(3)

    current_protocolo = None
    current_exec = None

    for line in block.splitlines():
        exec_match = execution_pattern.search(line)
        if exec_match:
            current_exec = int(exec_match.group(1)) - 1  # index 0–499
            current_protocolo = exec_match.group(2).upper()
            continue

        hs_match = handshake_pattern.search(line)
        if hs_match and current_protocolo and current_exec is not None:
            valor = hs_match.group(1)
            duration = "" if valor.upper() == "NAN" else float(valor)
            resultados[current_protocolo][sig_alg][kem_alg][current_exec] = duration

            if kem_alg not in orden_kems[current_protocolo][sig_alg]:
                orden_kems[current_protocolo][sig_alg].append(kem_alg)

# Guardar los CSVs
for protocolo, firmas in resultados.items():
    for sig_alg, kem_dict in firmas.items():
        kems = orden_kems[protocolo][sig_alg]
        columnas = [kem_dict[kem] for kem in kems]
        filas = list(zip(*columnas))

        filename = os.path.join(dir_output, f"{sig_alg}_{protocolo.lower()}_{tag}.csv")

        print(f"\n📁 File generated: {filename}")
        with open(filename, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(kems)
            writer.writerows(filas)

        # Resumen por KEM
        for i, kem in enumerate(kems):
            col = columnas[i]
            vacios = sum(1 for x in col if x == "")
            validos = 500 - vacios
            print(f"  → {kem:20} ✓ {validos:3} valid   ✗ {vacios:3} empty")

print("\n✅ CSVs generated.")
