#!/usr/bin/env bash

# run_handshake_processing.sh
# Generic script to convert PCAPNG to CSV, process logs, perform handshake analysis, and merge results

set -euo pipefail

if [[ $# -lt 3 ]]; then
  echo "Usage: $0 <protocol> <delay_tag> <directory_pcap>"
  echo "  protocol    : tls or quic"
  echo "  delay_tag   : string tag for log files (e.g., Loss10)"
  echo "  directory   : working directory (e.g., ./QUIC/)"
  exit 1
fi

PROTOCOL="$1"
DELAY_TAG="$2"
WORKING_DIRECTORY="$3"


PCAP_DIRECTORY="${WORKING_DIRECTORY}/capturas/pcap"
CAPTURES_CSV_DIRECTORY="${WORKING_DIRECTORY}/capturas/csv"

LOG_DIRECTORY="${WORKING_DIRECTORY}/log"


PCAP2CSV_SCRIPT="convert_pcapng_to_csv.sh"
PROCESS_LOG_SCRIPT="processLogTimeHandshake.py"
HANDSHAKE_SCRIPT="handshake_process.py"
MERGE_SCRIPT="merge_handshake_metrics.py"
PLOT_SCRIPT="plotAllViolinScattersLog.py"


OUTPUT_DIR="${WORKING_DIRECTORY}/output"
TARGET_DIR="${WORKING_DIRECTORY}/csvs_${PROTOCOL}_${DELAY_TAG}"
MERGED_DIR="${OUTPUT_DIR}/merged"

# Ensure required scripts exist
for script in "${PCAP2CSV_SCRIPT}" "${PROCESS_LOG_SCRIPT}" "${HANDSHAKE_SCRIPT}" "${MERGE_SCRIPT}" "${PLOT_SCRIPT}"; do
    if [[ ! -x "${script}" && ! -f "${script}" ]]; then
        echo "Error: script '${script}' not found or not executable."
        exit 1
    fi
done

mkdir -p "${TARGET_DIR}"
mkdir -p "${CAPTURES_CSV_DIRECTORY}"
mkdir -p "${OUTPUT_DIR}"
mkdir -p "${MERGED_DIR}"

# Step 1: Convert all .pcapng files to CSV
echo "[*] Converting PCAPNG to CSV using ${PCAP2CSV_SCRIPT}..."
./"${PCAP2CSV_SCRIPT}" "${PCAP_DIRECTORY}"
cp ${PCAP_DIRECTORY}/*.csv "${CAPTURES_CSV_DIRECTORY}/" 2>/dev/null || true
mv ${PCAP_DIRECTORY}/*.csv "${TARGET_DIR}/" 2>/dev/null || true

# Step 2: Process logs if provided
LOG_FILE="${LOG_DIRECTORY}/${PROTOCOL}_${DELAY_TAG}.log"
if [[ -f "${LOG_FILE}" ]]; then
  echo "[*] Processing log file ${LOG_FILE}..."
  python3 "${PROCESS_LOG_SCRIPT}" "${LOG_FILE}" "${DELAY_TAG}" "${OUTPUT_DIR}"
else
  echo "[!] Log file ${LOG_FILE} not found, skipping log processing."
fi


# Step 3: Run handshake analysis
echo "[*] Executing handshake script"
python3 "${HANDSHAKE_SCRIPT}" ${TARGET_DIR}  ${OUTPUT_DIR} ${PROTOCOL}

# Step 4: Merge metrics per signature algorithm
echo "[*] Merging handshake metrics for each KEM algorithm"
for sig in ed25519 secp384r1 secp521r1; do
    BASE="${OUTPUT_DIR}/${sig}_${PROTOCOL}_handshakes.csv"
    LOG_CSV="${OUTPUT_DIR}/${sig}_${PROTOCOL}_${DELAY_TAG}.csv"
    MERGED="${MERGED_DIR}/${sig}_${PROTOCOL}_${DELAY_TAG}_merged.csv"
    if [[ -f "${BASE}" && -f "${LOG_CSV}" ]]; then
        echo "    Merging ${BASE} + ${LOG_CSV} → ${MERGED}"
        python3 "${MERGE_SCRIPT}" "${BASE}" "${LOG_CSV}" "${MERGED}"
    else
        echo "[!] Missing ${BASE} or ${LOG_CSV}, skipping ${sig}."
    fi
done

# Step 4: Plot 
python3 "${PLOT_SCRIPT}" "${OUTPUT_DIR}"
echo "[+] All plots completed. Plots are in ${OUTPUT_DIR}/"

# Step 5: Finalize outputs
rm -r "${TARGET_DIR}"
echo "[+] All steps completed. "


