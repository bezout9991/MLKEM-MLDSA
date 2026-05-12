#!/usr/bin/env bash
# Usage: ./analyze_quic_bytes.sh <capture.pcapng> <keylog_file> [ROOT=.]
# Output CSV columns:
#   kem,keyshare,certificate,signature,total_quic
set -euo pipefail

PCAP="${1:-}"
KEYS="${2:-}"
ROOT="${3:-.}"

if [[ -z "${PCAP}" || -z "${KEYS}" ]]; then
  echo "Usage: $0 <capture.pcapng> <keylog_file> [ROOT]" >&2
  exit 1
fi

# ---------- Detect KEM from filename (supports hybrids) ----------
FILENAME=$(basename "$PCAP")
BASE="${FILENAME%.*}"

IFS='_' read -r -a PARTS <<< "$BASE"
STOP_RE='^(tls|quic|x86|arm.*|mutual.*|server|client)$'

KEM_TOKENS=()
for (( i=1; i<${#PARTS[@]}; i++ )); do
  tok="${PARTS[$i]}"
  if [[ "$tok" =~ $STOP_RE ]]; then
    break
  fi
  KEM_TOKENS+=("$tok")
done

KEM_RAW="$(IFS=_; echo "${KEM_TOKENS[*]}")"
KEM=$(echo "$KEM_RAW" \
        | tr '[:upper:]' '[:lower:]' \
        | sed -E 's/p-?256/p256/g; s/p-?384/p384/g; s/p-?521/p521/g')
KEM="${KEM:-unknown}"

# ---------- Output CSV path ----------
OUTDIR="$ROOT/csv"
mkdir -p "$OUTDIR"
OUTPUT_CSV="$OUTDIR/handshake_${KEM}.csv"

echo "📛 KEM: $KEM"
echo "💾 Output: $OUTPUT_CSV"
echo "🔍 Analyzing QUIC in $PCAP (keys: $KEYS)"
echo "---------------------------------------------------------------"

# QUIC handshake bytes on the wire:
# We count packets carrying QUIC CRYPTO frames (frame_type == 0x06).
# Requires decryption via tls.keylog_file so Wireshark/tshark can parse TLS-in-QUIC.
QUIC_CRYPTO_FILTER='quic && quic.frame_type == 0x06'

# Sum of frame lengths for selected QUIC packets (bytes on wire at L2 capture)
TOTAL_QUIC_BYTES=$(
  tshark -r "$PCAP" -o "tls.keylog_file:$KEYS" \
    -Y "$QUIC_CRYPTO_FILTER" \
    -T fields -e frame.len 2>/dev/null \
  | awk '{s+=$1} END{print s+0}'
)

# ---- TLS handshake elements extracted from decrypted QUIC (same fields as TLS1.3) ----
first_int() {
  local filter="${1-}"
  local field="${2-}"
  if [[ -z "${filter}" || -z "${field}" ]]; then echo 0; return 0; fi
  tshark -r "$PCAP" -o "tls.keylog_file:$KEYS" \
    -Y "$filter" -T fields -Eseparator=/ -e "$field" 2>/dev/null \
  | tr '/,;\t ' '\n' \
  | awk '/^[0-9]+$/{print; exit} END{if(NR==0) print 0}'
}

# ClientHello → KeyShare length
CLIENT_KEYSHARE=$(first_int \
  'tls.handshake.type==1 && tls.handshake.extensions_key_share_key_exchange_length' \
  'tls.handshake.extensions_key_share_key_exchange_length')

# Certificate (prefer TLS 1.3 list length; fallback handled by awk)
CERT_LENGTH=$(
  tshark -r "$PCAP" -o "tls.keylog_file:$KEYS" \
    -Y "tls.handshake.type==11" \
    -T fields -e tls.handshake.certificate_length 2>/dev/null \
  | tr '\t,; ' '\n' | awk '/^[0-9]+$/{print; exit} END{if(NR==0) print 0}'
)

# CertificateVerify → signature length
SIG_LENGTH=$(
  tshark -r "$PCAP" -o "tls.keylog_file:$KEYS" \
    -Y "tls.handshake.type==15" -V 2>/dev/null \
  | grep -i "Signature length" | awk '{print $3; exit}' | tr -d '\r'
)
SIG_LENGTH=${SIG_LENGTH:-0}

# === NUEVO: último 1-RTT (short header / KP0) ===
F_1RTT='quic && quic.header_form == 0'
LAST_1RTT_BYTES=$(
  tshark -r "$PCAP" -o "tls.keylog_file:$KEYS" -Y "$F_1RTT" \
    -T fields -e frame.number -e frame.len 2>/dev/null \
  | awk 'NF==2 { last_len=$2 } END { print last_len+0 }'
)

# total_quic = CRYPTO + último 1-RTT
TOTAL_QUIC_INCL_1RTT=$(( ${TOTAL_QUIC_BYTES:-0} + ${LAST_1RTT_BYTES:-0} ))


echo "🔐 QUIC/TLS details"
printf "   • KeyShare (client) : %d bytes\n" "${CLIENT_KEYSHARE:-0}"
printf "   • Certificate       : %d bytes\n" "${CERT_LENGTH:-0}"
printf "   • Signature         : %d bytes\n" "${SIG_LENGTH:-0}"
echo "---------------------------------------------------------------"
printf "🧩 Last 1-RTT (KP0)     : %d bytes\n" "${LAST_1RTT_BYTES:-0}"
printf "🧲 total_quic (CRYPTO+1RTT): %d bytes\n" "${TOTAL_QUIC_INCL_1RTT:-0}"


# ---------- CSV ----------


# ---- CSV: ahora con columna 1RTT, y total_quic incluye 1RTT ----
if [[ ! -s "$OUTPUT_CSV" ]]; then
  echo "kem,keyshare,certificate,signature,1RTT,total_quic" > "$OUTPUT_CSV"
fi

printf '%s,%d,%d,%d,%d,%d\n' \
  "$KEM" "${CLIENT_KEYSHARE:-0}" "${CERT_LENGTH:-0}" "${SIG_LENGTH:-0}" \
  "${LAST_1RTT_BYTES:-0}" "${TOTAL_QUIC_INCL_1RTT:-0}" >> "$OUTPUT_CSV"

echo "💾 Row appended to: $OUTPUT_CSV"
