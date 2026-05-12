#!/usr/bin/env bash
# Usage: ./analyze_tls_bytes.sh <capture.pcapng> <keylog_file>
set -euo pipefail

PCAP="${1:-}"
KEYS="${2:-}"
ROOT="${3:-.}"

if [[ -z "$PCAP" || -z "$KEYS" ]]; then
  echo "Usage: $0 <capture.pcapng> <keylog_file>"
  exit 1
fi

# ---------- Automatic KEM detection (supports hybrid ones) ----------
FILENAME=$(basename "$PCAP")
BASE="${FILENAME%.*}"   # remove .pcap/.pcapng extension

# parts separated by "_"
IFS='_' read -r -a PARTS <<< "$BASE"

# skip first token (signature: ed25519 | secp384r1 | secp521r1)
# and build the KEM until we find a “stop token”
STOP_RE='^(tls|quic|x86|arm.*|mutual.*|server|client)$'

KEM_TOKENS=()
for (( i=1; i<${#PARTS[@]}; i++ )); do
  tok="${PARTS[$i]}"
  if [[ "$tok" =~ $STOP_RE ]]; then
    break
  fi
  KEM_TOKENS+=("$tok")
done

# join with "_" and normalize: lowercase and P-256/384/521 -> p256/p384/p521
KEM_RAW="$(IFS=_; echo "${KEM_TOKENS[*]}")"
KEM=$(echo "$KEM_RAW" \
        | tr '[:upper:]' '[:lower:]' \
        | sed -E 's/p-?256/p256/g; s/p-?384/p384/g; s/p-?521/p521/g')

# fallback
KEM="${KEM:-unknown}"
echo "📛 Detected KEM: $KEM"

# ---------- Build CSV name automatically ----------
if [[ -n "$KEM" ]]; then
  OUTPUT_CSV="$ROOT/csv/handshake_${KEM}.csv"
else
  OUTPUT_CSV="$ROOT/csv/${OUTPUT_CSV:-handshake_summary.csv}"
fi

echo "💾 Output file: $OUTPUT_CSV"

echo "🔍 Analyzing $PCAP with keys $KEYS"
echo "---------------------------------------------------------------"

TLS_FILTER='(tls && (tls.record.content_type == 22 || tls.record.content_type == 20)) && tcp.len > 0 && tcp.flags.reset == 0'

# ---------- TLS: payload + number of records ----------
read -r TLS_PAYLOAD_BYTES TLS_RECORDS_COUNT <<<"$(
  tshark -r "$PCAP" -o "tls.keylog_file:$KEYS" \
    -Y "$TLS_FILTER" \
    -T fields -E separator=, -e tls.record.length 2>/dev/null \
  | awk -F',' '
      { for(i=1;i<=NF;i++){ if($i ~ /^[0-9]+$/){ pay+=$i; rec++ } } }
      END{ printf "%d %d", pay+0, rec+0 }
    '
)"
TLS_WITH_HEADERS=$(( TLS_PAYLOAD_BYTES + 5*TLS_RECORDS_COUNT ))

WIRE_TLS_BYTES=$(
  tshark -r "$PCAP" -o "tls.keylog_file:$KEYS" \
    -Y "$TLS_FILTER" \
    -T fields -e frame.len 2>/dev/null | awk '{s+=$1} END{print s+0}'
)
WIRE_TLS_PKTS=$(
  tshark -r "$PCAP" -o "tls.keylog_file:$KEYS" \
    -Y "$TLS_FILTER" -T fields -e frame.number 2>/dev/null | wc -l | awk '{print $1}'
)

# ---------- TCP control: SYN, ACK-only, RST ----------
SYN_FILTER='tcp.flags.syn == 1 && tcp.len == 0'
ACKONLY_FILTER='tcp.flags.ack == 1 && tcp.len == 0 && tcp.flags.syn == 0 && tcp.flags.fin == 0 && tcp.flags.reset == 0 && tcp.flags.push == 0'
RST_FILTER='tcp.flags.reset == 1'

sum_bytes () {
  local filter="$1"
  tshark -r "$PCAP" -o "tls.keylog_file:$KEYS" -Y "$filter" -T fields -e frame.len 2>/dev/null \
  | awk '{s+=$1} END{print s+0}'
}
count_pkts () {
  local filter="$1"
  tshark -r "$PCAP" -o "tls.keylog_file:$KEYS" -Y "$filter" -T fields -e frame.number 2>/dev/null \
  | wc -l | awk '{print $1}'
}

WIRE_SYN_BYTES=$(sum_bytes "$SYN_FILTER")
WIRE_SYN_PKTS=$(count_pkts "$SYN_FILTER")

WIRE_ACK_BYTES=$(sum_bytes "$ACKONLY_FILTER")
WIRE_ACK_PKTS=$(count_pkts "$ACKONLY_FILTER")

WIRE_RST_BYTES=$(sum_bytes "$RST_FILTER")
WIRE_RST_PKTS=$(count_pkts "$RST_FILTER")

# ---------- Combined totals ----------
WIRE_TCP_BYTES=$((  WIRE_SYN_BYTES + WIRE_ACK_BYTES + WIRE_RST_BYTES ))
TCP_PKTS=$((  WIRE_SYN_PKTS + WIRE_ACK_PKTS + WIRE_RST_PKTS ))

TOTAL_WIRE_BYTES=$(( WIRE_TLS_BYTES + WIRE_TCP_BYTES ))
TOTAL_PKTS=$(( WIRE_TLS_PKTS + TCP_PKTS ))

# ---------- Output ----------
printf "📦 TLS records              : %d\n" "$TLS_RECORDS_COUNT"
printf "🧩 tls.record.length (sum)  : %d bytes\n" "$TLS_PAYLOAD_BYTES"
printf "🧩 + headers (5B/record)    : %d bytes\n" "$TLS_WITH_HEADERS"
printf "🧲 TLS on the wire          : %d bytes (%d pkts)\n" "$WIRE_TLS_BYTES" "$WIRE_TLS_PKTS"
echo "---------------------------------------------------------------"
printf "🔹 TCP SYN (len=0)          : %d bytes (%d pkts)\n" "$WIRE_SYN_BYTES" "$WIRE_SYN_PKTS"
printf "🔹 TCP ACK-only (len=0)     : %d bytes (%d pkts)\n" "$WIRE_ACK_BYTES" "$WIRE_ACK_PKTS"
printf "🔹 TCP RST                  : %d bytes (%d pkts)\n" "$WIRE_RST_BYTES" "$WIRE_RST_PKTS"
printf "🧲 TCP on the wire          : %d bytes (%d pkts)\n" "$WIRE_TCP_BYTES" "$TCP_PKTS"
echo "---------------------------------------------------------------"
printf "🔢 TOTAL selected           : %d bytes (%d pkts)\n" "$TOTAL_WIRE_BYTES" "$TOTAL_PKTS"

echo "---------------------------------------------------------------"
echo "🔎 TLS Handshake frames (number, t_rel, frame.len):"
tshark -r "$PCAP" -o "tls.keylog_file:$KEYS" \
  -Y "$TLS_FILTER" \
  -T fields -e frame.number -e frame.time_relative -e frame.len \
  | awk '{printf "  • Frame %-6s t=%-10s len=%s\n", $1,$2,$3}'

# helper: extract first integer from a field, or 0 if none
first_int() {
  local filter="${1-}"
  local field="${2-}"
  if [[ -z "${filter}" || -z "${field}" ]]; then
    echo 0
    return 0
  fi
  tshark -r "$PCAP" -o "tls.keylog_file:$KEYS" \
    -Y "$filter" -T fields -Eseparator=/ -e "$field" 2>/dev/null \
  | tr '/,;\t ' '\n' \
  | awk '/^[0-9]+$/{print; exit} END{if(NR==0) print 0}'
}

# ClientHello → KeyShare (client pk)
CLIENT_KEYSHARE=$(first_int \
  'tls.handshake.type==1 && tls.handshake.extensions_key_share_key_exchange_length' \
  'tls.handshake.extensions_key_share_key_exchange_length')

# ServerHello → KeyShare (server ciphertext)
SERVER_KEYSHARE=$(first_int \
  'tls.handshake.type==2 && tls.handshake.extensions_key_share_key_exchange_length' \
  'tls.handshake.extensions_key_share_key_exchange_length')

# Certificate → prefer certificate_list_length (TLS1.3). Fallback to certificate_length.
CERT_LENGTH=$(
  tshark -r "$PCAP" -o "tls.keylog_file:$KEYS" \
    -Y "tls.handshake.type==11" \
    -T fields  -e tls.handshake.certificate_length 2>/dev/null \
  | tr '\t,; ' '\n' | awk '/^[0-9]+$/{print; exit} END{if(NR==0) print 0}'
)

# CertificateVerify → signature length
SIG_LENGTH=$(
  tshark -r "$PCAP" -o "tls.keylog_file:$KEYS" \
    -Y "tls.handshake.type==15" -V 2>/dev/null \
  | grep -i "Signature length" \
  | awk '{print $3; exit}' \
  | tr -d '\r'
)
SIG_LENGTH=${SIG_LENGTH:-0}

# Finished → verify_data length (optional)
FINISHED_LENGTH=$(first_int \
  "tls.handshake.type==20" \
  "tls.handshake.length")

# Useful crypto sum
CRYPTO_SUM=$(( ${CLIENT_KEYSHARE:-0}  + ${CERT_LENGTH:-0} + ${SIG_LENGTH:-0}  ))

echo "---------------------------------------------------------------"
printf "🔐 TLS 1.3 cryptographic details\n"
printf "   • KeyShare (pk or ct)     : %4d bytes\n" "${CLIENT_KEYSHARE:-0}"
printf "   • Certificate             : %4d bytes\n" "${CERT_LENGTH:-0}"
printf "   • Signature               : %4d bytes\n" "${SIG_LENGTH:-0}"
printf "   ➕ Useful crypto total     : %4d bytes\n" "${CRYPTO_SUM:-0}"
TLS_PAYLOAD=$(( ${WIRE_TLS_BYTES:-0} - ${CRYPTO_SUM:-0} ))
PCT_CRYPTO=$(awk -v c=${CRYPTO_SUM:-0} -v t=${WIRE_TLS_BYTES:-1} 'BEGIN{printf "%.2f", (c/t)*100}')
printf "  TOTAL TLS - Useful crypto total : %6d  -  %6d bytes\n" "${WIRE_TLS_BYTES:-0}" "${CRYPTO_SUM:-0}"
printf "  Non-crypto TLS payload           : %6d bytes\n" "${TLS_PAYLOAD:-0}"
printf "  %% Crypto inside TLS             : %6.2f %%\n" "${PCT_CRYPTO}"

# ---------- CSV: header (if not exists) and row ----------
if [[ ! -s "$OUTPUT_CSV" ]]; then
  echo "kem,total_tcp,keyshare,certificate,signature,total_tls" > "$OUTPUT_CSV"
fi

CKS=${CLIENT_KEYSHARE:-0}
CERT=${CERT_LENGTH:-0}
SIG=${SIG_LENGTH:-0}
TLSB=${WIRE_TLS_BYTES:-0}
TCPB=${WIRE_TCP_BYTES:-0}

printf '%s,%d,%d,%d,%d,%d\n' \
  "$KEM"  "$TCPB" "$CKS" "$CERT" "$SIG"  "$TLSB" >> "$OUTPUT_CSV"

echo "💾 Saved to CSV: $OUTPUT_CSV"