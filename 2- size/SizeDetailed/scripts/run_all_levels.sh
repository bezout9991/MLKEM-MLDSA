#!/usr/bin/env bash
# Iterate over pcaps and execute analyze_tls_bytes.sh or analyze_quic_bytes.sh

#!/usr/bin/env bash
# Usage: ./run_all_levels_any.sh <ROOT> [tls|quic]
# Example: ./run_all_levels_any.sh ../pcapKeysTLS tls
#          ./run_all_levels_any.sh ../pcapKeysQUIC quic
set -euo pipefail

ROOT="${1:-.}"
PROTOCOL="${2:-tls}"
proto="${PROTOCOL,,}"   # a minúsculas: tls/quic

# Valida protocolo
case "$proto" in
  tls|quic) ;;
  *) echo "❌ Unknown protocol: '$PROTOCOL' (use 'tls' or 'quic')" >&2; exit 2 ;;
esac

mkdir -p "$ROOT/csv"

shopt -s nullglob
for pcap in "$ROOT"/*.pcapng "$ROOT"/*.pcap; do
  base="$(basename "${pcap%.*}")"  # sin extensión

  # Regla de keylog por protocolo
  if [[ "$proto" = "tls" ]]; then
    keylog="$ROOT/sslkeys_server_${base}.log"
  else
    keylog="$ROOT/sslkeys_client_${base}.log"
  fi

  if [[ ! -f "$keylog" ]]; then
    echo "⚠️  Keylog file not found for $pcap -> $keylog (skipping)"
    continue
  fi

  echo "▶️  $pcap  (PROTOCOL=${proto^^}, KEYLOG=$keylog)"

  if [[ "$proto" = "tls" ]]; then
    ./analyze_tls_bytes.sh "$pcap" "$keylog" "$ROOT"
  else
    ./analyze_quic_bytes.sh "$pcap" "$keylog" "$ROOT"
  fi
done

