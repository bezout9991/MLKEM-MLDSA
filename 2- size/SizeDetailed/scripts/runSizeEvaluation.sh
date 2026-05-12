#!/usr/bin/env bash
# Usage: ./runSizeEvaluation.sh <directory>
# Example: ./run_TLS.sh ../pcapKeysTLS
set -euo pipefail

ROOT="${1:-../pcapKeysTLS}"
CSV="$ROOT/csv"
PLOT_DIR="./output/plots"
CSV_DIR="./output/csv"

rm -rf "$PLOT_DIR"
mkdir -p "$PLOT_DIR"

rm -rf "$CSV_DIR"
mkdir -p "$CSV_DIR"

# Delele CSV folder 
rm -rf "$CSV"

# Run analysis and merge levels
./run_all_levels.sh "$ROOT" tls
./merge_levels.sh "$CSV"

cp "$CSV/handshake_L1_merged.csv" "$CSV_DIR/handshake_L1_merged_TLS.csv"
cp "$CSV/handshake_L3_merged.csv" "$CSV_DIR/handshake_L3_merged_TLS.csv"
cp "$CSV/handshake_L5_merged.csv" "$CSV_DIR/handshake_L5_merged_TLS.csv"

# Generate stacked plots for each level
python3 plot_one_stacked_tls.py "$CSV/handshake_L1_merged.csv"
python3 plot_one_stacked_tls.py "$CSV/handshake_L3_merged.csv"
python3 plot_one_stacked_tls.py "$CSV/handshake_L5_merged.csv"

echo "✅ TLS analysis and plots complete."


ROOT="${1:-../pcapKeysQUIC}"
CSV="$ROOT/csv"

# Delele CSV folder 
rm -rf "$CSV"

# Run analysis and merge levels
./run_all_levels.sh "$ROOT" quic
./merge_levels.sh "$CSV"

cp "$CSV/handshake_L1_merged.csv" "$CSV_DIR/handshake_L1_merged_QUIC.csv"
cp "$CSV/handshake_L3_merged.csv" "$CSV_DIR/handshake_L3_merged_QUIC.csv"
cp "$CSV/handshake_L5_merged.csv" "$CSV_DIR/handshake_L5_merged_QUIC.csv"


# Generate stacked plots for each level
python3 plot_one_stacked_quic.py "$CSV/handshake_L1_merged.csv"
python3 plot_one_stacked_quic.py "$CSV/handshake_L3_merged.csv"
python3 plot_one_stacked_quic.py "$CSV/handshake_L5_merged.csv"

echo "✅ QUIC analysis and plots complete."
