#!/usr/bin/env bash
# Merge handshake_<kem>.csv into three files (L1, L3, L5), sorted by logical KEM order.
# Usage: ./merge_levels_from_kem.sh [csv_folder]
set -euo pipefail

ROOT="${1:-.}"
shopt -s nullglob

# --- Determine the level from KEM name ---
detect_level() {
  local kem="${1,,}"   # lowercase
  case "$kem" in
    *mlkem512*|*p256_mlkem512*|*x25519_mlkem512*|p256|x25519)
      echo "L1";;
    *mlkem768*|*p384_mlkem768*|*x448_mlkem768*|p384|x448)
      echo "L3";;
    *mlkem1024*|*p521_mlkem1024*|p521)
      echo "L5";;
    *)
      echo "NA";;
  esac
}

# --- Logical KEM order for each level ---
declare -A ORDER
ORDER["L1"]="p256 x25519 p256_mlkem512 x25519_mlkem512 mlkem512"
ORDER["L3"]="p384 x448 p384_mlkem768 x448_mlkem768 mlkem768"
ORDER["L5"]="p521 p521_mlkem1024 mlkem1024"

# --- Classify files ---
declare -A FILES
for csv in "$ROOT"/handshake_*.csv; do
  kem=$(basename "$csv" .csv | sed 's/^handshake_//' | tr '[:upper:]' '[:lower:]')
  lvl=$(detect_level "$kem")
  [[ "$lvl" == "NA" ]] && { echo "⚠️  Unclassified: $csv"; continue; }
  FILES["$lvl"]+="$csv "
done

# --- Merge and sort ---
merge_level() {
  local lvl="$1"
  local files_str="${FILES[$lvl]-}"
  [[ -z "$files_str" ]] && { echo "⚠️  No files for $lvl"; return; }

  local out="$ROOT/handshake_${lvl}_merged.csv"
  local files=( $files_str )

  echo "📦 Merging ${#files[@]} CSVs for ${lvl} → $out"

  # Header
  head -n 1 "${files[0]}" > "$out"

  tmp=$(mktemp)
  for f in "${files[@]}"; do
    tail -n +2 "$f" >> "$tmp"
  done

  # KEM order for this level
  local order="${ORDER[$lvl]}"
  echo "   ↳ KEM order: $order"

  head -n 1 "${files[0]}" > "$out"

  tmp=$(mktemp)
  for f in "${files[@]}"; do
    tail -n +2 "$f" >> "$tmp"
  done

  # Print rows following the defined order
  for kem in $order; do
    grep -E "^${kem}," "$tmp" || true
  done >> "$out"

  # Add any unlisted KEMs
  grep -v -E "^($(echo $order | sed 's/ /|/g'))," "$tmp" >> "$out" || true

  rm -f "$tmp"
}

merge_level "L1"
merge_level "L3"
merge_level "L5"

echo "✅ Merge complete:"
ls -1 $ROOT/handshake_L*_merged.csv 2>/dev/null || echo "No CSVs generated."
