#!/bin/bash

# Check if a directory was provided as an argument
if [ $# -eq 0 ]; then
  echo "❌ Usage: $0 <directory_with_pcapng_files>"
  exit 1
fi

DIRECTORY="$1"

# Check if the directory exists
if [ ! -d "$DIRECTORY" ]; then
  echo "❌ Directory '$DIRECTORY' does not exist."
  exit 1
fi

# Fields to extract
FIELDS=(
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

# Iterate over each .pcapng file in the directory
for file in "$DIRECTORY"/*.pcapng; do
  # Check if any .pcapng files exist
  if [ ! -e "$file" ]; then
    echo "⚠️  No .pcapng files found in '$DIRECTORY'"
    exit 0
  fi

  # Get the base name without extension
  base_name=$(basename "$file" .pcapng)
  output_csv="${DIRECTORY}/${base_name}.csv"

  echo "📥 Converting: $file to csv "

  # Run tshark to convert to CSV
  tshark -n -r "$file" \
    -T fields \
    "${FIELDS[@]}" \
    -E header=y \
    -E separator=, \
    -E quote=d \
    -E occurrence=f > "$output_csv"
done

echo "✅ Conversion completed in directory '$DIRECTORY'."
