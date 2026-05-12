#!/usr/bin/env python3
"""
merge_handshake_metrics.py  (v3, corrige KeyError)
Une tamaños y tiempos de handshakes y deja, opcionalmente, una columna
vacía entre KEMs para facilitar la inspección visual en Excel/LibreOffice.

Uso:
    python merge_handshake_metrics.py sizes_csv times_csv [output_csv]
"""

import sys
import pathlib
import pandas as pd

# ----- ajustes personalizables -----
METRICS        = ["Time_ms", "Bytes_Total"]
INSERT_SPACERS = True          # crea una columna vacía "" tras cada KEM
SPACER_HEADER  = ""            # cabecera de esa columna ("" o " ")
# -----------------------------------

def merge_csvs(sizes_csv: str, times_csv: str, out_csv: str | None = None) -> str:
    # 1) cargar datos
    sizes_df = pd.read_csv(sizes_csv)      # KEM_ALG, Handshake_ID, Bytes_*
    times_df = pd.read_csv(times_csv)      # columnas = KEMs (+ Handshake_ID)

    # 2) asegurar Handshake_ID
    if "Handshake_ID" not in times_df.columns:
        times_df = times_df.reset_index().rename(columns={"index": "Handshake_ID"})
        times_df["Handshake_ID"] += 1

    sizes_df["Handshake_ID"] = sizes_df["Handshake_ID"].astype(int)
    times_df["Handshake_ID"] = times_df["Handshake_ID"].astype(int)

    # 3) tiempos ancho -> largo
    kem_cols = [c for c in times_df.columns if c != "Handshake_ID"]
    times_long = times_df.melt(
        id_vars="Handshake_ID", value_vars=kem_cols,
        var_name="KEM_ALG", value_name="Time_ms"
    )

    # 4) fusionar
    merged = pd.merge(
        sizes_df, times_long,
        on=["Handshake_ID", "KEM_ALG"],
        how="inner", validate="one_to_one"
    )

    # 5) pivotar (métrica, KEM)  -> índice = Handshake_ID
    wide = merged.pivot(
        index="Handshake_ID",
        columns="KEM_ALG",
        values=METRICS
    )

    # 6) aplanar MultiIndex a "KEM_Métrica"
    wide.columns = [f"{kem}_{metric}" for metric, kem in wide.columns]

    # 7) reordenar columnas KEM-a-KEM con separadores
    ordered_cols = []
    for kem in kem_cols:                     # respeta orden original
        for metric in METRICS:
            ordered_cols.append(f"{kem}_{metric}")
        if INSERT_SPACERS:
            ordered_cols.append(SPACER_HEADER)

    if INSERT_SPACERS:
        # añade la(s) columna(s) de espacio vacía(s) sólo una vez
        for i, col in enumerate(ordered_cols):
            if col == SPACER_HEADER:
                col_name = f"{SPACER_HEADER}{i}" if SPACER_HEADER == "" else col
                wide[col_name] = ""          # valores vacíos

        # reemplaza en ordered_cols los "" repetidos por los nombres únicos añadidos
        ordered_cols = [
            (f"{SPACER_HEADER}{i}" if col == SPACER_HEADER else col)
            for i, col in enumerate(ordered_cols)
        ]
        # quita el último separador visual, si lo hubiera
        if ordered_cols and ordered_cols[-1].startswith(SPACER_HEADER):
            ordered_cols = ordered_cols[:-1]

    wide = wide[ordered_cols].reset_index()

    # 8) guardar
    if out_csv is None:
        out_csv = pathlib.Path(sizes_csv).with_suffix("").name + "_merged.csv"

    wide.to_csv(out_csv, index=False)
    return out_csv


def main() -> None:
    if len(sys.argv) < 3:
        print("Uso: python merge_handshake_metrics.py sizes_csv times_csv [output_csv]")
        sys.exit(1)

    sizes_csv = sys.argv[1]
    times_csv = sys.argv[2]
    out_csv   = sys.argv[3] if len(sys.argv) >= 4 else None

    output = merge_csvs(sizes_csv, times_csv, out_csv)
    print(f"Fichero combinado guardado en: {output}")


if __name__ == "__main__":
    main()
