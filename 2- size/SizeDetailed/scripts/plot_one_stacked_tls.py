#!/usr/bin/env python3
import argparse
import sys
from pathlib import Path
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import re
import os

"""
One stacked bar per KEM (KB):
- Bottom: total_tcp
- Above: total_tls split into keyshare + certificate + signature + tls_data
  where tls_data = total_tls - (keyshare + certificate + signature).

Robust CSV parser: supports comma or whitespace separated files.

Expected columns (case-insensitive; aliases accepted):
- kem (aliases: KEM_ALG, alg, algorithm)
- total_tcp (alias: Suma_TCP)
- keyshare
- certificate
- signature
- total_tls (alias: Suma_TLS)
"""

ALIASES = {
    "kem": ["kem", "kem_alg", "alg", "algorithm"],
    "total_tcp": ["total_tcp", "suma_tcp", "tcp_total", "tcp"],
    "keyshare": ["keyshare", "key_share", "ks"],
    "certificate": ["certificate", "cert"],
    "signature": ["signature", "sig"],
    "total_tls": ["total_tls", "suma_tls", "tls_total", "tls"],
}

def read_csv_robust(path: Path) -> pd.DataFrame:
    # Try comma/whitespace mixed
    try:
        return pd.read_csv(path, sep=r"\s*,\s*|\s+", engine="python")
    except Exception:
        return pd.read_csv(path)

def find_col(df, logical_name):
    wanted = ALIASES[logical_name]
    cols_lower = {c.lower(): c for c in df.columns}
    for w in wanted:
        if w in cols_lower:
            return cols_lower[w]
    return None

def ensure_numeric(df, cols):
    for c in cols:
        if c is not None and c in df.columns:
            df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv_file", help="Ruta al CSV")
    ap.add_argument("-o", "--output", help="PDF de salida", default=None)
    ap.add_argument("--kb-base", type=int, default=1024, help="Bytes por KB (1000 o 1024). Por defecto 1024.")
    args = ap.parse_args()


    csv_path = Path(args.csv_file)
    if not csv_path.exists():
        print(f"ERROR: no existe el fichero: {csv_path}", file=sys.stderr)
        sys.exit(1)

    df = read_csv_robust(csv_path)
    if df.empty:
        print("ERROR: CSV vacío.", file=sys.stderr)
        sys.exit(1)


    filename = csv_path.name
    match = re.search(r"(L[0-9]+)", filename, re.IGNORECASE)
    if match:
        level = match.group(1).upper()
    else:
        level = "Unknown"

    print(f"Level detected: {level}")


    kem_col = find_col(df, "kem")
    tcp_col = find_col(df, "total_tcp")
    ks_col  = find_col(df, "keyshare")
    cert_col= find_col(df, "certificate")
    sig_col = find_col(df, "signature")
    tls_col = find_col(df, "total_tls")

    missing = [name for name, col in [("kem", kem_col), ("total_tcp", tcp_col),
                                      ("keyshare", ks_col), ("certificate", cert_col),
                                      ("signature", sig_col), ("total_tls", tls_col)] if col is None]
    if missing:
        print(f"ERROR: faltan columnas: {', '.join(missing)}", file=sys.stderr)
        print(f"Columnas encontradas: {list(df.columns)}", file=sys.stderr)
        sys.exit(1)

    ensure_numeric(df, [tcp_col, ks_col, cert_col, sig_col, tls_col])

    # Compute tls_data
    ks = df[ks_col].to_numpy(dtype=float)
    cert = df[cert_col].to_numpy(dtype=float)
    sig = df[sig_col].to_numpy(dtype=float)
    tls_total = df[tls_col].to_numpy(dtype=float)

    parts_sum = ks + cert + sig
    tls_data = tls_total - parts_sum

    # Warn if negative residuals (clip to 0 for plotting)
    neg = tls_data < -1e-9
    if np.any(neg):
        print("AVISO: Hay residuales TLS negativos; se recortan a 0 para el gráfico.", file=sys.stderr)
        for kem, val in zip(df[kem_col].astype(str), tls_data):
            if val < -1e-9:
                print(f"  - {kem}: tls_data={val}", file=sys.stderr)
        tls_data = np.maximum(tls_data, 0)

    tcp = df[tcp_col].to_numpy(dtype=float)

    # Convert to KB
    base = float(args.kb_base)
    tcp_kb = tcp / base
    ks_kb = ks / base
    cert_kb = cert / base
    sig_kb = sig / base
    data_kb = tls_data / base

    # Plot
    kems = df[kem_col].astype(str).tolist()
    x = np.arange(len(kems))
    width = 0.65

    fig, ax = plt.subplots(figsize=(10, 6))

    #b_tcp  = ax.bar(x, tcp_kb, width, label="total_tcp (KB)")
    #b_ks   = ax.bar(x, ks_kb, width, bottom=tcp_kb, label="keyshare (KB)")
    #b_cert = ax.bar(x, cert_kb, width, bottom=tcp_kb + ks_kb, label="certificate (KB)")
    #b_sig  = ax.bar(x, sig_kb, width, bottom=tcp_kb + ks_kb + cert_kb, label="signature (KB)")
    #b_data = ax.bar(x, data_kb, width, bottom=tcp_kb + ks_kb + cert_kb + sig_kb, label="tls_data (KB)")


    colors = {
    "TCP": "#6CC4A1",                    
    "KeyShare": "#E5896D",               
    "Certificate": "#748BAE",           
    "Signature": "#C59FC9",             
    "Non-cryptographic TLS Data": "#9CCF7C"  
    }


    b_tcp  = ax.bar(x, tcp_kb, width, label="TCP", color=colors["TCP"])
    b_ks   = ax.bar(x, ks_kb, width, bottom=tcp_kb, label="KeyShare", color=colors["KeyShare"])
    b_cert = ax.bar(x, cert_kb, width, bottom=tcp_kb + ks_kb, label="Certificate", color=colors["Certificate"])
    b_sig  = ax.bar(x, sig_kb, width, bottom=tcp_kb + ks_kb + cert_kb, label="Signature", color=colors["Signature"])
    b_data = ax.bar(x, data_kb, width, bottom=tcp_kb + ks_kb + cert_kb + sig_kb, label="TLS Record Payload", color=colors["Non-cryptographic TLS Data"])
        
    totals_kb = tcp_kb + ks_kb + cert_kb + sig_kb + data_kb
    for xi, total in zip(x, totals_kb):
        ax.annotate(f"{total:.1f}",
                    xy=(xi, total),
                    xytext=(0, 3),
                    textcoords="offset points",
                    ha="center", va="bottom", fontsize=12, fontweight='bold')

   

    ax.set_xticks(x)
    ax.set_xticklabels(kems, rotation=20, ha="right")
    plt.ylabel('Total Size (KB)', fontsize=16)

    etiquetas1 = ['P-256', 'x25519', 'P-256\nmlkem512', 'x25519\nmlkem512', 'mlkem512']
    etiquetas3 = ['P-384', 'x448', 'P-384\nmlkem768', 'x448\nmlkem768', 'mlkem768']
    etiquetas5 = ['P-521', 'P-521\nmlkem1024', 'mlkem1024']
    
 # Adjust bar width and separation
    bar_width = 0.7  # Adjust this value for more/less separation
    index = np.arange(len(kem_col))  # X-axis indices for bars


    if level == 'L1':
        etiquetas = etiquetas1
    elif level == 'L3':
        etiquetas = etiquetas3
    elif level == 'L5':
        etiquetas = etiquetas5
    
    #print (f"Etiquetas: {etiquetas}")

    ax.set_xticks(x)
    ax.set_xticklabels(etiquetas, fontsize=18, rotation=0, ha='center')

   
    # Y si quieres grid y tamaño de ticks Y:
    plt.yticks(fontsize=20)
    plt.grid(axis='y', linestyle='--', alpha=0.7)


    handles, labels = ax.get_legend_handles_labels()
    new_labels = ["TCP", "KeyShare", "Certificate", "Signature", "TLS Record Payload"]
    ax.legend(handles, new_labels, fontsize=12)


    fig.tight_layout()
    
    out_path = args.output or "./output/plots"
    os.makedirs(out_path, exist_ok=True)
    out = os.path.join(out_path, f"{level}_TLS_size.pdf")
    
    plt.savefig(out, dpi=160, bbox_inches="tight")
    print(f"Save: {out}")

if __name__ == "__main__":
    main()
