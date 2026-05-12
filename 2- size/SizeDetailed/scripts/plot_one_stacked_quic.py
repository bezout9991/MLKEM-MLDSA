#!/usr/bin/env python3
import argparse, sys, re
from pathlib import Path
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import os

# --- Config ---
ALIASES = {
    "kem": ["kem", "kem_alg", "alg", "algorithm"],
    "keyshare": ["keyshare", "key_share", "ks"],
    "certificate": ["certificate", "cert"],
    "signature": ["signature", "sig"],
    # 👇 NUEVO: detectar columna 1-RTT (acepta varios alias)
    "rtt1": ["1rtt", "1-rtx", "1-rtt", "rtt1", "one_rtt", "kp0", "short_header"],
    "total_quic": ["total_quic", "quic_total", "quic"]
}

def read_csv_robust(path: Path) -> pd.DataFrame:
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
        if c and c in df.columns:
            df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv_file", help="Ruta al CSV (kem,keyshare,certificate,signature,1RTT,total_quic)")
    ap.add_argument("-o", "--output", help="Directorio de salida", default=None)
    ap.add_argument("--kb-base", type=int, default=1024, help="Bytes por KB (1000 o 1024).")
    args = ap.parse_args()

    csv_path = Path(args.csv_file)
    if not csv_path.exists():
        print(f"ERROR: no existe el fichero: {csv_path}", file=sys.stderr); sys.exit(1)

    df = read_csv_robust(csv_path)
    if df.empty:
        print("ERROR: CSV vacío.", file=sys.stderr); sys.exit(1)

    # Nivel desde el nombre del fichero
    m = re.search(r"(L[0-9]+)", csv_path.name, re.IGNORECASE)
    level = (m.group(1).upper() if m else "Unknown")
    print(f"Level detected: {level}")

    kem_col = find_col(df, "kem")
    ks_col  = find_col(df, "keyshare")
    cert_col= find_col(df, "certificate")
    sig_col = find_col(df, "signature")
    rtt_col = find_col(df, "rtt1")            # 👈 NUEVO
    quic_col= find_col(df, "total_quic")

    missing_required = [n for n,c in [("kem",kem_col),("keyshare",ks_col),
                                      ("certificate",cert_col),("signature",sig_col),
                                      ("total_quic",quic_col)] if c is None]
    if missing_required:
        print(f"ERROR: faltan columnas: {', '.join(missing_required)}", file=sys.stderr)
        print(f"columns finded: {list(df.columns)}", file=sys.stderr)
        sys.exit(1)

    # 1-RTT es opcional; si no está, lo tratamos como 0
    ensure_numeric(df, [ks_col, cert_col, sig_col, quic_col] + ([rtt_col] if rtt_col else []))

    # Partes QUIC (KB)
    base = float(args.kb_base)
    kems = df[kem_col].astype(str).tolist()
    ks_kb   = df[ks_col].to_numpy(float)   / base
    cert_kb = df[cert_col].to_numpy(float) / base
    sig_kb  = df[sig_col].to_numpy(float)  / base
    rtt_kb  = (df[rtt_col].to_numpy(float) / base) if rtt_col else np.zeros_like(sig_kb)  # 👈 NUEVO
    quic_kb = df[quic_col].to_numpy(float) / base

    # Residual = total_quic - (crypto + 1-RTT)  👇 ACTUALIZADO
    resid_kb = quic_kb - (ks_kb + cert_kb + sig_kb + rtt_kb)
    neg = resid_kb < -1e-9
    if np.any(neg):
        print("AVISO: residual QUIC negativo; se recorta a 0 para el gráfico.", file=sys.stderr)
        resid_kb = np.maximum(resid_kb, 0)

    x = np.arange(len(kems))
    width = 0.65
    fig, ax = plt.subplots(figsize=(10, 6))

    # Paleta
    colors = {
        "KeyShare": "#E5896D",
        "Certificate": "#748BAE",
        "Signature": "#C59FC9",
        "1-RTT": "#E5C16D",            # 👈 NUEVO
        "QUIC Residual": "#9CCF7C"
    }

    # Barras apiladas (añadimos 1-RTT)
    b_ks   = ax.bar(x, ks_kb,   width, label="KeyShare",                    color=colors["KeyShare"])
    b_cert = ax.bar(x, cert_kb, width, bottom=ks_kb,                        label="Certificate",                 color=colors["Certificate"])
    b_sig  = ax.bar(x, sig_kb,  width, bottom=ks_kb+cert_kb,                label="Signature",                   color=colors["Signature"])
    b_rtt  = ax.bar(x, rtt_kb,  width, bottom=ks_kb+cert_kb+sig_kb,         label="1-RTT",                       color=colors["1-RTT"])  # 👈 NUEVO
    b_rest = ax.bar(x, resid_kb,width, bottom=ks_kb+cert_kb+sig_kb+rtt_kb,  label="Non-cryptographic QUIC Data", color=colors["QUIC Residual"])

    # Totales encima
    for xi, total in zip(x, quic_kb):
        ax.annotate(f"{total:.1f}", xy=(xi, total), xytext=(0,5), textcoords="offset points",
                    ha="center", va="bottom", fontsize=12, fontweight="bold")

    # Etiquetas X
    etiquetas1 = ['P-256', 'x25519', 'P-256\nmlkem512', 'x25519\nmlkem512', 'mlkem512']
    etiquetas3 = ['P-384', 'x448', 'P-384\nmlkem768', 'x448\nmlkem768', 'mlkem768']
    etiquetas5 = ['P-521', 'P-521\nmlkem1024', 'mlkem1024']

    if level == "L1" and len(kems)==len(etiquetas1): etiquetas = etiquetas1
    elif level == "L3" and len(kems)==len(etiquetas3): etiquetas = etiquetas3
    elif level == "L5" and len(kems)==len(etiquetas5): etiquetas = etiquetas5
    else: etiquetas = kems

    ax.set_xticks(x)
    ax.set_xticklabels(etiquetas, fontsize=16)
    ax.set_ylabel("Total Size (KB)", fontsize=16)
    plt.yticks(fontsize=14)
    plt.grid(axis="y", linestyle="--", alpha=0.7)

    # Leyenda (con 1-RTT)
    handles, labels = ax.get_legend_handles_labels()
    new_labels = ["KeyShare", "Certificate", "Signature", "1-RTT", "QUIC Record Payload"]
    ax.legend(handles, new_labels, fontsize=12)

    fig.tight_layout()
    out_path = args.output or "./output/plots"
    os.makedirs(out_path, exist_ok=True)
    out = os.path.join(out_path, f"{level}_QUIC_size.pdf")
    plt.savefig(out, dpi=300, bbox_inches="tight")
    print(f"Save: {out}")

if __name__ == "__main__":
    main()
