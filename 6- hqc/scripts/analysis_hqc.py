#!/usr/bin/env python3
"""
analysis_hqc.py
===============
Analyse comparative : HQC vs ML-KEM vs classiques
dans TLS et QUIC — conditions idéales.

Usage:
    python3 analysis_hqc.py --data-dir <chemin_vers_6-hqc>

Structure attendue:
    <data-dir>/TLS/csv/ed25519_tls_hqc.csv
    <data-dir>/TLS/csv/mldsa44_tls_hqc.csv
    ...
    <data-dir>/QUIC/csv/ed25519_quic_hqc.csv
    ...
"""

import os
import sys
import argparse
import numpy as np
import pandas as pd
from scipy.stats import mannwhitneyu, shapiro, levene
from itertools import combinations

try:
    from tabulate import tabulate
except ImportError:
    def tabulate(data, headers=[], tablefmt="simple", floatfmt=".2f"):
        rows = [headers] + [[str(x) for x in row] for row in data]
        widths = [max(len(str(r[i])) for r in rows) for i in range(len(rows[0]))]
        lines = []
        for row in rows:
            lines.append("  ".join(str(r).ljust(w) for r, w in zip(row, widths)))
        return "\n".join(lines)

# ── Configuration ─────────────────────────────────────────────────────────────

SIG_LEVEL = {
    "ed25519":   1, "secp384r1": 3, "secp521r1": 5,
    "mldsa44":   1, "mldsa65":   3, "mldsa87":   5,
}

SIG_PAIRS = [
    ("ed25519",   "mldsa44",  1),
    ("secp384r1", "mldsa65",  3),
    ("secp521r1", "mldsa87",  5),
]

# KEMs présents dans les CSV HQC
KEMS_L1 = ["P-256", "x25519", "hqc128", "p256_hqc128", "x25519_hqc128"]
KEMS_L3 = ["P-384", "x448",   "hqc192", "p384_hqc192", "x448_hqc192"]
KEMS_L5 = ["P-521", "hqc256", "p521_hqc256"]
KEMS_BY_LEVEL = {1: KEMS_L1, 3: KEMS_L3, 5: KEMS_L5}

# KEMs ML-KEM de référence (Phase 5) pour comparaison HQC vs ML-KEM
MLKEM_REF = {
    "hqc128":      "mlkem512",
    "p256_hqc128": "p256_mlkem512",
    "x25519_hqc128": "x25519_mlkem512",
    "hqc192":      "mlkem768",
    "p384_hqc192": "p384_mlkem768",
    "x448_hqc192": "x448_mlkem768",
    "hqc256":      "mlkem1024",
    "p521_hqc256": "p521_mlkem1024",
}

KEM_TYPE = {
    "P-256": "classique", "x25519": "classique",
    "P-384": "classique", "x448":   "classique",
    "P-521": "classique",
    "hqc128":  "HQC pur",  "hqc192":  "HQC pur",  "hqc256":  "HQC pur",
    "p256_hqc128": "HQC hybride", "x25519_hqc128": "HQC hybride",
    "p384_hqc192": "HQC hybride", "x448_hqc192":   "HQC hybride",
    "p521_hqc256": "HQC hybride",
}

# ── Chargement ────────────────────────────────────────────────────────────────

def load_csv(data_dir, sig, proto):
    path = os.path.join(data_dir, proto.upper(), "csv",
                        f"{sig}_{proto.lower()}_hqc.csv")
    if not os.path.isfile(path):
        return None
    return pd.read_csv(path)

def load_all(data_dir):
    data = {}
    for proto in ["TLS", "QUIC"]:
        data[proto] = {}
        for sig in SIG_LEVEL:
            df = load_csv(data_dir, sig, proto)
            if df is None:
                continue
            data[proto][sig] = {}
            for kem in df.columns:
                arr = df[kem].dropna().values.astype(float)
                if len(arr) > 0:
                    data[proto][sig][kem] = arr
    return data

def p_fmt(p):
    if p is None or np.isnan(p): return "nan"
    if p < 0.001: return "< 0.001"
    return f"{p:.3f}"

def mw(a, b):
    try:
        _, p = mannwhitneyu(a, b, alternative="two-sided")
        return p
    except:
        return float("nan")

# ── Section 1 : Statistiques descriptives ────────────────────────────────────

def section1_descriptive(data):
    print(f"\n{'='*70}")
    print("SECTION 1 — STATISTIQUES DESCRIPTIVES PAR NIVEAU ET PROTOCOLE")
    print(f"{'='*70}")

    for proto in ["TLS", "QUIC"]:
        for lvl in [1, 3, 5]:
            sigs_lvl = [s for s, l in SIG_LEVEL.items() if l == lvl and s in data.get(proto, {})]
            if not sigs_lvl:
                continue
            print(f"\n{'─'*60}")
            print(f"  {proto} — Niveau L{lvl}")
            print(f"{'─'*60}")
            for sig in sigs_lvl:
                kems = KEMS_BY_LEVEL[lvl]
                rows = []
                for kem in kems:
                    if kem not in data[proto][sig]:
                        continue
                    arr = data[proto][sig][kem]
                    rows.append([
                        kem,
                        KEM_TYPE.get(kem, "?"),
                        f"{np.mean(arr):.2f}",
                        f"{np.std(arr):.2f}",
                        f"{np.median(arr):.2f}",
                        f"{np.min(arr):.2f}",
                        f"{np.max(arr):.2f}",
                    ])
                print(f"\n  Signature : {sig}")
                print(tabulate(rows,
                    headers=["KEM", "Type", "Moyenne", "Std", "Médiane", "Min", "Max"],
                    tablefmt="github", floatfmt=".2f"))

# ── Section 2 : HQC vs Classiques ────────────────────────────────────────────

def section2_hqc_vs_classique(data):
    print(f"\n{'='*70}")
    print("SECTION 2 — HQC vs CLASSIQUES (surcoût PQ)")
    print(f"{'='*70}")
    print("Δ% = (HQC − Classique) / Classique × 100")
    print("Classique de référence : P-256 (L1), P-384 (L3), P-521 (L5)")

    ref_classique = {1: "P-256", 3: "P-384", 5: "P-521"}
    hqc_purs = {1: "hqc128", 3: "hqc192", 5: "hqc256"}

    for proto in ["TLS", "QUIC"]:
        print(f"\n  ── {proto} ──")
        rows = []
        for lvl in [1, 3, 5]:
            sigs = [s for s, l in SIG_LEVEL.items() if l == lvl and s in data.get(proto, {})]
            ref_kem = ref_classique[lvl]
            hqc_kem = hqc_purs[lvl]
            for sig in sigs:
                if ref_kem not in data[proto][sig]: continue
                if hqc_kem not in data[proto][sig]: continue
                ref_arr = data[proto][sig][ref_kem]
                hqc_arr = data[proto][sig][hqc_kem]
                delta = (np.mean(hqc_arr) - np.mean(ref_arr)) / np.mean(ref_arr) * 100
                p = mw(ref_arr, hqc_arr)
                rows.append([
                    f"L{lvl}", sig, ref_kem, f"{np.mean(ref_arr):.2f}",
                    hqc_kem, f"{np.mean(hqc_arr):.2f}",
                    f"{delta:+.1f}%", p_fmt(p)
                ])
        print(tabulate(rows,
            headers=["Niv.", "Sig.", "Classique", "Moy.(ms)",
                     "HQC pur", "Moy.(ms)", "Δ%", "p-val (MW)"],
            tablefmt="github"))

# ── Section 3 : HQC pur vs ML-KEM pur ────────────────────────────────────────

def section3_hqc_vs_mlkem(data, mlkem_dir):
    print(f"\n{'='*70}")
    print("SECTION 3 — HQC pur vs ML-KEM pur (comparaison inter-KEM PQ)")
    print(f"{'='*70}")

    if mlkem_dir is None:
        print("  ⚠ Répertoire ML-KEM non fourni (--mlkem-dir). Section ignorée.")
        return

    # Charger données ML-KEM Phase 5
    mlkem_data = {}
    for proto in ["TLS", "QUIC"]:
        mlkem_data[proto] = {}
        for sig in ["ed25519", "secp384r1", "secp521r1", "mldsa44", "mldsa65", "mldsa87"]:
            path = os.path.join(mlkem_dir, proto.upper(), "csv",
                                f"{sig}_{proto.lower()}_ideal.csv")
            if not os.path.isfile(path):
                continue
            df = pd.read_csv(path)
            mlkem_data[proto][sig] = {col: df[col].dropna().values.astype(float)
                                       for col in df.columns}

    pairs = [
        ("hqc128", "mlkem512",    1, "ed25519"),
        ("hqc192", "mlkem768",    3, "secp384r1"),
        ("hqc256", "mlkem1024",   5, "secp521r1"),
    ]

    for proto in ["TLS", "QUIC"]:
        print(f"\n  ── {proto} — Signatures classiques ──")
        rows = []
        for hqc_kem, mlkem_kem, lvl, sig in pairs:
            if sig not in data.get(proto, {}): continue
            if hqc_kem not in data[proto][sig]: continue
            if sig not in mlkem_data.get(proto, {}): continue
            if mlkem_kem not in mlkem_data[proto][sig]: continue

            hqc_arr   = data[proto][sig][hqc_kem]
            mlkem_arr = mlkem_data[proto][sig][mlkem_kem]
            delta = (np.mean(hqc_arr) - np.mean(mlkem_arr)) / np.mean(mlkem_arr) * 100
            p = mw(hqc_arr, mlkem_arr)
            winner = "HQC" if np.mean(hqc_arr) < np.mean(mlkem_arr) else "ML-KEM"
            rows.append([
                f"L{lvl}", sig,
                hqc_kem,   f"{np.mean(hqc_arr):.2f}",
                mlkem_kem, f"{np.mean(mlkem_arr):.2f}",
                f"{delta:+.1f}%", p_fmt(p), winner
            ])
        print(tabulate(rows,
            headers=["Niv.", "Sig.", "HQC", "Moy.(ms)",
                     "ML-KEM", "Moy.(ms)", "Δ%", "p-val", "Gagnant"],
            tablefmt="github"))

# ── Section 4 : Impact de la signature (classique vs ML-DSA) sur HQC ─────────

def section4_sig_impact_on_hqc(data):
    print(f"\n{'='*70}")
    print("SECTION 4 — IMPACT DE LA SIGNATURE SUR HQC")
    print("           (ed25519 vs mldsa44, secp384r1 vs mldsa65, etc.)")
    print(f"{'='*70}")
    print("Δ% = (ML-DSA − Classique) / Classique × 100 pour chaque KEM HQC")

    hqc_kems = {
        1: ["hqc128", "p256_hqc128", "x25519_hqc128"],
        3: ["hqc192", "p384_hqc192", "x448_hqc192"],
        5: ["hqc256", "p521_hqc256"],
    }

    for proto in ["TLS", "QUIC"]:
        print(f"\n  ── {proto} ──")
        rows = []
        for sig_classic, sig_pq, lvl in SIG_PAIRS:
            if sig_classic not in data.get(proto, {}): continue
            if sig_pq not in data.get(proto, {}): continue
            for kem in hqc_kems[lvl]:
                if kem not in data[proto][sig_classic]: continue
                if kem not in data[proto][sig_pq]: continue
                classic_arr = data[proto][sig_classic][kem]
                pq_arr      = data[proto][sig_pq][kem]
                delta = (np.mean(pq_arr) - np.mean(classic_arr)) / np.mean(classic_arr) * 100
                p = mw(classic_arr, pq_arr)
                rows.append([
                    f"L{lvl}", kem, KEM_TYPE.get(kem, "?"),
                    sig_classic, f"{np.mean(classic_arr):.2f}",
                    sig_pq,     f"{np.mean(pq_arr):.2f}",
                    f"{delta:+.1f}%", p_fmt(p)
                ])
        print(tabulate(rows,
            headers=["Niv.", "KEM", "Type",
                     "Sig. classique", "Moy.(ms)",
                     "Sig. ML-DSA",    "Moy.(ms)",
                     "Δ%", "p-val (MW)"],
            tablefmt="github"))

# ── Section 5 : TLS vs QUIC pour chaque KEM HQC ──────────────────────────────

def section5_tls_vs_quic(data):
    print(f"\n{'='*70}")
    print("SECTION 5 — TLS vs QUIC POUR CHAQUE KEM HQC")
    print(f"{'='*70}")
    print("Δ% = (TLS − QUIC) / QUIC × 100  (négatif = QUIC plus rapide)")

    all_hqc = ["hqc128","p256_hqc128","x25519_hqc128",
                "hqc192","p384_hqc192","x448_hqc192",
                "hqc256","p521_hqc256"]

    for sig in ["ed25519", "secp384r1", "secp521r1", "mldsa44", "mldsa65", "mldsa87"]:
        lvl = SIG_LEVEL[sig]
        kems = KEMS_BY_LEVEL[lvl]
        if sig not in data.get("TLS", {}): continue
        if sig not in data.get("QUIC", {}): continue

        print(f"\n  Signature : {sig} (L{lvl})")
        rows = []
        for kem in kems:
            if kem not in data["TLS"][sig]: continue
            if kem not in data["QUIC"][sig]: continue
            tls_arr  = data["TLS"][sig][kem]
            quic_arr = data["QUIC"][sig][kem]
            delta = (np.mean(tls_arr) - np.mean(quic_arr)) / np.mean(quic_arr) * 100
            p = mw(tls_arr, quic_arr)
            winner = "QUIC" if np.mean(quic_arr) < np.mean(tls_arr) else "TLS"
            rows.append([
                kem, KEM_TYPE.get(kem, "?"),
                f"{np.mean(tls_arr):.2f}",
                f"{np.mean(quic_arr):.2f}",
                f"{delta:+.1f}%", p_fmt(p), winner
            ])
        print(tabulate(rows,
            headers=["KEM", "Type", "TLS (ms)", "QUIC (ms)",
                     "Δ%", "p-val (MW)", "Gagnant"],
            tablefmt="github"))

# ── Section 6 : Synthèse — Classement des KEMs HQC ───────────────────────────

def section6_ranking(data):
    print(f"\n{'='*70}")
    print("SECTION 6 — CLASSEMENT GLOBAL DES KEMs HQC PAR PERFORMANCE")
    print(f"{'='*70}")

    for proto in ["TLS", "QUIC"]:
        print(f"\n  ── {proto} — Signature ed25519/secp384r1/secp521r1 ──")
        rows = []
        for lvl in [1, 3, 5]:
            sig_map = {1: "ed25519", 3: "secp384r1", 5: "secp521r1"}
            sig = sig_map[lvl]
            if sig not in data.get(proto, {}): continue
            for kem in KEMS_BY_LEVEL[lvl]:
                if kem not in data[proto][sig]: continue
                arr = data[proto][sig][kem]
                rows.append((np.mean(arr), f"L{lvl}", kem,
                              KEM_TYPE.get(kem, "?"),
                              f"{np.mean(arr):.2f}",
                              f"{np.median(arr):.2f}",
                              f"{np.std(arr):.2f}"))

        rows.sort(key=lambda x: x[0])
        print(tabulate(
            [[i+1] + list(r[1:]) for i, r in enumerate(rows)],
            headers=["Rang", "Niv.", "KEM", "Type",
                     "Moyenne (ms)", "Médiane (ms)", "Std (ms)"],
            tablefmt="github"))

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Analyse HQC vs ML-KEM vs Classiques")
    parser.add_argument("--data-dir", required=True,
                        help="Chemin vers le dossier 6- hqc/")
    parser.add_argument("--mlkem-dir", default=None,
                        help="Chemin vers le dossier 5- pq-signatures/ (pour comparaison HQC vs ML-KEM)")
    parser.add_argument("--sections", default="1,2,3,4,5,6",
                        help="Sections à exécuter (défaut: toutes)")
    args = parser.parse_args()

    sections = [int(s) for s in args.sections.split(",")]

    print(f"\n{'='*70}")
    print("ANALYSE HQC — CONDITIONS IDÉALES")
    print("HQC vs ML-KEM vs Classiques | TLS 1.3 et QUIC | 500 runs")
    print(f"Données : {args.data_dir}")
    print(f"{'='*70}")

    data = load_all(args.data_dir)

    # Vérification
    loaded = [(p, s) for p in data for s in data[p]]
    print(f"\n✅ Données chargées : {len(loaded)} fichiers CSV")
    for proto, sig in sorted(loaded):
        kems = list(data[proto][sig].keys())
        n = len(data[proto][sig][kems[0]]) if kems else 0
        print(f"   {proto:4s} | {sig:12s} | {len(kems)} KEMs | {n} runs chacun")

    if 1 in sections: section1_descriptive(data)
    if 2 in sections: section2_hqc_vs_classique(data)
    if 3 in sections: section3_hqc_vs_mlkem(data, args.mlkem_dir)
    if 4 in sections: section4_sig_impact_on_hqc(data)
    if 5 in sections: section5_tls_vs_quic(data)
    if 6 in sections: section6_ranking(data)

    print(f"\n{'='*70}")
    print("Analyse terminée.")
    print(f"{'='*70}\n")

if __name__ == "__main__":
    main()
