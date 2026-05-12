#!/usr/bin/env python3
"""
analysis_pq_signatures.py
=========================
Analyse comparative : signatures classiques vs ML-DSA (FIPS 204)
dans TLS et QUIC — conditions idéales.

Usage:
    python3 analysis_pq_signatures.py --data-dir <chemin_vers_5-pq-signatures>

Structure attendue:
    <data-dir>/TLS/csv/ed25519_tls_ideal.csv
    <data-dir>/TLS/csv/mldsa44_tls_ideal.csv
    ...
    <data-dir>/QUIC/csv/ed25519_quic_ideal.csv
    ...
"""

import os
import sys
import argparse
import numpy as np
import pandas as pd
from scipy import stats
from scipy.stats import mannwhitneyu, shapiro, levene
from itertools import combinations
from tabulate import tabulate

# ── Configuration ────────────────────────────────────────────────────────────

# Mapping signature → niveau NIST
SIG_LEVEL = {
    "ed25519":   1, "secp384r1": 3, "secp521r1": 5,
    "mldsa44":   1, "mldsa65":   3, "mldsa87":   5,
}

# Paires comparables (classique → PQ même niveau)
SIG_PAIRS = [
    ("ed25519",   "mldsa44",  1),
    ("secp384r1", "mldsa65",  3),
    ("secp521r1", "mldsa87",  5),
]

# KEMs par niveau
KEMS_L1 = ["P-256", "x25519", "p256_mlkem512", "x25519_mlkem512", "mlkem512"]
KEMS_L3 = ["P-384", "x448",   "p384_mlkem768", "x448_mlkem768",   "mlkem768"]
KEMS_L5 = ["P-521", "p521_mlkem1024", "mlkem1024"]
KEMS_BY_LEVEL = {1: KEMS_L1, 3: KEMS_L3, 5: KEMS_L5}

# Classification des KEMs
KEM_TYPE = {
    "P-256": "classique", "x25519": "classique",
    "P-384": "classique", "x448": "classique",
    "P-521": "classique",
    "mlkem512": "PQ pur", "mlkem768": "PQ pur", "mlkem1024": "PQ pur",
    "p256_mlkem512": "hybride", "x25519_mlkem512": "hybride",
    "p384_mlkem768": "hybride", "x448_mlkem768": "hybride",
    "p521_mlkem1024": "hybride",
}

# ── Chargement des données ────────────────────────────────────────────────────

def load_csv(data_dir, sig, proto):
    path = os.path.join(data_dir, proto.upper(), "csv",
                        f"{sig}_{proto.lower()}_ideal.csv")
    if not os.path.isfile(path):
        return None
    return pd.read_csv(path)

def load_all(data_dir):
    """Charge tous les CSV dans un dict [proto][sig][kem] → np.array"""
    data = {}
    for proto in ["TLS", "QUIC"]:
        data[proto] = {}
        for sig in SIG_LEVEL:
            df = load_csv(data_dir, sig, proto)
            if df is None:
                continue
            data[proto][sig] = {}
            for kem in df.columns:
                vals = df[kem].dropna().astype(float).values
                data[proto][sig][kem] = vals
    return data

# ── Statistiques descriptives ─────────────────────────────────────────────────

def desc_stats(arr):
    return {
        "mean":   np.mean(arr),
        "std":    np.std(arr, ddof=1),
        "median": np.median(arr),
        "min":    np.min(arr),
        "max":    np.max(arr),
        "n":      len(arr),
    }

# ── Section 1 : Statistiques par signature et protocole ──────────────────────

def section1_descriptive(data):
    print("\n" + "="*80)
    print("SECTION 1 — STATISTIQUES DESCRIPTIVES PAR SIGNATURE ET PROTOCOLE")
    print("="*80)

    for proto in ["TLS", "QUIC"]:
        for sig, level in SIG_LEVEL.items():
            if sig not in data[proto]:
                continue
            kems = KEMS_BY_LEVEL[level]
            rows = []
            for kem in kems:
                if kem not in data[proto][sig]:
                    continue
                s = desc_stats(data[proto][sig][kem])
                rows.append([
                    kem,
                    KEM_TYPE.get(kem, "?"),
                    f"{s['mean']:.2f}",
                    f"{s['std']:.2f}",
                    f"{s['median']:.2f}",
                    f"{s['min']:.2f}",
                    f"{s['max']:.2f}",
                ])
            print(f"\n── {proto} | Signature: {sig} (Niveau L{level}) ──")
            print(tabulate(rows,
                headers=["KEM", "Type", "Mean (ms)", "Std", "Median", "Min", "Max"],
                tablefmt="github"))

# ── Section 2 : Surcoût signatures PQ vs classiques ─────────────────────────

def section2_overhead(data):
    print("\n" + "="*80)
    print("SECTION 2 — SURCOÛT ML-DSA vs SIGNATURE CLASSIQUE (même niveau)")
    print("="*80)

    for proto in ["TLS", "QUIC"]:
        print(f"\n{'─'*60}")
        print(f"Protocole : {proto}")
        print(f"{'─'*60}")

        all_rows = []
        for sig_classic, sig_pq, level in SIG_PAIRS:
            if sig_classic not in data[proto] or sig_pq not in data[proto]:
                continue
            kems = KEMS_BY_LEVEL[level]
            for kem in kems:
                if kem not in data[proto][sig_classic]:
                    continue
                if kem not in data[proto][sig_pq]:
                    continue
                arr_c = data[proto][sig_classic][kem]
                arr_pq = data[proto][sig_pq][kem]
                mean_c  = np.mean(arr_c)
                mean_pq = np.mean(arr_pq)
                overhead_abs = mean_pq - mean_c
                overhead_pct = (overhead_abs / mean_c) * 100 if mean_c > 0 else np.nan

                # Test Mann-Whitney
                try:
                    stat, p = mannwhitneyu(arr_c, arr_pq, alternative='two-sided')
                    sig_str = "***" if p < 0.001 else ("**" if p < 0.01 else ("*" if p < 0.05 else "ns"))
                except:
                    p, sig_str = np.nan, "?"

                all_rows.append([
                    f"L{level}",
                    kem,
                    KEM_TYPE.get(kem, "?"),
                    sig_classic,
                    f"{mean_c:.2f}",
                    sig_pq,
                    f"{mean_pq:.2f}",
                    f"{overhead_abs:+.2f}",
                    f"{overhead_pct:+.1f}%",
                    f"{p:.3e}" if not np.isnan(p) else "nan",
                    sig_str,
                ])

        print(tabulate(all_rows,
            headers=["Niv", "KEM", "Type KEM",
                     "Sig classique", "Mean (ms)",
                     "Sig PQ", "Mean (ms)",
                     "Δ (ms)", "Δ (%)",
                     "p-val MW", "Sig"],
            tablefmt="github"))

# ── Section 3 : Super-additivité ─────────────────────────────────────────────

def section3_superadditivity(data):
    print("\n" + "="*80)
    print("SECTION 3 — SUPER-ADDITIVITÉ : (KEM PQ + Sig PQ) vs somme des surcoûts")
    print("="*80)
    print("""
Méthode :
  overhead_KEM  = mean(sig_classic + kem_pq)  - mean(sig_classic + kem_classic)
  overhead_SIG  = mean(sig_pq      + kem_classic) - mean(sig_classic + kem_classic)
  overhead_BOTH = mean(sig_pq      + kem_pq)  - mean(sig_classic + kem_classic)
  overhead_SUM  = overhead_KEM + overhead_SIG  (hypothèse additive)
  
  Si overhead_BOTH > overhead_SUM  → super-additif (synergie négative)
  Si overhead_BOTH ≈ overhead_SUM  → additif
  Si overhead_BOTH < overhead_SUM  → sous-additif (synergie positive)
""")

    # Paires KEM classique → KEM PQ même niveau
    kem_pairs = {
        1: [("P-256", "mlkem512"), ("x25519", "mlkem512"),
            ("P-256", "p256_mlkem512"), ("x25519", "x25519_mlkem512")],
        3: [("P-384", "mlkem768"), ("x448", "mlkem768"),
            ("P-384", "p384_mlkem768"), ("x448", "x448_mlkem768")],
        5: [("P-521", "mlkem1024"), ("P-521", "p521_mlkem1024")],
    }

    for proto in ["TLS", "QUIC"]:
        print(f"\n{'─'*60}")
        print(f"Protocole : {proto}")
        print(f"{'─'*60}")
        rows = []
        for sig_c, sig_pq, level in SIG_PAIRS:
            if sig_c not in data[proto] or sig_pq not in data[proto]:
                continue
            for kem_c, kem_pq in kem_pairs.get(level, []):
                try:
                    baseline    = np.mean(data[proto][sig_c][kem_c])
                    sig_c_kpq   = np.mean(data[proto][sig_c][kem_pq])
                    sig_pq_kc   = np.mean(data[proto][sig_pq][kem_c])
                    sig_pq_kpq  = np.mean(data[proto][sig_pq][kem_pq])
                except KeyError:
                    continue

                oh_kem  = sig_c_kpq  - baseline
                oh_sig  = sig_pq_kc  - baseline
                oh_both = sig_pq_kpq - baseline
                oh_sum  = oh_kem + oh_sig
                ratio   = oh_both / oh_sum if oh_sum != 0 else np.nan

                if ratio > 1.05:
                    verdict = "⚠ Super-additif"
                elif ratio < 0.95:
                    verdict = "✓ Sous-additif"
                else:
                    verdict = "≈ Additif"

                rows.append([
                    f"L{level}",
                    f"{sig_c}→{sig_pq}",
                    f"{kem_c}→{kem_pq}",
                    f"{baseline:.2f}",
                    f"{oh_kem:+.2f}",
                    f"{oh_sig:+.2f}",
                    f"{oh_sum:+.2f}",
                    f"{oh_both:+.2f}",
                    f"{ratio:.2f}" if not np.isnan(ratio) else "nan",
                    verdict,
                ])

        print(tabulate(rows,
            headers=["Niv", "Signature", "KEM",
                     "Baseline\n(ms)", "ΔKem\n(ms)", "ΔSig\n(ms)",
                     "Σ attendu\n(ms)", "Réel\n(ms)",
                     "Ratio", "Verdict"],
            tablefmt="github"))

# ── Section 4 : TLS vs QUIC par combinaison sig+kem ─────────────────────────

def section4_tls_vs_quic(data):
    print("\n" + "="*80)
    print("SECTION 4 — TLS vs QUIC PAR COMBINAISON SIGNATURE × KEM")
    print("="*80)

    for sig_c, sig_pq, level in SIG_PAIRS:
        kems = KEMS_BY_LEVEL[level]
        print(f"\n── Niveau L{level} ──")
        rows = []
        for sig in [sig_c, sig_pq]:
            for kem in kems:
                try:
                    arr_tls  = data["TLS"][sig][kem]
                    arr_quic = data["QUIC"][sig][kem]
                except KeyError:
                    continue
                mean_tls  = np.mean(arr_tls)
                mean_quic = np.mean(arr_quic)
                diff_pct  = ((mean_tls - mean_quic) / mean_quic) * 100

                try:
                    _, p = mannwhitneyu(arr_tls, arr_quic, alternative='two-sided')
                    sig_str = "***" if p < 0.001 else ("**" if p < 0.01 else ("*" if p < 0.05 else "ns"))
                except:
                    p, sig_str = np.nan, "?"

                winner = "QUIC" if mean_quic < mean_tls else "TLS"
                rows.append([
                    sig,
                    kem,
                    KEM_TYPE.get(kem, "?"),
                    f"{mean_tls:.2f}",
                    f"{mean_quic:.2f}",
                    f"{diff_pct:+.1f}%",
                    f"{p:.3e}" if not np.isnan(p) else "nan",
                    sig_str,
                    winner,
                ])

        print(tabulate(rows,
            headers=["Signature", "KEM", "Type",
                     "TLS (ms)", "QUIC (ms)", "TLS vs QUIC",
                     "p-val", "Sig", "Meilleur"],
            tablefmt="github"))

# ── Section 5 : Résumé synthétique ───────────────────────────────────────────

def section5_summary(data):
    print("\n" + "="*80)
    print("SECTION 5 — RÉSUMÉ SYNTHÉTIQUE")
    print("="*80)

    print("\n── Moyennes globales par catégorie ──\n")

    categories = {
        "Sig classique + KEM classique": [],
        "Sig classique + KEM hybride":   [],
        "Sig classique + KEM PQ pur":    [],
        "Sig PQ + KEM classique":        [],
        "Sig PQ + KEM hybride":          [],
        "Sig PQ + KEM PQ pur":           [],
    }

    sig_classic_set = {"ed25519", "secp384r1", "secp521r1"}
    sig_pq_set      = {"mldsa44", "mldsa65",   "mldsa87"}

    for proto in ["TLS", "QUIC"]:
        cat_data = {k: {"TLS": [], "QUIC": []} for k in categories}
        for sig in sig_classic_set | sig_pq_set:
            if sig not in data[proto]:
                continue
            level = SIG_LEVEL[sig]
            is_pq_sig = sig in sig_pq_set
            for kem, vals in data[proto][sig].items():
                kt = KEM_TYPE.get(kem, "?")
                sig_label = "Sig PQ" if is_pq_sig else "Sig classique"
                kem_label = ("KEM classique" if kt == "classique"
                             else "KEM hybride" if kt == "hybride"
                             else "KEM PQ pur")
                key = f"{sig_label} + {kem_label}"
                if key in cat_data:
                    cat_data[key][proto].extend(vals.tolist())

        rows = []
        for cat, pdata in cat_data.items():
            tls_mean  = np.mean(pdata["TLS"])  if pdata["TLS"]  else np.nan
            quic_mean = np.mean(pdata["QUIC"]) if pdata["QUIC"] else np.nan
            rows.append([
                cat,
                f"{tls_mean:.2f}"  if not np.isnan(tls_mean)  else "—",
                f"{quic_mean:.2f}" if not np.isnan(quic_mean) else "—",
            ])

        print(tabulate(rows,
            headers=["Catégorie", "TLS moy. (ms)", "QUIC moy. (ms)"],
            tablefmt="github"))

    print("\n── Combinaisons optimales (latence minimale) ──\n")
    for proto in ["TLS", "QUIC"]:
        best = []
        for sig in sig_classic_set | sig_pq_set:
            if sig not in data[proto]:
                continue
            level = SIG_LEVEL[sig]
            for kem, vals in data[proto][sig].items():
                best.append((np.mean(vals), sig, kem, level))
        best.sort()
        print(f"\n{proto} — Top 5 combinaisons les plus rapides :")
        rows = []
        for mean, sig, kem, level in best[:5]:
            rows.append([f"L{level}", sig, kem,
                        KEM_TYPE.get(kem,"?"), f"{mean:.2f}"])
        print(tabulate(rows,
            headers=["Niv", "Signature", "KEM", "Type KEM", "Mean (ms)"],
            tablefmt="github"))

        print(f"\n{proto} — Top 5 combinaisons les plus lentes :")
        rows = []
        for mean, sig, kem, level in best[-5:][::-1]:
            rows.append([f"L{level}", sig, kem,
                        KEM_TYPE.get(kem,"?"), f"{mean:.2f}"])
        print(tabulate(rows,
            headers=["Niv", "Signature", "KEM", "Type KEM", "Mean (ms)"],
            tablefmt="github"))

# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Analyse comparative signatures PQ vs classiques dans TLS/QUIC")
    parser.add_argument("--data-dir", required=True,
        help="Chemin vers le dossier 5- pq-signatures/")
    parser.add_argument("--sections", default="1,2,3,4,5",
        help="Sections à exécuter (défaut: 1,2,3,4,5)")
    args = parser.parse_args()

    sections = [int(s) for s in args.sections.split(",")]

    print(f"\n{'='*80}")
    print("ANALYSE COMPARATIVE : SIGNATURES POST-QUANTIQUES ML-DSA vs CLASSIQUES")
    print("TLS 1.3 et QUIC — Conditions idéales — 500 runs")
    print(f"Données : {args.data_dir}")
    print(f"{'='*80}")

    data = load_all(args.data_dir)

    # Vérification chargement
    loaded = [(p, s) for p in data for s in data[p]]
    print(f"\n✅ Données chargées : {len(loaded)} fichiers CSV")
    for proto, sig in sorted(loaded):
        kems = list(data[proto][sig].keys())
        n = len(data[proto][sig][kems[0]]) if kems else 0
        print(f"   {proto:4s} | {sig:12s} | {len(kems)} KEMs | {n} runs chacun")

    if 1 in sections: section1_descriptive(data)
    if 2 in sections: section2_overhead(data)
    if 3 in sections: section3_superadditivity(data)
    if 4 in sections: section4_tls_vs_quic(data)
    if 5 in sections: section5_summary(data)

    print(f"\n{'='*80}")
    print("Analyse terminée.")
    print(f"{'='*80}\n")

if __name__ == "__main__":
    main()
