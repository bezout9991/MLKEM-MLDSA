#!/usr/bin/env python3
"""
analysis_africa_scenarios.py
=============================
Analyse comparative des 4 scénarios réseau africains :
  - ideal        : conditions parfaites (baseline)
  - africa_local : 35ms délai, 2% perte (Yaoundé local)
  - africa_backbone : 200ms délai, 4% perte (liaison internationale)
  - africa_degraded : 200ms délai, 10% perte (réseau dégradé)

Usage:
    python3 analysis_africa_scenarios.py \
        --data-dir ~/Documents/TLS-QUIC/5- pq-signatures/
"""

import os
import argparse
import numpy as np
import pandas as pd
from scipy.stats import mannwhitneyu
from tabulate import tabulate

# ── Configuration ─────────────────────────────────────────────────────────────
SCENARIOS = {
    "ideal":            {"delay": 0,   "loss": 0,  "label": "Idéal"},
    "africa_local":     {"delay": 35,  "loss": 2,  "label": "Local YDE\n(35ms/2%)"},
    "africa_backbone":  {"delay": 200, "loss": 4,  "label": "Backbone\n(200ms/4%)"},
    "africa_degraded":  {"delay": 200, "loss": 10, "label": "Dégradé\n(200ms/10%)"},
}

SIG_LEVEL = {
    "ed25519":1,"secp384r1":3,"secp521r1":5,
    "mldsa44":1,"mldsa65":3,"mldsa87":5,
}
SIG_PAIRS = [
    ("ed25519",   "mldsa44", 1),
    ("secp384r1", "mldsa65", 3),
    ("secp521r1", "mldsa87", 5),
]
KEMS_L = {
    1: ["P-256","x25519","p256_mlkem512","x25519_mlkem512","mlkem512"],
    3: ["P-384","x448","p384_mlkem768","x448_mlkem768","mlkem768"],
    5: ["P-521","p521_mlkem1024","mlkem1024"],
}
KEM_TYPE = {
    "P-256":"classique","x25519":"classique",
    "P-384":"classique","x448":"classique","P-521":"classique",
    "mlkem512":"PQ pur","mlkem768":"PQ pur","mlkem1024":"PQ pur",
    "p256_mlkem512":"hybride","x25519_mlkem512":"hybride",
    "p384_mlkem768":"hybride","x448_mlkem768":"hybride",
    "p521_mlkem1024":"hybride",
}
SIG_CLASSIC = {"ed25519","secp384r1","secp521r1"}
SIG_PQ      = {"mldsa44","mldsa65","mldsa87"}

# ── Chargement ────────────────────────────────────────────────────────────────
def load_all(data_dir):
    """Charge tous les CSV : data[proto][scenario][sig][kem] → np.array"""
    data = {}
    for proto in ["TLS","QUIC"]:
        data[proto] = {}
        for scenario in SCENARIOS:
            data[proto][scenario] = {}
            for sig in SIG_LEVEL:
                fname = f"{sig}_{proto.lower()}_{scenario}.csv"
                path  = os.path.join(data_dir, proto.upper(), "csv", fname)
                if not os.path.isfile(path):
                    continue
                df = pd.read_csv(path)
                data[proto][scenario][sig] = {
                    kem: df[kem].dropna().astype(float).values
                    for kem in df.columns
                }
    return data

# ── Section 1 : Impact des scénarios sur les moyennes ────────────────────────
def section1_scenario_impact(data):
    print("\n" + "="*80)
    print("SECTION 1 — IMPACT DES CONDITIONS RÉSEAU AFRICAINES SUR LES HANDSHAKES")
    print("="*80)
    print("Moyennes en ms — entre parenthèses : facteur multiplicatif vs idéal\n")

    for proto in ["TLS","QUIC"]:
        print(f"\n{'─'*70}")
        print(f"Protocole : {proto}")
        print(f"{'─'*70}")

        for sig_c, sig_pq, level in SIG_PAIRS:
            kems = KEMS_L[level]
            print(f"\n── L{level} | {sig_c} vs {sig_pq} ──")

            for sig in [sig_c, sig_pq]:
                rows = []
                for kem in kems:
                    row = [sig, kem, KEM_TYPE.get(kem,"?")]
                    try:
                        ideal_mean = np.mean(data[proto]["ideal"][sig][kem])
                    except KeyError:
                        continue
                    row.append(f"{ideal_mean:.1f}")
                    for scen in ["africa_local","africa_backbone","africa_degraded"]:
                        try:
                            arr  = data[proto][scen][sig][kem]
                            mean = np.mean(arr)
                            # Médiane pour les distributions avec timeouts
                            med  = np.median(arr)
                            factor = mean / ideal_mean if ideal_mean > 0 else np.nan
                            row.append(f"{mean:.1f} (×{factor:.1f})")
                        except KeyError:
                            row.append("—")
                    rows.append(row)

                if rows:
                    print(tabulate(rows,
                        headers=["Sig","KEM","Type",
                                 "Idéal (ms)",
                                 "Local YDE\n35ms/2%",
                                 "Backbone\n200ms/4%",
                                 "Dégradé\n200ms/10%"],
                        tablefmt="github"))
                    print()

# ── Section 2 : ML-DSA reste-t-il avantageux sous conditions africaines ? ────
def section2_mldsa_advantage(data):
    print("\n" + "="*80)
    print("SECTION 2 — ML-DSA RESTE-T-IL AVANTAGEUX SOUS CONDITIONS AFRICAINES ?")
    print("="*80)
    print("Δ% = (mldsa - classique) / classique × 100")
    print("Négatif = ML-DSA plus rapide | Positif = ML-DSA plus lent\n")

    for proto in ["TLS","QUIC"]:
        print(f"\n{'─'*70}")
        print(f"Protocole : {proto}")
        print(f"{'─'*70}")
        rows = []

        for sig_c, sig_pq, level in SIG_PAIRS:
            kems = KEMS_L[level]
            for kem in kems:
                row = [f"L{level}", kem, KEM_TYPE.get(kem,"?")]
                for scen in SCENARIOS:
                    try:
                        mean_c  = np.mean(data[proto][scen][sig_c][kem])
                        mean_pq = np.mean(data[proto][scen][sig_pq][kem])
                        pct = ((mean_pq - mean_c) / mean_c) * 100
                        # Test Mann-Whitney
                        _, p = mannwhitneyu(
                            data[proto][scen][sig_c][kem],
                            data[proto][scen][sig_pq][kem],
                            alternative='two-sided'
                        )
                        sig_str = "***" if p<0.001 else "**" if p<0.01 else "*" if p<0.05 else "ns"
                        row.append(f"{pct:+.1f}% {sig_str}")
                    except KeyError:
                        row.append("—")
                rows.append(row)

        print(tabulate(rows,
            headers=["Niv","KEM","Type",
                     "Idéal","Local YDE","Backbone","Dégradé"],
            tablefmt="github"))

# ── Section 3 : Évolution du surcoût avec la dégradation ─────────────────────
def section3_degradation_slope(data):
    print("\n" + "="*80)
    print("SECTION 3 — SENSIBILITÉ AUX CONDITIONS RÉSEAU : SLOPE (ms/scénario)")
    print("="*80)
    print("Slope = régression linéaire sur [idéal, local, backbone, dégradé]")
    print("Valeurs de délai utilisées : 0, 35, 200, 200 ms\n")

    delay_vals = [0, 35, 200, 200]
    scen_order = ["ideal","africa_local","africa_backbone","africa_degraded"]

    for proto in ["TLS","QUIC"]:
        print(f"\n{'─'*70}")
        print(f"Protocole : {proto}")
        print(f"{'─'*70}")
        rows = []

        for sig_c, sig_pq, level in SIG_PAIRS:
            kems = KEMS_L[level]
            for sig in [sig_c, sig_pq]:
                for kem in kems:
                    means = []
                    for scen in scen_order:
                        try:
                            means.append(np.mean(data[proto][scen][sig][kem]))
                        except KeyError:
                            means.append(np.nan)

                    if all(np.isnan(m) for m in means):
                        continue

                    # Slope via régression linéaire
                    valid = [(d,m) for d,m in zip(delay_vals,means)
                             if not np.isnan(m)]
                    if len(valid) >= 2:
                        x = np.array([v[0] for v in valid])
                        y = np.array([v[1] for v in valid])
                        slope = np.polyfit(x, y, 1)[0]
                    else:
                        slope = np.nan

                    sig_type = "PQ" if sig in SIG_PQ else "Classic"
                    rows.append([
                        f"L{level}", sig, sig_type,
                        kem, KEM_TYPE.get(kem,"?"),
                        f"{means[0]:.1f}" if not np.isnan(means[0]) else "—",
                        f"{means[1]:.1f}" if not np.isnan(means[1]) else "—",
                        f"{means[2]:.1f}" if not np.isnan(means[2]) else "—",
                        f"{means[3]:.1f}" if not np.isnan(means[3]) else "—",
                        f"{slope:.3f}" if not np.isnan(slope) else "—",
                    ])

        print(tabulate(rows,
            headers=["Niv","Sig","Type Sig","KEM","Type KEM",
                     "Idéal","Local","Backbone","Dégradé",
                     "Slope\n(ms/ms-délai)"],
            tablefmt="github"))

# ── Section 4 : TLS vs QUIC sous conditions africaines ───────────────────────
def section4_tls_vs_quic_africa(data):
    print("\n" + "="*80)
    print("SECTION 4 — TLS vs QUIC SOUS CONDITIONS AFRICAINES")
    print("="*80)
    print("p-val Mann-Whitney | *** p<0.001 | ** p<0.01 | * p<0.05 | ns\n")

    for scen, scen_info in SCENARIOS.items():
        print(f"\n── Scénario : {scen_info['label'].replace(chr(10),' ')} ──")
        rows = []
        for sig_c, sig_pq, level in SIG_PAIRS:
            kems = KEMS_L[level]
            for sig in [sig_c, sig_pq]:
                for kem in kems:
                    try:
                        arr_tls  = data["TLS"][scen][sig][kem]
                        arr_quic = data["QUIC"][scen][sig][kem]
                    except KeyError:
                        continue
                    mean_tls  = np.mean(arr_tls)
                    mean_quic = np.mean(arr_quic)
                    diff_pct  = ((mean_tls - mean_quic)/mean_quic)*100
                    try:
                        _, p = mannwhitneyu(arr_tls, arr_quic,
                                            alternative='two-sided')
                        sig_str = "***" if p<0.001 else "**" if p<0.01 \
                                  else "*" if p<0.05 else "ns"
                    except:
                        p, sig_str = np.nan, "?"
                    winner = "QUIC" if mean_quic < mean_tls else "TLS"
                    rows.append([
                        f"L{level}", sig,
                        kem, KEM_TYPE.get(kem,"?"),
                        f"{mean_tls:.1f}",
                        f"{mean_quic:.1f}",
                        f"{diff_pct:+.1f}%",
                        sig_str, winner
                    ])

        print(tabulate(rows,
            headers=["Niv","Sig","KEM","Type",
                     "TLS (ms)","QUIC (ms)","TLS vs QUIC",
                     "Sig","Meilleur"],
            tablefmt="github"))

# ── Section 5 : Recommandations de déploiement ───────────────────────────────
def section5_recommendations(data):
    print("\n" + "="*80)
    print("SECTION 5 — RECOMMANDATIONS DE DÉPLOIEMENT POUR RÉSEAUX AFRICAINS")
    print("="*80)
    print("Top 5 combinaisons optimales par scénario et protocole\n")

    for scen, scen_info in SCENARIOS.items():
        print(f"\n── {scen_info['label'].replace(chr(10),' ')} ──")
        for proto in ["TLS","QUIC"]:
            candidates = []
            for sig in SIG_LEVEL:
                if sig not in data[proto].get(scen, {}):
                    continue
                level = SIG_LEVEL[sig]
                for kem, arr in data[proto][scen][sig].items():
                    # Utiliser la médiane pour les scénarios avec pertes
                    med  = np.median(arr)
                    mean = np.mean(arr)
                    sig_type = "PQ" if sig in SIG_PQ else "Classic"
                    candidates.append((med, mean, sig, kem,
                                       level, sig_type,
                                       KEM_TYPE.get(kem,"?")))
            candidates.sort()
            print(f"\n  {proto} — Top 5 (triés par médiane) :")
            rows = []
            for med, mean, sig, kem, level, st, kt in candidates[:5]:
                rows.append([f"L{level}", sig, st, kem, kt,
                             f"{med:.1f}", f"{mean:.1f}"])
            print(tabulate(rows,
                headers=["Niv","Sig","Type Sig","KEM","Type KEM",
                         "Médiane (ms)","Moyenne (ms)"],
                tablefmt="github"))

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", required=True,
        help="Chemin vers 5- pq-signatures/")
    parser.add_argument("--sections", default="1,2,3,4,5",
        help="Sections à exécuter (défaut: 1,2,3,4,5)")
    args = parser.parse_args()

    sections = [int(s) for s in args.sections.split(",")]

    print(f"\n{'='*80}")
    print("ANALYSE COMPARATIVE — CONDITIONS RÉSEAU AFRICAINES")
    print("ML-DSA (FIPS 204) vs Signatures classiques dans TLS et QUIC")
    print(f"Données : {args.data_dir}")
    print(f"{'='*80}")

    data = load_all(args.data_dir)

    # Résumé du chargement
    total = sum(
        len(data[p][s])
        for p in data
        for s in data[p]
    )
    print(f"\n✅ {total} groupes de CSV chargés")
    for proto in ["TLS","QUIC"]:
        for scen in SCENARIOS:
            n = len(data[proto].get(scen,{}))
            print(f"   {proto:4s} | {scen:20s} | {n} signatures")

    if 1 in sections: section1_scenario_impact(data)
    if 2 in sections: section2_mldsa_advantage(data)
    if 3 in sections: section3_degradation_slope(data)
    if 4 in sections: section4_tls_vs_quic_africa(data)
    if 5 in sections: section5_recommendations(data)

    print(f"\n{'='*80}")
    print("Analyse terminée.")
    print(f"{'='*80}\n")

if __name__ == "__main__":
    main()
