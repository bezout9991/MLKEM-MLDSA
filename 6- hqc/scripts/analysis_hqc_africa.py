#!/usr/bin/env python3
"""
analysis_hqc_africa.py
=======================
Analyse comparative des 4 scénarios réseau africains pour HQC :
  - ideal           : conditions parfaites (baseline)
  - africa_local    : 35ms délai, 2% perte (Yaoundé local)
  - africa_backbone : 200ms délai, 4% perte (liaison internationale)
  - africa_degraded : 200ms délai, 10% perte (réseau dégradé)

Usage:
    python3 analysis_hqc_africa.py \
        --data-dir ~/Documents/TLS-QUIC/'6- hqc'/
"""

import os
import argparse
import numpy as np
import pandas as pd
from scipy.stats import mannwhitneyu
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
SCENARIOS = {
    "ideal":            {"delay": 0,   "loss": 0,  "label": "Idéal (0ms/0%)"},
    "africa_local":     {"delay": 35,  "loss": 2,  "label": "Local YDE (35ms/2%)"},
    "africa_backbone":  {"delay": 200, "loss": 4,  "label": "Backbone (200ms/4%)"},
    "africa_degraded":  {"delay": 200, "loss": 10, "label": "Dégradé (200ms/10%)"},
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

# KEMs HQC par niveau
KEMS_L = {
    1: ["P-256","x25519","hqc128","p256_hqc128","x25519_hqc128"],
    3: ["P-384","x448","hqc192","p384_hqc192","x448_hqc192"],
    5: ["P-521","hqc256","p521_hqc256"],
}
KEM_TYPE = {
    "P-256":"classique","x25519":"classique",
    "P-384":"classique","x448":"classique","P-521":"classique",
    "hqc128":"HQC pur","hqc192":"HQC pur","hqc256":"HQC pur",
    "p256_hqc128":"HQC hybride","x25519_hqc128":"HQC hybride",
    "p384_hqc192":"HQC hybride","x448_hqc192":"HQC hybride",
    "p521_hqc256":"HQC hybride",
}
SIG_CLASSIC = {"ed25519","secp384r1","secp521r1"}
SIG_PQ      = {"mldsa44","mldsa65","mldsa87"}

# ── Chargement ────────────────────────────────────────────────────────────────
def load_all(data_dir):
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

# ── Section 1 : Impact des scénarios sur les moyennes ────────────────────────
def section1_scenario_impact(data):
    print("\n" + "="*80)
    print("SECTION 1 — IMPACT DES CONDITIONS RÉSEAU AFRICAINES SUR LES HANDSHAKES HQC")
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
                    try:
                        ideal_mean = np.mean(data[proto]["ideal"][sig][kem])
                    except KeyError:
                        continue

                    row = [sig, kem, KEM_TYPE.get(kem,"?"), f"{ideal_mean:.1f}"]

                    for scen in ["africa_local","africa_backbone","africa_degraded"]:
                        try:
                            m = np.mean(data[proto][scen][sig][kem])
                            factor = m / ideal_mean
                            row.append(f"{m:.1f} (×{factor:.1f})")
                        except KeyError:
                            row.append("N/A")
                    rows.append(row)

                if rows:
                    print(tabulate(rows,
                        headers=["Sig","KEM","Type","Idéal (ms)",
                                 "Local YDE (35ms/2%)",
                                 "Backbone (200ms/4%)",
                                 "Dégradé (200ms/10%)"],
                        tablefmt="github"))

# ── Section 2 : Δ% ML-DSA vs classique par scénario ──────────────────────────
def section2_mldsa_vs_classic(data):
    print("\n" + "="*80)
    print("SECTION 2 — IMPACT ML-DSA vs CLASSIQUE SUR HQC PAR SCÉNARIO")
    print("="*80)
    print("Δ% = (ML-DSA − Classique) / Classique × 100")
    print("Valeur négative = ML-DSA plus rapide\n")

    hqc_kems_by_lvl = {
        1: ["hqc128","p256_hqc128","x25519_hqc128"],
        3: ["hqc192","p384_hqc192","x448_hqc192"],
        5: ["hqc256","p521_hqc256"],
    }

    for proto in ["TLS","QUIC"]:
        print(f"\n── {proto} ──")
        for sig_c, sig_pq, lvl in SIG_PAIRS:
            print(f"\n  L{lvl} : {sig_c} → {sig_pq}")
            rows = []
            for kem in hqc_kems_by_lvl[lvl]:
                row = [kem, KEM_TYPE.get(kem,"?")]
                for scen in SCENARIOS:
                    try:
                        m_c  = np.mean(data[proto][scen][sig_c][kem])
                        m_pq = np.mean(data[proto][scen][sig_pq][kem])
                        delta = (m_pq - m_c) / m_c * 100
                        p = mw(data[proto][scen][sig_c][kem],
                               data[proto][scen][sig_pq][kem])
                        row.append(f"{delta:+.1f}% (p={p_fmt(p)})")
                    except KeyError:
                        row.append("N/A")
                rows.append(row)

            print(tabulate(rows,
                headers=["KEM","Type","Idéal","Local YDE","Backbone","Dégradé"],
                tablefmt="github"))

# ── Section 3 : TLS vs QUIC par scénario ─────────────────────────────────────
def section3_tls_vs_quic(data):
    print("\n" + "="*80)
    print("SECTION 3 — TLS vs QUIC POUR CHAQUE SCÉNARIO")
    print("="*80)
    print("Δ% = (TLS − QUIC) / QUIC × 100  (négatif = QUIC plus rapide)\n")

    for sig_c, sig_pq, lvl in SIG_PAIRS:
        kems = KEMS_L[lvl]
        for sig in [sig_c, sig_pq]:
            print(f"\n── L{lvl} | Signature : {sig} ──")
            rows = []
            for kem in kems:
                row = [kem, KEM_TYPE.get(kem,"?")]
                for scen in SCENARIOS:
                    try:
                        m_tls  = np.mean(data["TLS"][scen][sig][kem])
                        m_quic = np.mean(data["QUIC"][scen][sig][kem])
                        delta  = (m_tls - m_quic) / m_quic * 100
                        winner = "TLS" if m_tls < m_quic else "QUIC"
                        row.append(f"{delta:+.1f}% ({winner})")
                    except KeyError:
                        row.append("N/A")
                rows.append(row)

            print(tabulate(rows,
                headers=["KEM","Type","Idéal","Local YDE","Backbone","Dégradé"],
                tablefmt="github"))

# ── Section 4 : Synthèse — point de renversement ─────────────────────────────
def section4_reversal_point(data):
    print("\n" + "="*80)
    print("SECTION 4 — POINT DE RENVERSEMENT ML-DSA SUR HQC")
    print("="*80)
    print("Identification du scénario où ML-DSA devient moins avantageux\n")

    hqc_purs = {1:"hqc128", 3:"hqc192", 5:"hqc256"}

    for proto in ["TLS","QUIC"]:
        print(f"\n── {proto} — HQC pur uniquement ──")
        rows = []
        for sig_c, sig_pq, lvl in SIG_PAIRS:
            kem = hqc_purs[lvl]
            row = [f"L{lvl}", kem, sig_c, sig_pq]
            reversal = "Jamais"
            for scen in SCENARIOS:
                try:
                    m_c  = np.mean(data[proto][scen][sig_c][kem])
                    m_pq = np.mean(data[proto][scen][sig_pq][kem])
                    delta = (m_pq - m_c) / m_c * 100
                    row.append(f"{delta:+.1f}%")
                    if delta > 0 and reversal == "Jamais":
                        reversal = SCENARIOS[scen]["label"]
                except KeyError:
                    row.append("N/A")
            row.append(reversal)
            rows.append(row)

        print(tabulate(rows,
            headers=["Niv.","KEM","Sig.class.","Sig.PQ",
                     "Idéal","Local YDE","Backbone","Dégradé","Renversement"],
            tablefmt="github"))

# ── Section 5 : Résumé des facteurs de dégradation ───────────────────────────
def section5_degradation_factors(data):
    print("\n" + "="*80)
    print("SECTION 5 — FACTEURS DE DÉGRADATION vs CONDITIONS IDÉALES")
    print("="*80)
    print("Facteur = Moyenne(scénario) / Moyenne(idéal)\n")

    for proto in ["TLS","QUIC"]:
        print(f"\n── {proto} — Signature classique ──")
        rows = []
        sig_map = {1:"ed25519", 3:"secp384r1", 5:"secp521r1"}

        for lvl in [1,3,5]:
            sig = sig_map[lvl]
            for kem in KEMS_L[lvl]:
                try:
                    ideal = np.mean(data[proto]["ideal"][sig][kem])
                except KeyError:
                    continue
                row = [f"L{lvl}", kem, KEM_TYPE.get(kem,"?"), f"{ideal:.1f}"]
                for scen in ["africa_local","africa_backbone","africa_degraded"]:
                    try:
                        m = np.mean(data[proto][scen][sig][kem])
                        row.append(f"×{m/ideal:.1f}")
                    except KeyError:
                        row.append("N/A")
                rows.append(row)

        print(tabulate(rows,
            headers=["Niv.","KEM","Type","Idéal(ms)",
                     "×Local YDE","×Backbone","×Dégradé"],
            tablefmt="github"))

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", required=True,
                        help="Chemin vers 6- hqc/")
    parser.add_argument("--sections", default="1,2,3,4,5",
                        help="Sections à exécuter (défaut: toutes)")
    args = parser.parse_args()

    sections = [int(s) for s in args.sections.split(",")]

    print("\n" + "="*80)
    print("ANALYSE HQC — CONDITIONS RÉSEAU AFRICAINES")
    print("HQC × Signatures classiques et ML-DSA | TLS 1.3 et QUIC | 500 runs")
    print(f"Données : {args.data_dir}")
    print("="*80)

    data = load_all(args.data_dir)

    loaded = [(p,sc,s) for p in data for sc in data[p] for s in data[p][sc]]
    print(f"\n✅ {len(loaded)} groupes CSV chargés")
    for proto in ["TLS","QUIC"]:
        for scen in SCENARIOS:
            sigs = list(data[proto][scen].keys())
            print(f"   {proto:4s} | {scen:20s} | {len(sigs)} signatures")

    if 1 in sections: section1_scenario_impact(data)
    if 2 in sections: section2_mldsa_vs_classic(data)
    if 3 in sections: section3_tls_vs_quic(data)
    if 4 in sections: section4_reversal_point(data)
    if 5 in sections: section5_degradation_factors(data)

    print("\n" + "="*80)
    print("Analyse terminée.")
    print("="*80 + "\n")

if __name__ == "__main__":
    main()
