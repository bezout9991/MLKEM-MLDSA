#!/usr/bin/env python3
"""
plot_hqc_africa.py — version corrigée
==================
Figures pour les conditions réseau africaines — Phase 6 HQC
Identique en structure aux figures 6-9 de la Phase 5 ML-DSA

Corrections apportées vs version précédente :
  [C1] Suffixe _hqc ajouté à tous les fichiers de sortie (fig6, fig7, fig9)
       pour éviter l'écrasement des figures Phase 5
  [C2] Fig9 : x_max calculé dynamiquement depuis les données (plus de 150ms hardcodé)
       → hqc192 (111ms) et hqc256 (88ms) ne seront plus tronqués
  [C3] Fig7 : structure alignée sur Phase 5 (2x2, L1+L3 uniquement)
       + ajout L5 en subplot séparé pour cohérence comparative

Usage:
    python3 plot_hqc_africa.py \\
        --data-dir ~/Documents/TLS-QUIC/'6- hqc'/ \\
        --out-dir  ~/Documents/TLS-QUIC/'6- hqc'/plots/
"""

import os
import argparse
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

plt.rcParams.update({
    'font.family': 'DejaVu Sans', 'font.size': 10,
    'axes.titlesize': 11, 'axes.labelsize': 10,
    'xtick.labelsize': 9, 'ytick.labelsize': 9,
    'legend.fontsize': 8, 'figure.dpi': 150,
    'axes.grid': True, 'grid.alpha': 0.3,
    'axes.spines.top': False, 'axes.spines.right': False,
})

# ── Configuration ─────────────────────────────────────────────────────────────
SCENARIOS = {
    "ideal":           {"label": "Idéal\n(0ms/0%)",       "delay": 0,   "loss": 0},
    "africa_local":    {"label": "Local YDE\n(35ms/2%)",  "delay": 35,  "loss": 2},
    "africa_backbone": {"label": "Backbone\n(200ms/4%)",  "delay": 200, "loss": 4},
    "africa_degraded": {"label": "Dégradé\n(200ms/10%)", "delay": 200, "loss": 10},
}
SCEN_ORDER  = list(SCENARIOS.keys())
SCEN_LABELS = [SCENARIOS[s]["label"] for s in SCEN_ORDER]

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
# [C1] Labels cohérents avec Phase 5 (classique/hybride/PQ pur)
# mais on garde HQC pur / HQC hybride pour distinguer clairement Phase 6
KEM_COLORS  = {
    "classique":    "#2E75B6",
    "HQC pur":      "#C55A11",
    "HQC hybride":  "#BF9000",
}
KEM_MARKERS = {"classique":"o", "HQC pur":"^", "HQC hybride":"s"}
SIG_PQ      = {"mldsa44","mldsa65","mldsa87"}
SIG_CLASSIC = {"ed25519","secp384r1","secp521r1"}

# ── Chargement ────────────────────────────────────────────────────────────────
def load_all(data_dir):
    data = {}
    for proto in ["TLS","QUIC"]:
        data[proto] = {}
        for scen in SCENARIOS:
            data[proto][scen] = {}
            for sig in SIG_LEVEL:
                fname = f"{sig}_{proto.lower()}_{scen}.csv"
                path  = os.path.join(data_dir, proto.upper(), "csv", fname)
                if not os.path.isfile(path):
                    continue
                df = pd.read_csv(path)
                data[proto][scen][sig] = {
                    kem: df[kem].dropna().astype(float).values
                    for kem in df.columns
                }
    return data

# [C1] Fonction save centralisée — tous les noms passent par ici
def save(fig, out_dir, name):
    os.makedirs(out_dir, exist_ok=True)
    for ext in ["pdf", "png"]:
        fig.savefig(os.path.join(out_dir, f"{name}.{ext}"),
                    bbox_inches="tight", dpi=150)
    plt.close(fig)
    print(f"  ✅ {name}.pdf / .png")


# ── Figure 6 : Évolution Δ% ML-DSA vs classique selon scénario ───────────────
def fig6_delta_evolution(data, out_dir):
    print("\n[Fig 6] Évolution Δ% ML-DSA vs classique sur HQC selon scénario réseau")

    fig, axes = plt.subplots(2, 3, figsize=(15, 10))
    fig.suptitle(
        "Évolution du surcoût ML-DSA vs signature classique selon le scénario réseau\n"
        "Δ%(%) = (ML-DSA − Classique) / Classique × 100\n"
        "Zone verte = ML-DSA plus rapide | Zone rouge = ML-DSA plus lent",
        fontsize=11, y=1.02
    )

    hqc_kems_by_lvl = {
        1: ["hqc128","p256_hqc128","x25519_hqc128"],
        3: ["hqc192","p384_hqc192","x448_hqc192"],
        5: ["hqc256","p521_hqc256"],
    }

    for col, (sig_c, sig_pq, lvl) in enumerate(SIG_PAIRS):
        for row, proto in enumerate(["TLS","QUIC"]):
            ax = axes[row][col]
            kems_hqc = hqc_kems_by_lvl[lvl]

            ax.axhline(0, color='black', lw=1.5, ls='--', alpha=0.7)
            ax.axhspan(-200, 0,  alpha=0.04, color='green')
            ax.axhspan(0,   300, alpha=0.04, color='red')

            x = range(len(SCEN_ORDER))
            for kem in kems_hqc:
                deltas = []
                for scen in SCEN_ORDER:
                    try:
                        m_c  = np.mean(data[proto][scen][sig_c][kem])
                        m_pq = np.mean(data[proto][scen][sig_pq][kem])
                        deltas.append((m_pq - m_c) / m_c * 100)
                    except KeyError:
                        deltas.append(np.nan)

                kt = KEM_TYPE.get(kem, "classique")
                ax.plot(x, deltas,
                        marker=KEM_MARKERS.get(kt, "o"),
                        color=KEM_COLORS.get(kt, "gray"),
                        linewidth=2, markersize=6, label=kem)

            ax.set_xticks(range(len(SCEN_ORDER)))
            ax.set_xticklabels(SCEN_LABELS, fontsize=8)
            ax.set_ylabel("Δ% ML-DSA vs Classique")
            ax.set_title(f"{proto} — L{lvl} ({sig_c} vs {sig_pq})", fontsize=9)
            ax.legend(fontsize=7, loc='best')

    plt.tight_layout()
    # [C1] Suffixe _hqc ajouté
    save(fig, out_dir, "fig6_delta_evolution_hqc")


# ── Figure 7 : Renversement TLS vs QUIC ──────────────────────────────────────
# [C3] Structure alignée sur Phase 5 : 2x2 pour L1+L3, + rangée L5 séparée
# Phase 5 fait 2x2 (L1 classique / L1 ML-DSA / L3 classique / L3 ML-DSA)
# Phase 6 : même structure 2x2 pour L1+L3, + 1x2 pour L5 en dessous
def fig7_tls_quic_reversal(data, out_dir):
    print("\n[Fig 7] Renversement TLS vs QUIC selon scénario réseau")

    # Même 4 subplots principaux que Phase 5 + 2 subplots L5
    plot_combos_main = [
        ("ed25519",   1, (0, 0)),
        ("mldsa44",   1, (0, 1)),
        ("secp384r1", 3, (1, 0)),
        ("mldsa65",   3, (1, 1)),
    ]
    plot_combos_l5 = [
        ("secp521r1", 5, (2, 0)),
        ("mldsa87",   5, (2, 1)),
    ]

    fig, axes = plt.subplots(3, 2, figsize=(16, 18))
    fig.suptitle(
        "Rapport TLS vs QUIC selon le scénario réseau — KEMs HQC\n"
        "TLS−QUIC (%) | Positif = TLS plus lent | Négatif = TLS plus rapide",
        fontsize=13, fontweight='bold', y=0.98
    )

    x_pos = np.arange(len(SCEN_ORDER))

    for sig, level, (r, c) in plot_combos_main + plot_combos_l5:
        ax = axes[r][c]
        kems = KEMS_L[level]
        sig_type = "ML-DSA" if sig in SIG_PQ else "Classique"

        ax.axhline(y=0, color='black', lw=1.5, ls='--', alpha=0.7,
                   label='TLS = QUIC')
        ax.axhspan(-400, 0,   alpha=0.04, color='blue')
        ax.axhspan(0,    600, alpha=0.04, color='red')

        for kem in kems:
            diffs = []
            for scen in SCEN_ORDER:
                try:
                    mt = np.mean(data["TLS"][scen][sig][kem])
                    mq = np.mean(data["QUIC"][scen][sig][kem])
                    diffs.append(((mt - mq) / mq) * 100)
                except KeyError:
                    diffs.append(np.nan)

            kt     = KEM_TYPE.get(kem, "classique")
            color  = KEM_COLORS.get(kt, "gray")
            marker = KEM_MARKERS.get(kt, "o")
            valid  = [(x_pos[i], d) for i, d in enumerate(diffs)
                      if not np.isnan(d)]
            if not valid:
                continue
            vx, vd = zip(*valid)
            ax.plot(vx, vd, color=color, marker=marker,
                    lw=1.5, ms=6, alpha=0.85, label=kem)
            ax.annotate(kem, (vx[-1], vd[-1]), fontsize=6,
                        xytext=(3, 0), textcoords='offset points',
                        color=color)

        ax.set_xticks(x_pos)
        ax.set_xticklabels(SCEN_LABELS, fontsize=8)
        ax.set_ylabel("(TLS − QUIC) / QUIC × 100 (%)")
        ax.set_title(f"L{level} | Sig: {sig} ({sig_type})", fontweight='bold')
        for xv in [0.5, 1.5, 2.5]:
            ax.axvline(x=xv, color='gray', lw=0.6, ls=':', alpha=0.5)

        ax.legend(handles=[
            mpatches.Patch(color=KEM_COLORS["classique"],   label='KEM classique'),
            mpatches.Patch(color=KEM_COLORS["HQC pur"],     label='HQC pur'),
            mpatches.Patch(color=KEM_COLORS["HQC hybride"], label='HQC hybride'),
            mpatches.Patch(color='blue', alpha=0.3, label='TLS meilleur'),
            mpatches.Patch(color='red',  alpha=0.3, label='QUIC meilleur'),
        ], fontsize=7, loc='upper left')

    plt.tight_layout(rect=[0, 0, 1, 0.96])
    # [C1] Suffixe _hqc ajouté
    save(fig, out_dir, "fig7_tls_quic_reversal_hqc")


# ── Figure 8 : Heatmap des temps moyens ──────────────────────────────────────
def fig8_deployment_heatmap(data, out_dir):
    print("\n[Fig 8] Heatmap des temps moyens — combinaisons × 4 scénarios")

    all_combos = []
    for lvl in [1, 3, 5]:
        sig_c  = {1:"ed25519",  3:"secp384r1", 5:"secp521r1"}[lvl]
        sig_pq = {1:"mldsa44",  3:"mldsa65",   5:"mldsa87"}[lvl]
        for kem in KEMS_L[lvl]:
            for sig in [sig_c, sig_pq]:
                all_combos.append((sig, kem, lvl))

    fig, axes = plt.subplots(1, 2,
                             figsize=(18, max(len(all_combos) * 0.4 + 2, 8)))
    fig.suptitle(
        "Heatmap des temps moyens de handshake (ms) — échelle logarithmique\n"
        "KEMs HQC × Signatures × Scénarios réseau africains",
        fontsize=11
    )

    for col, proto in enumerate(["TLS","QUIC"]):
        ax = axes[col]
        matrix  = np.full((len(all_combos), len(SCEN_ORDER)), np.nan)
        ylabels = []

        for i, (sig, kem, lvl) in enumerate(all_combos):
            for j, scen in enumerate(SCEN_ORDER):
                try:
                    matrix[i, j] = np.mean(data[proto][scen][sig][kem])
                except KeyError:
                    pass
            kt        = KEM_TYPE.get(kem, "?")
            sig_short = (sig.replace("secp384r1", "s384")
                            .replace("secp521r1", "s521"))
            ylabels.append(f"{sig_short}+{kem}\n({kt})")

        masked  = np.ma.masked_invalid(matrix)
        im = ax.imshow(np.log10(masked + 1), aspect='auto',
                       cmap='YlOrRd', vmin=0, vmax=np.log10(3000))

        for i in range(len(all_combos)):
            for j in range(len(SCEN_ORDER)):
                v = matrix[i, j]
                if not np.isnan(v):
                    ax.text(j, i, f"{v:.0f}", ha='center', va='center',
                            fontsize=6,
                            color='white' if v > 200 else 'black')

        ax.set_xticks(range(len(SCEN_ORDER)))
        ax.set_xticklabels(SCEN_LABELS, fontsize=8)
        ax.set_yticks(range(len(ylabels)))
        ax.set_yticklabels(ylabels, fontsize=6)
        ax.set_title(proto, fontsize=11)
        plt.colorbar(im, ax=ax, label="log10(ms+1)")

    plt.tight_layout()
    # Nom déjà correct dans la version originale — on garde
    save(fig, out_dir, "fig8_deployment_heatmap_hqc")


# ── Figure 9 : Scatter idéal vs dégradé ──────────────────────────────────────
def fig9_ideal_vs_degraded(data, out_dir):
    print("\n[Fig 9] Scatter idéal vs dégradé — résistance à la dégradation")

    fig, axes = plt.subplots(1, 2, figsize=(14, 6))
    fig.suptitle(
        "Impact de la dégradation réseau : Idéal vs Dégradé (200ms/10%)\n"
        "Points proches de la diagonale = combinaison résistante à la dégradation",
        fontsize=11
    )

    for col, proto in enumerate(["TLS","QUIC"]):
        ax = axes[col]
        sig_map    = {1:"ed25519",  3:"secp384r1", 5:"secp521r1"}
        sig_pq_map = {1:"mldsa44",  3:"mldsa65",   5:"mldsa87"}

        # [C2] Collecter toutes les valeurs idéales et dégradées
        #      pour calculer x_max dynamiquement
        all_ideal   = []
        all_degraded= []

        for lvl in [1, 3, 5]:
            for sig_key, sig_map_used in [("classic", sig_map),
                                           ("pq",      sig_pq_map)]:
                sig = sig_map_used[lvl]
                for kem in KEMS_L[lvl]:
                    try:
                        ideal   = np.mean(data[proto]["ideal"][sig][kem])
                        degraded= np.mean(data[proto]["africa_degraded"][sig][kem])
                    except KeyError:
                        continue
                    all_ideal.append(ideal)
                    all_degraded.append(degraded)

                    kt     = KEM_TYPE.get(kem, "classique")
                    color  = KEM_COLORS.get(kt, "gray")
                    marker = "o" if sig in SIG_CLASSIC else "^"
                    ax.scatter(ideal, degraded, c=color, marker=marker,
                               s=50, alpha=0.8, zorder=5)
                    ax.annotate(f"{kem[:8]}", (ideal, degraded),
                                textcoords="offset points",
                                xytext=(3, 3), fontsize=5, alpha=0.7)

        # [C2] x_max dynamique avec marge 10% — fini le 150ms hardcodé
        if all_ideal:
            x_max = max(all_ideal) * 1.10
            y_max = max(all_degraded) * 1.05
            ax.plot([0, x_max], [0, x_max], 'k--', alpha=0.4, lw=1,
                    label='Idéal = Dégradé')
            ax.set_xlim(0, x_max)
            ax.set_ylim(0, y_max)

        ax.set_xlabel("Temps idéal (ms)")
        ax.set_ylabel("Temps dégradé 200ms/10% (ms)")
        ax.set_title(proto, fontsize=11)
        ax.legend(handles=[
            mpatches.Patch(color=KEM_COLORS["classique"],   label='classique'),
            mpatches.Patch(color=KEM_COLORS["HQC pur"],     label='HQC pur'),
            mpatches.Patch(color=KEM_COLORS["HQC hybride"], label='HQC hybride'),
            plt.Line2D([0],[0], marker='o', color='gray', ls='', ms=7,
                       alpha=0.6, label='Sig. classique'),
            plt.Line2D([0],[0], marker='^', color='gray', ls='', ms=7,
                       label='Sig. ML-DSA'),
        ], fontsize=7, loc='upper left')

    plt.tight_layout()
    # [C1] Suffixe _hqc ajouté
    save(fig, out_dir, "fig9_ideal_vs_degraded_hqc")


# ── Figure 10 : Résumé par catégorie ─────────────────────────────────────────
def fig10_category_summary(data, out_dir):
    print("\n[Fig 10] Synthèse par catégorie : classique vs HQC pur vs HQC hybride")

    categories_order = ["classique","HQC pur","HQC hybride"]
    sig_classic_map  = {1:"ed25519",  3:"secp384r1", 5:"secp521r1"}
    sig_pq_map       = {1:"mldsa44",  3:"mldsa65",   5:"mldsa87"}

    fig, axes = plt.subplots(2, len(SCEN_ORDER), figsize=(18, 10))
    fig.suptitle(
        "Temps moyen de handshake par catégorie de KEM HQC\n"
        "Barres hachurées = Signature ML-DSA | Pleines = Signature classique",
        fontsize=11, y=1.02
    )

    for col, scen in enumerate(SCEN_ORDER):
        for row, proto in enumerate(["TLS","QUIC"]):
            ax = axes[row][col]
            x = np.arange(len(categories_order))
            w = 0.35

            means_classic, means_pq = [], []

            for cat in categories_order:
                vals_c, vals_pq = [], []
                for lvl in [1, 3, 5]:
                    sig_c  = sig_classic_map[lvl]
                    sig_pq = sig_pq_map[lvl]
                    for kem in KEMS_L[lvl]:
                        if KEM_TYPE.get(kem, "") != cat:
                            continue
                        try:
                            vals_c.append(
                                np.mean(data[proto][scen][sig_c][kem]))
                        except KeyError:
                            pass
                        try:
                            vals_pq.append(
                                np.mean(data[proto][scen][sig_pq][kem]))
                        except KeyError:
                            pass
                means_classic.append(np.mean(vals_c)  if vals_c  else 0)
                means_pq.append(     np.mean(vals_pq) if vals_pq else 0)

            colors = [KEM_COLORS[c] for c in categories_order]
            bars_c  = ax.bar(x - w/2, means_classic, w,
                             color=colors, alpha=0.85, label="Sig. classique")
            bars_pq = ax.bar(x + w/2, means_pq,      w,
                             color=colors, alpha=0.55, hatch="//",
                             label="Sig. ML-DSA")

            for bar in list(bars_c) + list(bars_pq):
                h = bar.get_height()
                if h > 0:
                    ax.text(bar.get_x() + bar.get_width() / 2, h + 0.5,
                            f"{h:.0f}", ha='center', va='bottom', fontsize=7)

            ax.set_xticks(x)
            ax.set_xticklabels([c.replace(" ", "\n") for c in categories_order],
                               fontsize=8)
            ax.set_ylabel("Temps moyen (ms)")
            ax.set_title(f"{proto}\n{SCENARIOS[scen]['label']}", fontsize=9)
            if col == 0 and row == 0:
                ax.legend(fontsize=7)

    plt.tight_layout()
    # Nom déjà correct dans la version originale — on garde
    save(fig, out_dir, "fig10_category_summary_hqc")


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Phase 6 HQC — figures conditions africaines (version corrigée)"
    )
    parser.add_argument("--data-dir", required=True,
                        help="Chemin vers 6- hqc/")
    parser.add_argument("--out-dir",  required=True,
                        help="Dossier de sortie pour les plots")
    args = parser.parse_args()

    print("\n" + "="*60)
    print("GÉNÉRATION DES PLOTS HQC — CONDITIONS AFRICAINES (corrigé)")
    print(f"Données : {args.data_dir}")
    print(f"Sortie  : {args.out_dir}")
    print("="*60)
    print("\nCorrections actives :")
    print("  [C1] Suffixe _hqc sur fig6, fig7, fig9")
    print("  [C2] Fig9 x_max dynamique (plus de troncature hqc192/hqc256)")
    print("  [C3] Fig7 structure 3x2 alignée Phase 5 (L1+L3+L5)\n")

    data = load_all(args.data_dir)

    loaded = [(p, sc) for p in data
              for sc in data[p] if data[p][sc]]
    print(f"✅ {len(loaded)} groupes chargés")
    for proto in ["TLS","QUIC"]:
        for scen in SCENARIOS:
            sigs = list(data[proto][scen].keys())
            if sigs:
                print(f"   {proto:4s} | {scen:20s} | {len(sigs)} signatures")

    fig6_delta_evolution(data, args.out_dir)
    fig7_tls_quic_reversal(data, args.out_dir)
    fig8_deployment_heatmap(data, args.out_dir)
    fig9_ideal_vs_degraded(data, args.out_dir)
    fig10_category_summary(data, args.out_dir)

    print("\n" + "="*60)
    print(f"✅ 5 figures générées dans : {args.out_dir}")
    print("  fig6_delta_evolution_hqc.png")
    print("  fig7_tls_quic_reversal_hqc.png")
    print("  fig8_deployment_heatmap_hqc.png")
    print("  fig9_ideal_vs_degraded_hqc.png")
    print("  fig10_category_summary_hqc.png")
    print("="*60 + "\n")


if __name__ == "__main__":
    main()
