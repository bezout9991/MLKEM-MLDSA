#!/usr/bin/env python3
"""
plot_africa_scenarios_v2.py — version corrigée
Figures 6-9 pour conditions réseau africaines
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
KEM_COLORS  = {"classique":"#2E75B6","hybride":"#BF9000","PQ pur":"#C55A11"}
KEM_MARKERS = {"classique":"o","hybride":"s","PQ pur":"^"}
SIG_PQ      = {"mldsa44","mldsa65","mldsa87"}
SIG_CLASSIC = {"ed25519","secp384r1","secp521r1"}

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

# ── Figure 6 : Évolution Δ% ML-DSA vs classique ──────────────────────────────
def fig6_delta_evolution(data, out_dir):
    # 3 lignes (niveaux L1/L3/L5) × 2 colonnes (TLS/QUIC)
    fig, axes = plt.subplots(3, 2, figsize=(16, 14))
    fig.suptitle(
        "Figure 6 — Évolution du surcoût ML-DSA vs signature classique\n"
        "selon le scénario réseau | Δ% négatif = ML-DSA plus rapide",
        fontsize=13, fontweight='bold', y=0.98
    )

    x_pos = np.arange(len(SCEN_ORDER))

    for row, (sig_c, sig_pq, level) in enumerate(SIG_PAIRS):
        for col, proto in enumerate(["TLS","QUIC"]):
            ax = axes[row][col]
            kems = KEMS_L[level]

            ax.axhline(y=0, color='black', lw=1.5, ls='--', alpha=0.7)
            ax.axhspan(-200, 0,   alpha=0.04, color='green')
            ax.axhspan(0,   200,  alpha=0.04, color='red')

            for kem in kems:
                deltas = []
                for scen in SCEN_ORDER:
                    try:
                        mc = np.mean(data[proto][scen][sig_c][kem])
                        mp = np.mean(data[proto][scen][sig_pq][kem])
                        deltas.append(((mp - mc) / mc) * 100)
                    except KeyError:
                        deltas.append(np.nan)

                kt     = KEM_TYPE.get(kem,"?")
                color  = KEM_COLORS.get(kt,"gray")
                marker = KEM_MARKERS.get(kt,"o")
                valid  = [(x_pos[i], d) for i,d in enumerate(deltas)
                          if not np.isnan(d)]
                if not valid:
                    continue
                vx, vd = zip(*valid)
                ax.plot(vx, vd, color=color, marker=marker,
                        lw=1.5, ms=6, alpha=0.85, label=kem)
                ax.annotate(kem, (vx[-1], vd[-1]), fontsize=6,
                            xytext=(3,0), textcoords='offset points',
                            color=color)

            ax.set_xticks(x_pos)
            ax.set_xticklabels(SCEN_LABELS, fontsize=8)
            ax.set_ylabel("Δ% (ML-DSA vs Classique)")
            ax.set_title(f"{proto} — L{level} ({sig_c} vs {sig_pq})",
                         fontweight='bold')
            for xv in [0.5, 1.5, 2.5]:
                ax.axvline(x=xv, color='gray', lw=0.6, ls=':', alpha=0.5)

            ax.legend(handles=[
                mpatches.Patch(color=KEM_COLORS["classique"], label='KEM classique'),
                mpatches.Patch(color=KEM_COLORS["hybride"],   label='KEM hybride'),
                mpatches.Patch(color=KEM_COLORS["PQ pur"],    label='KEM PQ pur'),
                plt.Line2D([0],[0], color='black', ls='--', label='Parité Δ=0'),
            ], fontsize=7, loc='upper left')

    fig.text(0.5, 0.01,
             "Zone verte = ML-DSA plus rapide | Zone rouge = ML-DSA plus lent",
             ha='center', fontsize=10, style='italic', color='gray')
    plt.tight_layout(rect=[0, 0.02, 1, 0.96])
    path = os.path.join(out_dir, "fig6_delta_evolution.pdf")
    plt.savefig(path, bbox_inches='tight')
    plt.savefig(path.replace('.pdf','.png'), bbox_inches='tight', dpi=150)
    plt.close()
    print(f"✅ Fig6 sauvegardée : {path}")

# ── Figure 7 : Renversement TLS vs QUIC ──────────────────────────────────────
def fig7_tls_quic_reversal(data, out_dir):
    # 4 subplots : ed25519 L1 | mldsa44 L1 | secp384r1 L3 | mldsa65 L3
    plot_combos = [
        ("ed25519",   1, (0,0)),
        ("mldsa44",   1, (0,1)),
        ("secp384r1", 3, (1,0)),
        ("mldsa65",   3, (1,1)),
    ]

    fig, axes = plt.subplots(2, 2, figsize=(16, 12))
    fig.suptitle(
        "Figure 7 — Renversement de l'avantage QUIC sous conditions africaines\n"
        "TLS vs QUIC (%) | Positif = TLS plus lent | Négatif = TLS plus rapide",
        fontsize=13, fontweight='bold', y=0.98
    )

    x_pos = np.arange(len(SCEN_ORDER))

    for sig, level, (r, c) in plot_combos:
        ax = axes[r][c]
        kems = KEMS_L[level]
        sig_type = "ML-DSA" if sig in SIG_PQ else "Classique"

        ax.axhline(y=0, color='black', lw=1.5, ls='--', alpha=0.7)
        ax.axhspan(-400, 0,   alpha=0.04, color='blue')
        ax.axhspan(0,    400, alpha=0.04, color='red')

        for kem in kems:
            diffs = []
            for scen in SCEN_ORDER:
                try:
                    mt = np.mean(data["TLS"][scen][sig][kem])
                    mq = np.mean(data["QUIC"][scen][sig][kem])
                    diffs.append(((mt - mq) / mq) * 100)
                except KeyError:
                    diffs.append(np.nan)

            kt     = KEM_TYPE.get(kem,"?")
            color  = KEM_COLORS.get(kt,"gray")
            marker = KEM_MARKERS.get(kt,"o")
            valid  = [(x_pos[i], d) for i,d in enumerate(diffs)
                      if not np.isnan(d)]
            if not valid:
                continue
            vx, vd = zip(*valid)
            ax.plot(vx, vd, color=color, marker=marker,
                    lw=1.5, ms=6, alpha=0.85, label=kem)
            ax.annotate(kem, (vx[-1], vd[-1]), fontsize=6,
                        xytext=(3,0), textcoords='offset points',
                        color=color)

        ax.set_xticks(x_pos)
        ax.set_xticklabels(SCEN_LABELS, fontsize=8)
        ax.set_ylabel("(TLS − QUIC) / QUIC × 100 (%)")
        ax.set_title(f"L{level} | Sig: {sig} ({sig_type})",
                     fontweight='bold')
        for xv in [0.5, 1.5, 2.5]:
            ax.axvline(x=xv, color='gray', lw=0.6, ls=':', alpha=0.5)

        ax.legend(handles=[
            mpatches.Patch(color=KEM_COLORS["classique"], label='KEM classique'),
            mpatches.Patch(color=KEM_COLORS["hybride"],   label='KEM hybride'),
            mpatches.Patch(color=KEM_COLORS["PQ pur"],    label='KEM PQ pur'),
            mpatches.Patch(color='blue', alpha=0.3, label='TLS meilleur'),
            mpatches.Patch(color='red',  alpha=0.3, label='QUIC meilleur'),
        ], fontsize=7, loc='upper left')

    plt.tight_layout(rect=[0, 0, 1, 0.96])
    path = os.path.join(out_dir, "fig7_tls_quic_reversal.pdf")
    plt.savefig(path, bbox_inches='tight')
    plt.savefig(path.replace('.pdf','.png'), bbox_inches='tight', dpi=150)
    plt.close()
    print(f"✅ Fig7 sauvegardée : {path}")

# ── Figure 8 : Heatmap déploiement ───────────────────────────────────────────
def fig8_deployment_heatmap(data, out_dir):
    combos = []
    for sig_c, sig_pq, level in SIG_PAIRS:
        for sig in [sig_c, sig_pq]:
            st = "PQ" if sig in SIG_PQ else "Cls"
            for kem in KEMS_L[level]:
                kt = KEM_TYPE.get(kem,"?")[:3]
                combos.append((sig, kem,
                               f"{sig[:6]}+{kem[:8]}\n({st}/{kt})"))

    fig, axes = plt.subplots(1, 2, figsize=(20, 14))
    fig.suptitle(
        "Figure 8 — Heatmap des temps moyens (ms) par combinaison et scénario réseau\n"
        "Échelle logarithmique | Rouge foncé = lent | Jaune clair = rapide",
        fontsize=13, fontweight='bold'
    )

    for col, proto in enumerate(["TLS","QUIC"]):
        ax = axes[col]
        mat = np.full((len(combos), len(SCEN_ORDER)), np.nan)

        for ri, (sig, kem, _) in enumerate(combos):
            for ci, scen in enumerate(SCEN_ORDER):
                try:
                    mat[ri, ci] = np.mean(data[proto][scen][sig][kem])
                except KeyError:
                    pass

        mat_log = np.log10(np.where(mat > 0, mat, np.nan))
        im = ax.imshow(mat_log, cmap='YlOrRd', aspect='auto',
                       vmin=0, vmax=np.nanmax(mat_log))

        ax.set_xticks(range(len(SCEN_ORDER)))
        ax.set_xticklabels(SCEN_LABELS, fontsize=9)
        ax.set_yticks(range(len(combos)))
        ax.set_yticklabels([c[2] for c in combos], fontsize=7)
        ax.set_title(f"{proto}", fontweight='bold')
        ax.grid(False)

        for ri in range(mat.shape[0]):
            for ci in range(mat.shape[1]):
                val = mat[ri, ci]
                if not np.isnan(val):
                    lv = mat_log[ri, ci]
                    tc = 'white' if lv > np.nanmax(mat_log)*0.7 else 'black'
                    ax.text(ci, ri,
                            f"{val:.0f}" if val >= 10 else f"{val:.1f}",
                            ha='center', va='center',
                            fontsize=6, color=tc)

        for b in [10, 20]:
            if b < len(combos):
                ax.axhline(y=b-0.5, color='white', lw=2)

        cbar = plt.colorbar(im, ax=ax, shrink=0.8)
        cbar.set_label("log₁₀(ms)", fontsize=9)
        cbar.set_ticks([0, 1, 2, 3])
        cbar.set_ticklabels(['1ms','10ms','100ms','1000ms'])

    plt.tight_layout()
    path = os.path.join(out_dir, "fig8_deployment_heatmap.pdf")
    plt.savefig(path, bbox_inches='tight')
    plt.savefig(path.replace('.pdf','.png'), bbox_inches='tight', dpi=150)
    plt.close()
    print(f"✅ Fig8 sauvegardée : {path}")

# ── Figure 9 : Scatter idéal vs dégradé ──────────────────────────────────────
def fig9_ideal_vs_degraded(data, out_dir):
    fig, axes = plt.subplots(1, 2, figsize=(16, 7))
    fig.suptitle(
        "Figure 9 — Impact de la dégradation : Idéal vs Dégradé (200ms/10%)\n"
        "Points proches de la diagonale = combinaison résistante à la dégradation",
        fontsize=13, fontweight='bold'
    )

    for col, proto in enumerate(["TLS","QUIC"]):
        ax = axes[col]
        all_vals = []

        for sig_c, sig_pq, level in SIG_PAIRS:
            for sig in [sig_c, sig_pq]:
                marker = 's' if sig in SIG_PQ else 'o'
                for kem in KEMS_L[level]:
                    try:
                        ideal  = np.mean(data[proto]["ideal"][sig][kem])
                        degrad = np.mean(data[proto]["africa_degraded"][sig][kem])
                    except KeyError:
                        continue
                    all_vals.extend([ideal, degrad])
                    kt    = KEM_TYPE.get(kem,"?")
                    color = KEM_COLORS.get(kt,"gray")
                    ax.scatter(ideal, degrad, c=color, marker=marker,
                               s=80, alpha=0.8, edgecolors='black',
                               linewidth=0.5, zorder=5)
                    ax.annotate(f"{kem}\n({sig[:5]})",
                                (ideal, degrad), fontsize=5,
                                xytext=(3,3), textcoords='offset points',
                                color=color)

        if all_vals:
            x_max = min(150, max(all_vals)*0.15)
            y_max = max(all_vals)*1.05
            ax.plot([0, x_max], [0, x_max * y_max/x_max],
                    'k--', alpha=0.2, lw=1)
            ax.set_xlim(0, x_max)
            ax.set_ylim(0, y_max)

        ax.set_xlabel("Temps idéal (ms)")
        ax.set_ylabel("Temps dégradé 200ms/10% (ms)")
        ax.set_title(f"{proto}", fontweight='bold')
        ax.legend(handles=[
            mpatches.Patch(color=KEM_COLORS["classique"], label='KEM classique'),
            mpatches.Patch(color=KEM_COLORS["hybride"],   label='KEM hybride'),
            mpatches.Patch(color=KEM_COLORS["PQ pur"],    label='KEM PQ pur'),
            plt.Line2D([0],[0],marker='o',color='gray',ls='',ms=7,
                       alpha=0.6,label='Sig classique'),
            plt.Line2D([0],[0],marker='s',color='gray',ls='',ms=7,
                       label='Sig ML-DSA'),
        ], fontsize=7, loc='upper left')

    plt.tight_layout()
    path = os.path.join(out_dir, "fig9_ideal_vs_degraded.pdf")
    plt.savefig(path, bbox_inches='tight')
    plt.savefig(path.replace('.pdf','.png'), bbox_inches='tight', dpi=150)
    plt.close()
    print(f"✅ Fig9 sauvegardée : {path}")

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", required=True)
    parser.add_argument("--out-dir",  default=None)
    args = parser.parse_args()

    out_dir = args.out_dir or os.path.join(args.data_dir, "plots")
    os.makedirs(out_dir, exist_ok=True)

    print(f"\n{'='*60}")
    print("Génération Fig6–9 — Conditions africaines")
    print(f"Données : {args.data_dir}")
    print(f"Sorties : {out_dir}")
    print(f"{'='*60}\n")

    data = load_all(args.data_dir)
    print(f"✅ {sum(len(data[p][s]) for p in data for s in data[p])} "
          f"groupes CSV chargés\n")

    fig6_delta_evolution(data, out_dir)
    fig7_tls_quic_reversal(data, out_dir)
    fig8_deployment_heatmap(data, out_dir)
    fig9_ideal_vs_degraded(data, out_dir)

    print(f"\n{'='*60}")
    print(f"✅ Figures 6–9 sauvegardées dans : {out_dir}")
    print(f"{'='*60}\n")

if __name__ == "__main__":
    main()
