#!/usr/bin/env python3
"""
plot_hqc_ideal.py
==================
Génération complète des figures conditions idéales — Phase 6 HQC.
Même format exact que plot_pq_signatures_final.py (Phase 5).

Figures générées :
  fig1_violin_hqc_sig_comparison.png  — Violin sig. classique vs ML-DSA × KEMs HQC
  fig2_heatmap_overhead_hqc.png       — Heatmap surcoût ML-DSA vs classique
  fig3_tls_vs_quic_hqc_scatter.png    — Scatter TLS vs QUIC par combinaison
  fig4_sig_impact_hqc.png             — Barres Δ% ML-DSA vs classique par KEM
  fig5_ranking_hqc.png                — Classement global KEMs HQC par performance
  fig6_category_summary_hqc_ideal.png — Résumé par catégorie (sig × KEM × proto)

Usage:
    python3 plot_hqc_ideal.py \\
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
from scipy import stats as scipy_stats

# ── Palette identique Phase 5 ─────────────────────────────────────────────────
COLORS = {
    "classic_tls":  "#2E75B6",
    "pq_tls":       "#C55A11",
    "classic_quic": "#375623",
    "pq_quic":      "#7030A0",
    "hybride":      "#BF9000",
    "pq_pur":       "#C55A11",
    "classique":    "#2E75B6",
}

plt.rcParams.update({
    'font.family': 'DejaVu Sans', 'font.size': 10,
    'axes.titlesize': 11, 'axes.labelsize': 10,
    'xtick.labelsize': 9, 'ytick.labelsize': 9,
    'legend.fontsize': 9, 'figure.dpi': 150,
    'axes.grid': True, 'grid.alpha': 0.3,
    'axes.spines.top': False, 'axes.spines.right': False,
})

# ── Constantes Phase 6 HQC ────────────────────────────────────────────────────
SIG_PAIRS = [
    ("ed25519",   "mldsa44", 1),
    ("secp384r1", "mldsa65", 3),
    ("secp521r1", "mldsa87", 5),
]

# KEMs HQC par niveau — classiques + HQC purs + HQC hybrides
KEMS_L = {
    1: ["P-256", "x25519", "hqc128", "p256_hqc128", "x25519_hqc128"],
    3: ["P-384", "x448",   "hqc192", "p384_hqc192", "x448_hqc192"],
    5: ["P-521",           "hqc256", "p521_hqc256"],
}

KEM_TYPE = {
    "P-256":          "classique",
    "x25519":         "classique",
    "P-384":          "classique",
    "x448":           "classique",
    "P-521":          "classique",
    "hqc128":         "HQC pur",
    "hqc192":         "HQC pur",
    "hqc256":         "HQC pur",
    "p256_hqc128":    "HQC hybride",
    "x25519_hqc128":  "HQC hybride",
    "p384_hqc192":    "HQC hybride",
    "x448_hqc192":    "HQC hybride",
    "p521_hqc256":    "HQC hybride",
}

KEM_COLOR = {
    "classique":    "#2E75B6",
    "HQC pur":      "#C55A11",
    "HQC hybride":  "#BF9000",
}

SIG_CLASSIC = {"ed25519", "secp384r1", "secp521r1"}
SIG_PQ      = {"mldsa44", "mldsa65", "mldsa87"}

ALL_SIGS = {sig for pair in SIG_PAIRS for sig in (pair[0], pair[1])}

# ── Chargement ────────────────────────────────────────────────────────────────
def load_all(data_dir):
    data = {}
    for proto in ["TLS", "QUIC"]:
        data[proto] = {}
        csv_dir = os.path.join(data_dir, proto.upper(), "csv")
        if not os.path.isdir(csv_dir):
            csv_dir = os.path.join(data_dir, proto.lower(), "csv")
        if not os.path.isdir(csv_dir):
            print(f"⚠️  Répertoire introuvable : {csv_dir}")
            continue

        for sig in ALL_SIGS:
            candidates = [
                os.path.join(csv_dir, f"{sig}_{proto.lower()}_ideal.csv"),
                os.path.join(csv_dir, f"{sig}_{proto.upper()}_ideal.csv"),
                os.path.join(csv_dir, f"{sig}_ideal.csv"),
                os.path.join(csv_dir, f"{sig}_{proto.lower()}.csv"),
            ]
            path = None
            for c in candidates:
                if os.path.isfile(c):
                    path = c
                    break
            if path is None:
                print(f"  ⚠️  Fichier manquant : {proto}/{sig}")
                continue

            df = pd.read_csv(path)
            data[proto][sig] = {
                col: df[col].dropna().astype(float).values
                for col in df.columns
                if len(df[col].dropna()) > 0
            }
            n = len(data[proto][sig])
            print(f"  ✅ {proto}/{sig} — {n} KEMs ({os.path.basename(path)})")

    return data


# ═════════════════════════════════════════════════════════════════════════════
# FIGURE 1 — Violin comparatif sig. classique vs ML-DSA
# Identique Figure 1 Phase 5
# ═════════════════════════════════════════════════════════════════════════════
def fig1_violin_comparison(data, out_dir):
    fig, axes = plt.subplots(3, 2, figsize=(16, 14))
    fig.suptitle(
        "Figure 1 — Comparaison signatures classiques vs ML-DSA sur KEMs HQC\n"
        "Distributions des temps de handshake (500 runs, conditions idéales)",
        fontsize=13, fontweight='bold', y=0.98
    )

    for row, (sig_c, sig_pq, level) in enumerate(SIG_PAIRS):
        kems = KEMS_L[level]
        for col, proto in enumerate(["TLS", "QUIC"]):
            ax = axes[row][col]

            if sig_c not in data[proto] or sig_pq not in data[proto]:
                ax.set_visible(False)
                continue

            positions_c, positions_pq = [], []
            vals_c, vals_pq, labels   = [], [], []
            x = 1
            spacing = 3

            for kem in kems:
                if kem not in data[proto][sig_c] or kem not in data[proto][sig_pq]:
                    continue
                arr_c  = data[proto][sig_c][kem]
                arr_pq = data[proto][sig_pq][kem]
                cap = np.percentile(np.concatenate([arr_c, arr_pq]), 99)
                vals_c.append(np.clip(arr_c,  0, cap))
                vals_pq.append(np.clip(arr_pq, 0, cap))
                positions_c.append(x)
                positions_pq.append(x + 1)
                labels.append(kem)
                x += spacing

            if not vals_c:
                ax.set_visible(False)
                continue

            color_c  = COLORS["classic_tls"]  if proto == "TLS" else COLORS["classic_quic"]
            color_pq = COLORS["pq_tls"]        if proto == "TLS" else COLORS["pq_quic"]

            vp_c = ax.violinplot(vals_c,  positions=positions_c,  showmedians=True, widths=0.8)
            vp_pq= ax.violinplot(vals_pq, positions=positions_pq, showmedians=True, widths=0.8)

            for pc in vp_c['bodies']:
                pc.set_facecolor(color_c); pc.set_alpha(0.6)
            for part in ['cmedians','cmins','cmaxes','cbars']:
                vp_c[part].set_color(color_c)

            for pc in vp_pq['bodies']:
                pc.set_facecolor(color_pq); pc.set_alpha(0.6)
            for part in ['cmedians','cmins','cmaxes','cbars']:
                vp_pq[part].set_color(color_pq)

            tick_pos = [(p + p2) / 2 for p, p2 in zip(positions_c, positions_pq)]
            ax.set_xticks(tick_pos)
            ax.set_xticklabels(labels, rotation=30, ha='right', fontsize=8)
            ax.set_ylabel("Temps (ms)")
            ax.set_title(f"{proto} — L{level} ({sig_c} vs {sig_pq})")
            ax.legend(handles=[
                mpatches.Patch(color=color_c,  alpha=0.6, label=sig_c),
                mpatches.Patch(color=color_pq, alpha=0.6, label=sig_pq),
            ], loc='upper left', framealpha=0.8)

    plt.tight_layout(rect=[0, 0, 1, 0.96])
    _save(fig, out_dir, "fig1_violin_hqc_sig_comparison")


# ═════════════════════════════════════════════════════════════════════════════
# FIGURE 2 — Heatmap surcoût ML-DSA vs classique
# Identique Figure 2 Phase 5
# ═════════════════════════════════════════════════════════════════════════════
def fig2_heatmap_overhead(data, out_dir):
    all_kems = []
    for _, _, level in SIG_PAIRS:
        for kem in KEMS_L[level]:
            if kem not in all_kems:
                all_kems.append(kem)

    row_labels = [f"L{lvl}: {sc}→{sp}" for sc, sp, lvl in SIG_PAIRS]

    fig, axes = plt.subplots(1, 2, figsize=(18, 5))
    fig.suptitle(
        "Figure 2 — Surcoût ML-DSA vs signature classique sur KEMs HQC (Δ%)\n"
        "Vert = ML-DSA plus rapide | Rouge = ML-DSA plus lent",
        fontsize=13, fontweight='bold'
    )

    for col, proto in enumerate(["TLS", "QUIC"]):
        ax = axes[col]
        mat = np.full((len(SIG_PAIRS), len(all_kems)), np.nan)

        for ri, (sig_c, sig_pq, level) in enumerate(SIG_PAIRS):
            for kem in KEMS_L[level]:
                ci = all_kems.index(kem)
                try:
                    mean_c  = np.mean(data[proto][sig_c][kem])
                    mean_pq = np.mean(data[proto][sig_pq][kem])
                    mat[ri, ci] = ((mean_pq - mean_c) / mean_c) * 100
                except KeyError:
                    pass

        vmax = np.nanmax(np.abs(mat)) if not np.all(np.isnan(mat)) else 100
        im = ax.imshow(mat, cmap='RdYlGn_r', vmin=-vmax, vmax=vmax, aspect='auto')

        ax.set_xticks(range(len(all_kems)))
        ax.set_xticklabels(all_kems, rotation=45, ha='right', fontsize=8)
        ax.set_yticks(range(len(row_labels)))
        ax.set_yticklabels(row_labels, fontsize=9)
        ax.set_title(f"{proto}", fontweight='bold')
        ax.grid(False)

        for ri in range(mat.shape[0]):
            for ci in range(mat.shape[1]):
                val = mat[ri, ci]
                if not np.isnan(val):
                    txt_color = 'white' if abs(val) > vmax * 0.6 else 'black'
                    ax.text(ci, ri, f"{val:+.0f}%",
                            ha='center', va='center',
                            fontsize=8, color=txt_color, fontweight='bold')

        plt.colorbar(im, ax=ax, label="Δ% (ML-DSA vs classique)", shrink=0.8)

    plt.tight_layout()
    _save(fig, out_dir, "fig2_heatmap_overhead_hqc")


# ═════════════════════════════════════════════════════════════════════════════
# FIGURE 3 — Scatter TLS vs QUIC (même format Figure 4 Phase 5)
# ═════════════════════════════════════════════════════════════════════════════
def fig3_tls_vs_quic_scatter(data, out_dir):
    fig, axes = plt.subplots(1, 3, figsize=(18, 7))
    fig.suptitle(
        "Figure 3 — TLS vs QUIC : temps moyen par combinaison Signature × KEM HQC\n"
        "Points au-dessus de la diagonale = TLS plus lent que QUIC",
        fontsize=13, fontweight='bold'
    )

    for col, (sig_c, sig_pq, level) in enumerate(SIG_PAIRS):
        ax = axes[col]
        kems = KEMS_L[level]
        all_vals = []

        for sig, marker, alpha in [(sig_c, 'o', 0.6), (sig_pq, 's', 1.0)]:
            if sig not in data["TLS"] or sig not in data["QUIC"]:
                continue
            for kem in kems:
                try:
                    tls_mean  = np.mean(data["TLS"][sig][kem])
                    quic_mean = np.mean(data["QUIC"][sig][kem])
                except KeyError:
                    continue
                all_vals.extend([tls_mean, quic_mean])
                kt    = KEM_TYPE.get(kem, "classique")
                color = KEM_COLOR.get(kt, "#2E75B6")
                ax.scatter(quic_mean, tls_mean, c=color, marker=marker,
                           s=90, alpha=alpha, edgecolors='black',
                           linewidth=0.5, zorder=5)
                ax.annotate(f"{kem}\n({sig[:5]})", (quic_mean, tls_mean),
                            fontsize=6, xytext=(3, 3),
                            textcoords='offset points')

        if all_vals:
            vmax = max(all_vals) * 1.1
            ax.plot([0, vmax], [0, vmax], 'k--', alpha=0.4, lw=1, label='TLS=QUIC')
            ax.set_xlim(0, vmax)
            ax.set_ylim(0, vmax)

        ax.set_xlabel("QUIC — temps moyen (ms)")
        ax.set_ylabel("TLS — temps moyen (ms)")
        ax.set_title(f"Niveau L{level} | {sig_c} vs {sig_pq}", fontweight='bold')
        ax.legend(handles=[
            mpatches.Patch(color=KEM_COLOR["classique"],   label='KEM classique'),
            mpatches.Patch(color=KEM_COLOR["HQC hybride"], label='HQC hybride'),
            mpatches.Patch(color=KEM_COLOR["HQC pur"],     label='HQC pur'),
            plt.Line2D([0],[0], marker='o', color='gray', ls='', ms=7,
                       alpha=0.6, label=sig_c),
            plt.Line2D([0],[0], marker='s', color='gray', ls='', ms=7,
                       label=sig_pq),
        ], fontsize=7, loc='upper left')

    plt.tight_layout()
    _save(fig, out_dir, "fig3_tls_vs_quic_hqc_scatter")


# ═════════════════════════════════════════════════════════════════════════════
# FIGURE 4 — Impact signature : barres Δ% ML-DSA vs classique par KEM
# (même format que fig4 original Phase 6, mais recalculé proprement)
# ═════════════════════════════════════════════════════════════════════════════
def fig4_sig_impact(data, out_dir):
    fig, axes = plt.subplots(1, 3, figsize=(18, 6))
    fig.suptitle(
        "Figure 4 — Impact de la signature sur KEMs HQC : Δ% ML-DSA vs classique\n"
        "Δ% = (ML-DSA − Classique) / Classique × 100  |  Négatif = ML-DSA plus rapide",
        fontsize=13, fontweight='bold'
    )

    for col, (sig_c, sig_pq, level) in enumerate(SIG_PAIRS):
        ax = axes[col]
        kems = KEMS_L[level]

        kems_ok, deltas_tls, deltas_quic = [], [], []
        for kem in kems:
            try:
                m_tls_c  = np.mean(data["TLS"][sig_c][kem])
                m_tls_pq = np.mean(data["TLS"][sig_pq][kem])
                m_qui_c  = np.mean(data["QUIC"][sig_c][kem])
                m_qui_pq = np.mean(data["QUIC"][sig_pq][kem])
            except KeyError:
                continue
            kems_ok.append(kem)
            deltas_tls.append(((m_tls_pq - m_tls_c) / m_tls_c) * 100)
            deltas_quic.append(((m_qui_pq - m_qui_c) / m_qui_c) * 100)

        if not kems_ok:
            ax.set_visible(False)
            continue

        x    = np.arange(len(kems_ok))
        width= 0.35

        bars_tls  = ax.bar(x - width/2, deltas_tls,  width,
                           color=COLORS["classic_tls"],  alpha=0.85,
                           label='TLS', edgecolor='white')
        bars_quic = ax.bar(x + width/2, deltas_quic, width,
                           color=COLORS["classic_quic"], alpha=0.85,
                           label='QUIC', edgecolor='white')

        ax.axhline(0, color='black', lw=1.2, ls='--')

        # Colorer fond : vert si négatif (ML-DSA plus rapide)
        ymin, ymax = ax.get_ylim()
        ax.axhspan(ymin if ymin < 0 else 0, 0, alpha=0.05, color='green')
        ax.axhspan(0, ymax if ymax > 0 else 0, alpha=0.05, color='red')

        for bar in list(bars_tls) + list(bars_quic):
            h = bar.get_height()
            va = 'bottom' if h >= 0 else 'top'
            offset = 0.5 if h >= 0 else -0.5
            ax.text(bar.get_x() + bar.get_width()/2., h + offset,
                    f'{h:+.1f}%', ha='center', va=va, fontsize=7)

        ax.set_xticks(x)
        ax.set_xticklabels(kems_ok, rotation=30, ha='right', fontsize=8)
        ax.set_ylabel("Δ% ML-DSA vs Classique")
        ax.set_title(f"L{level} : {sig_c} → {sig_pq}", fontweight='bold')
        ax.legend(fontsize=8)

    plt.tight_layout()
    _save(fig, out_dir, "fig4_sig_impact_hqc")


# ═════════════════════════════════════════════════════════════════════════════
# FIGURE 5 — Classement global des KEMs HQC par performance
# (même format que fig5_ranking_hqc original)
# ═════════════════════════════════════════════════════════════════════════════
def fig5_ranking(data, out_dir):
    fig, axes = plt.subplots(1, 2, figsize=(14, 7))
    fig.suptitle(
        "Figure 5 — Classement des KEMs HQC par temps moyen de handshake\n"
        "Signature : ed25519 (L1), secp384r1 (L3), secp521r1 (L5)",
        fontsize=13, fontweight='bold'
    )

    for col, proto in enumerate(["TLS", "QUIC"]):
        ax = axes[col]
        means, labels, bar_colors = [], [], []

        for sig_c, _, level in SIG_PAIRS:
            if sig_c not in data[proto]:
                continue
            for kem in KEMS_L[level]:
                if kem not in data[proto][sig_c]:
                    continue
                m = np.mean(data[proto][sig_c][kem])
                means.append(m)
                labels.append(f"{kem} (L{level})")
                kt = KEM_TYPE.get(kem, "classique")
                bar_colors.append(KEM_COLOR.get(kt, "#2E75B6"))

        if not means:
            ax.set_visible(False)
            continue

        # Tri décroissant
        order  = np.argsort(means)[::-1]
        means  = [means[i]  for i in order]
        labels = [labels[i] for i in order]
        bar_colors = [bar_colors[i] for i in order]

        y_pos = np.arange(len(labels))
        ax.barh(y_pos, means, color=bar_colors, alpha=0.85, edgecolor='white')
        ax.set_yticks(y_pos)
        ax.set_yticklabels(labels, fontsize=8)
        ax.set_xlabel("Temps moyen de handshake (ms)")
        ax.set_title(f"{proto}", fontweight='bold')
        ax.invert_yaxis()

        for i, m in enumerate(means):
            ax.text(m + max(means)*0.01, i, f"{m:.1f} ms",
                    va='center', fontsize=7)

        ax.legend(handles=[
            mpatches.Patch(color=KEM_COLOR["classique"],   label='classique'),
            mpatches.Patch(color=KEM_COLOR["HQC pur"],     label='HQC pur'),
            mpatches.Patch(color=KEM_COLOR["HQC hybride"], label='HQC hybride'),
        ], fontsize=8, loc='lower right')

    plt.tight_layout()
    _save(fig, out_dir, "fig5_ranking_hqc")


# ═════════════════════════════════════════════════════════════════════════════
# FIGURE 6 — Résumé par catégorie (même format Figure 5 Phase 5)
# ═════════════════════════════════════════════════════════════════════════════
def fig6_category_summary(data, out_dir):
    categories = [
        ("Sig class.\nKEM class.",     "classique", "classique"),
        ("Sig class.\nHQC pur",        "classique", "HQC pur"),
        ("Sig class.\nHQC hybride",    "classique", "HQC hybride"),
        ("Sig PQ\nKEM class.",         "pq",        "classique"),
        ("Sig PQ\nHQC pur",            "pq",        "HQC pur"),
        ("Sig PQ\nHQC hybride",        "pq",        "HQC hybride"),
    ]

    means_tls, means_quic = [], []
    errs_tls,  errs_quic  = [], []

    for _, sig_type, kem_type in categories:
        sig_set = SIG_PQ if sig_type == "pq" else SIG_CLASSIC
        for proto, mlist, elist in [("TLS",  means_tls,  errs_tls),
                                     ("QUIC", means_quic, errs_quic)]:
            vals = []
            for sig in sig_set:
                if sig not in data[proto]:
                    continue
                for kem, arr in data[proto][sig].items():
                    if KEM_TYPE.get(kem, "?") == kem_type:
                        vals.extend(arr.tolist())
            if vals:
                mlist.append(np.mean(vals))
                elist.append(np.std(vals) / np.sqrt(len(vals)))
            else:
                mlist.append(0)
                elist.append(0)

    x     = np.arange(len(categories))
    width = 0.35
    cat_labels = [c[0] for c in categories]

    fig, ax = plt.subplots(figsize=(14, 7))
    b1 = ax.bar(x - width/2, means_tls,  width, yerr=errs_tls,
                color=COLORS["classic_tls"],  alpha=0.85, capsize=4,
                label='TLS', edgecolor='white')
    b2 = ax.bar(x + width/2, means_quic, width, yerr=errs_quic,
                color=COLORS["classic_quic"], alpha=0.85, capsize=4,
                label='QUIC', edgecolor='white')

    # Hachures pour les catégories PQ (même convention Phase 5)
    for i, (_, sig_type, _) in enumerate(categories):
        if sig_type == "pq":
            b1.patches[i].set_hatch('//')
            b2.patches[i].set_hatch('//')

    ax.set_xticks(x)
    ax.set_xticklabels(cat_labels, fontsize=9)
    ax.set_ylabel("Temps moyen de handshake (ms)")
    ax.set_title(
        "Figure 6 — Temps moyen par catégorie (Signature × KEM HQC × Protocole)\n"
        "Barres hachurées = Signature ML-DSA",
        fontweight='bold', fontsize=12
    )
    ax.legend(fontsize=10)

    for bar in list(b1.patches) + list(b2.patches):
        h = bar.get_height()
        if h > 0.5:
            ax.text(bar.get_x() + bar.get_width()/2., h + 0.5,
                    f'{h:.1f}', ha='center', va='bottom', fontsize=7)

    plt.tight_layout()
    _save(fig, out_dir, "fig6_category_summary_hqc_ideal")


# ── Utilitaire sauvegarde ─────────────────────────────────────────────────────
def _save(fig, out_dir, name):
    os.makedirs(out_dir, exist_ok=True)
    pdf_path = os.path.join(out_dir, f"{name}.pdf")
    png_path = os.path.join(out_dir, f"{name}.png")
    fig.savefig(pdf_path, bbox_inches='tight')
    fig.savefig(png_path, bbox_inches='tight', dpi=150)
    plt.close(fig)
    print(f"  ✅ {name}.png  /  {name}.pdf")


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Génère toutes les figures conditions idéales Phase 6 HQC"
    )
    parser.add_argument("--data-dir", required=True,
                        help="Répertoire racine Phase 6 (contient TLS/csv/ et QUIC/csv/)")
    parser.add_argument("--out-dir",  default=None,
                        help="Répertoire de sortie (défaut : data-dir/plots/)")
    parser.add_argument("--figs",     default="all",
                        help="Figures à générer : all, ou liste séparée par virgule ex: 1,2,5")
    args = parser.parse_args()

    out_dir = args.out_dir or os.path.join(args.data_dir, "plots")
    figs_to_run = set(range(1, 7)) if args.figs == "all" else \
                  {int(x) for x in args.figs.split(",")}

    print(f"\n{'='*60}")
    print("Phase 6 HQC — Figures conditions idéales")
    print(f"Données : {args.data_dir}")
    print(f"Sorties : {out_dir}")
    print(f"Figures : {sorted(figs_to_run)}")
    print(f"{'='*60}\n")

    data = load_all(args.data_dir)
    n = sum(len(data[p]) for p in data)
    if n == 0:
        print("❌ Aucune donnée chargée. Vérifier --data-dir.")
        return
    print(f"\n✅ {n} signatures chargées au total\n")
    print(f"{'─'*60}")

    dispatch = {
        1: fig1_violin_comparison,
        2: fig2_heatmap_overhead,
        3: fig3_tls_vs_quic_scatter,
        4: fig4_sig_impact,
        5: fig5_ranking,
        6: fig6_category_summary,
    }

    for num in sorted(figs_to_run):
        if num in dispatch:
            print(f"\n→ Figure {num}...")
            dispatch[num](data, out_dir)

    print(f"\n{'='*60}")
    print(f"✅ Terminé. {len(figs_to_run)} figure(s) dans : {out_dir}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
