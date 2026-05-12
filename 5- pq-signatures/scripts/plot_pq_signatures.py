#!/usr/bin/env python3
"""
plot_pq_signatures_final.py
============================
Génération complète des 5 figures pour le papier PQ Signatures.

Usage:
    python3 plot_pq_signatures_final.py \
        --data-dir ~/Documents/TLS-QUIC/5- pq-signatures/ \
        --out-dir  ~/Documents/TLS-QUIC/5- pq-signatures/plots/
"""

import os
import argparse
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

# ── Palette ───────────────────────────────────────────────────────────────────
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

# ── Constantes ────────────────────────────────────────────────────────────────
SIG_LEVEL = {
    "ed25519":1,"secp384r1":3,"secp521r1":5,
    "mldsa44":1,"mldsa65":3,"mldsa87":5
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
    data = {}
    for proto in ["TLS","QUIC"]:
        data[proto] = {}
        for sig in SIG_LEVEL:
            path = os.path.join(data_dir, proto.upper(), "csv",
                                f"{sig}_{proto.lower()}_ideal.csv")
            if not os.path.isfile(path):
                continue
            df = pd.read_csv(path)
            data[proto][sig] = {
                kem: df[kem].dropna().astype(float).values
                for kem in df.columns
            }
    return data

# ── Figure 1 : Violin comparatif sig classique vs ML-DSA ─────────────────────
def fig1_violin_comparison(data, out_dir):
    fig, axes = plt.subplots(3, 2, figsize=(16, 14))
    fig.suptitle(
        "Figure 1 — Comparaison signatures classiques vs ML-DSA\n"
        "Distributions des temps de handshake (500 runs, conditions idéales)",
        fontsize=13, fontweight='bold', y=0.98
    )

    for row, (sig_c, sig_pq, level) in enumerate(SIG_PAIRS):
        kems = KEMS_L[level]
        for col, proto in enumerate(["TLS","QUIC"]):
            ax = axes[row][col]
            if sig_c not in data[proto] or sig_pq not in data[proto]:
                ax.set_visible(False)
                continue

            positions_c, positions_pq = [], []
            vals_c, vals_pq, labels   = [], [], []
            x = 1
            spacing = 3

            for kem in kems:
                if kem not in data[proto][sig_c]:
                    continue
                if kem not in data[proto][sig_pq]:
                    continue
                arr_c  = data[proto][sig_c][kem]
                arr_pq = data[proto][sig_pq][kem]
                cap = np.percentile(np.concatenate([arr_c, arr_pq]), 99)
                vals_c.append(np.clip(arr_c, 0, cap))
                vals_pq.append(np.clip(arr_pq, 0, cap))
                positions_c.append(x)
                positions_pq.append(x + 1)
                labels.append(kem)
                x += spacing

            if not vals_c:
                continue

            color_c  = COLORS["classic_tls"]  if proto == "TLS" else COLORS["classic_quic"]
            color_pq = COLORS["pq_tls"]        if proto == "TLS" else COLORS["pq_quic"]

            vp_c = ax.violinplot(vals_c, positions=positions_c,
                                 showmedians=True, widths=0.8)
            vp_pq = ax.violinplot(vals_pq, positions=positions_pq,
                                  showmedians=True, widths=0.8)

            for pc in vp_c['bodies']:
                pc.set_facecolor(color_c); pc.set_alpha(0.6)
            for part in ['cmedians','cmins','cmaxes','cbars']:
                vp_c[part].set_color(color_c)

            for pc in vp_pq['bodies']:
                pc.set_facecolor(color_pq); pc.set_alpha(0.6)
            for part in ['cmedians','cmins','cmaxes','cbars']:
                vp_pq[part].set_color(color_pq)

            tick_pos = [(p+p2)/2 for p,p2 in zip(positions_c, positions_pq)]
            ax.set_xticks(tick_pos)
            ax.set_xticklabels(labels, rotation=30, ha='right', fontsize=8)
            ax.set_ylabel("Temps (ms)")
            ax.set_title(f"{proto} — L{level} ({sig_c} vs {sig_pq})")
            ax.legend(handles=[
                mpatches.Patch(color=color_c,  alpha=0.6, label=sig_c),
                mpatches.Patch(color=color_pq, alpha=0.6, label=sig_pq),
            ], loc='upper left', framealpha=0.8)

    plt.tight_layout(rect=[0, 0, 1, 0.96])
    path = os.path.join(out_dir, "fig1_violin_sig_comparison.pdf")
    plt.savefig(path, bbox_inches='tight')
    plt.savefig(path.replace('.pdf','.png'), bbox_inches='tight', dpi=150)
    plt.close()
    print(f"✅ Fig1 sauvegardée : {path}")

# ── Figure 2 : Heatmap surcoût ML-DSA ────────────────────────────────────────
def fig2_heatmap_overhead(data, out_dir):
    # Liste ordonnée de tous les KEMs
    all_kems = []
    for _, _, level in SIG_PAIRS:
        for kem in KEMS_L[level]:
            if kem not in all_kems:
                all_kems.append(kem)

    row_labels = [f"L{lvl}: {sc}→{sp}" for sc, sp, lvl in SIG_PAIRS]

    fig, axes = plt.subplots(1, 2, figsize=(18, 5))
    fig.suptitle(
        "Figure 2 — Surcoût ML-DSA vs signature classique (Δ%)\n"
        "Vert = ML-DSA plus rapide | Rouge = ML-DSA plus lent",
        fontsize=13, fontweight='bold'
    )

    for col, proto in enumerate(["TLS","QUIC"]):
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

        vmax = np.nanmax(np.abs(mat))
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
    path = os.path.join(out_dir, "fig2_heatmap_overhead.pdf")
    plt.savefig(path, bbox_inches='tight')
    plt.savefig(path.replace('.pdf','.png'), bbox_inches='tight', dpi=150)
    plt.close()
    print(f"✅ Fig2 sauvegardée : {path}")

# ── Figure 3 : Super-additivité ───────────────────────────────────────────────
def fig3_superadditivity(data, out_dir):
    kem_pairs = {
        1: [("P-256","mlkem512"),("x25519","mlkem512"),
            ("P-256","p256_mlkem512"),("x25519","x25519_mlkem512")],
        3: [("P-384","mlkem768"),("x448","mlkem768"),
            ("P-384","p384_mlkem768"),("x448","x448_mlkem768")],
        5: [("P-521","mlkem1024"),("P-521","p521_mlkem1024")],
    }

    fig, axes = plt.subplots(1, 2, figsize=(16, 8))
    fig.suptitle(
        "Figure 3 — Super-additivité : ratio surcoût réel / surcoût attendu\n"
        "Ratio > 1.05 = super-additif | 0.95–1.05 = additif | < 0.95 = sous-additif",
        fontsize=13, fontweight='bold'
    )

    for col, proto in enumerate(["TLS","QUIC"]):
        ax = axes[col]
        labels, ratios, bar_colors = [], [], []

        for sig_c, sig_pq, level in SIG_PAIRS:
            for kem_c, kem_pq in kem_pairs.get(level, []):
                try:
                    baseline   = np.mean(data[proto][sig_c][kem_c])
                    sig_c_kpq  = np.mean(data[proto][sig_c][kem_pq])
                    sig_pq_kc  = np.mean(data[proto][sig_pq][kem_c])
                    sig_pq_kpq = np.mean(data[proto][sig_pq][kem_pq])
                except KeyError:
                    continue
                oh_sum  = (sig_c_kpq - baseline) + (sig_pq_kc - baseline)
                oh_both = sig_pq_kpq - baseline
                if oh_sum == 0:
                    continue
                ratio = oh_both / oh_sum
                labels.append(f"L{level} | {sig_c[:6]}→{sig_pq[:6]}\n{kem_c}→{kem_pq}")
                ratios.append(ratio)
                bar_colors.append(
                    '#C55A11' if ratio > 1.05 else
                    '#375623' if ratio < 0.95 else
                    '#BF9000'
                )

        y_pos = np.arange(len(labels))
        ax.barh(y_pos, ratios, color=bar_colors, alpha=0.85, edgecolor='white')
        ax.axvline(1.0,  color='black',   lw=1.5, ls='--', label='Additif')
        ax.axvline(1.05, color='#C55A11', lw=1,   ls=':', alpha=0.7)
        ax.axvline(0.95, color='#375623', lw=1,   ls=':', alpha=0.7)
        ax.set_yticks(y_pos)
        ax.set_yticklabels(labels, fontsize=7)
        ax.set_xlabel("Ratio surcoût réel / attendu")
        ax.set_title(f"{proto}", fontweight='bold')
        for i, r in enumerate(ratios):
            ax.text(r + 0.03, i, f"{r:.2f}", va='center', fontsize=7)
        ax.legend(handles=[
            mpatches.Patch(color='#C55A11', alpha=0.85, label='Super-additif (>1.05)'),
            mpatches.Patch(color='#BF9000', alpha=0.85, label='Additif (0.95–1.05)'),
            mpatches.Patch(color='#375623', alpha=0.85, label='Sous-additif (<0.95)'),
        ], fontsize=8, loc='lower right')

    plt.tight_layout()
    path = os.path.join(out_dir, "fig3_superadditivity.pdf")
    plt.savefig(path, bbox_inches='tight')
    plt.savefig(path.replace('.pdf','.png'), bbox_inches='tight', dpi=150)
    plt.close()
    print(f"✅ Fig3 sauvegardée : {path}")

# ── Figure 4 : Scatter TLS vs QUIC ───────────────────────────────────────────
def fig4_tls_vs_quic_scatter(data, out_dir):
    fig, axes = plt.subplots(1, 3, figsize=(18, 7))
    fig.suptitle(
        "Figure 4 — TLS vs QUIC : temps moyen par combinaison Signature × KEM\n"
        "Points au-dessus de la diagonale = TLS plus lent que QUIC",
        fontsize=13, fontweight='bold'
    )

    for col, (sig_c, sig_pq, level) in enumerate(SIG_PAIRS):
        ax = axes[col]
        kems = KEMS_L[level]
        all_vals = []

        for sig, marker, alpha in [(sig_c,'o',0.6),(sig_pq,'s',1.0)]:
            for kem in kems:
                try:
                    tls_mean  = np.mean(data["TLS"][sig][kem])
                    quic_mean = np.mean(data["QUIC"][sig][kem])
                except KeyError:
                    continue
                all_vals.extend([tls_mean, quic_mean])
                kt = KEM_TYPE.get(kem,"?")
                color = (COLORS["classique"] if kt=="classique" else
                         COLORS["hybride"]   if kt=="hybride"   else
                         COLORS["pq_pur"])
                ax.scatter(quic_mean, tls_mean, c=color, marker=marker,
                           s=90, alpha=alpha, edgecolors='black',
                           linewidth=0.5, zorder=5)
                ax.annotate(f"{kem}\n({sig[:5]})", (quic_mean, tls_mean),
                            fontsize=6, xytext=(3,3),
                            textcoords='offset points')

        if all_vals:
            vmax = max(all_vals) * 1.1
            ax.plot([0,vmax],[0,vmax],'k--',alpha=0.4,lw=1,label='TLS=QUIC')
            ax.set_xlim(0,vmax); ax.set_ylim(0,vmax)

        ax.set_xlabel("QUIC — temps moyen (ms)")
        ax.set_ylabel("TLS — temps moyen (ms)")
        ax.set_title(f"Niveau L{level} | {sig_c} vs {sig_pq}", fontweight='bold')
        ax.legend(handles=[
            mpatches.Patch(color=COLORS["classique"], label='KEM classique'),
            mpatches.Patch(color=COLORS["hybride"],   label='KEM hybride'),
            mpatches.Patch(color=COLORS["pq_pur"],    label='KEM PQ pur'),
            plt.Line2D([0],[0],marker='o',color='gray',ls='',ms=7,
                       alpha=0.6,label=sig_c),
            plt.Line2D([0],[0],marker='s',color='gray',ls='',ms=7,
                       label=sig_pq),
        ], fontsize=7, loc='upper left')

    plt.tight_layout()
    path = os.path.join(out_dir, "fig4_tls_vs_quic_scatter.pdf")
    plt.savefig(path, bbox_inches='tight')
    plt.savefig(path.replace('.pdf','.png'), bbox_inches='tight', dpi=150)
    plt.close()
    print(f"✅ Fig4 sauvegardée : {path}")

# ── Figure 5 : Résumé par catégorie ──────────────────────────────────────────
def fig5_category_summary(data, out_dir):
    categories = [
        ("Sig class.\nKEM class.",  "classique", "classique"),
        ("Sig class.\nKEM hybride", "classique", "hybride"),
        ("Sig class.\nKEM PQ pur",  "classique", "PQ pur"),
        ("Sig PQ\nKEM class.",      "pq",        "classique"),
        ("Sig PQ\nKEM hybride",     "pq",        "hybride"),
        ("Sig PQ\nKEM PQ pur",      "pq",        "PQ pur"),
    ]

    means_tls,  means_quic  = [], []
    errs_tls,   errs_quic   = [], []

    for _, sig_type, kem_type in categories:
        sig_set = SIG_PQ if sig_type == "pq" else SIG_CLASSIC
        for proto, mlist, elist in [("TLS",means_tls,errs_tls),
                                     ("QUIC",means_quic,errs_quic)]:
            vals = []
            for sig in sig_set:
                if sig not in data[proto]:
                    continue
                for kem, arr in data[proto][sig].items():
                    if KEM_TYPE.get(kem,"?") == kem_type:
                        vals.extend(arr.tolist())
            mlist.append(np.mean(vals) if vals else 0)
            elist.append(np.std(vals)/np.sqrt(len(vals)) if vals else 0)

    x = np.arange(len(categories))
    width = 0.35
    cat_labels = [c[0] for c in categories]

    fig, ax = plt.subplots(figsize=(14, 7))
    b1 = ax.bar(x - width/2, means_tls,  width, yerr=errs_tls,
                color=COLORS["classic_tls"],  alpha=0.85, capsize=4,
                label='TLS', edgecolor='white')
    b2 = ax.bar(x + width/2, means_quic, width, yerr=errs_quic,
                color=COLORS["classic_quic"], alpha=0.85, capsize=4,
                label='QUIC', edgecolor='white')

    # Hachures pour les catégories PQ
    for i, (_, sig_type, _) in enumerate(categories):
        if sig_type == "pq":
            b1.patches[i].set_hatch('//')
            b2.patches[i].set_hatch('//')

    ax.set_xticks(x)
    ax.set_xticklabels(cat_labels, fontsize=9)
    ax.set_ylabel("Temps moyen de handshake (ms)")
    ax.set_title(
        "Figure 5 — Temps moyen par catégorie (Signature × KEM × Protocole)\n"
        "Barres hachurées = Signature ML-DSA",
        fontweight='bold', fontsize=12
    )
    ax.legend(fontsize=10)

    for bar in list(b1.patches) + list(b2.patches):
        h = bar.get_height()
        if h > 0.5:
            ax.text(bar.get_x() + bar.get_width()/2., h + 0.3,
                    f'{h:.1f}', ha='center', va='bottom', fontsize=7)

    plt.tight_layout()
    path = os.path.join(out_dir, "fig5_category_summary.pdf")
    plt.savefig(path, bbox_inches='tight')
    plt.savefig(path.replace('.pdf','.png'), bbox_inches='tight', dpi=150)
    plt.close()
    print(f"✅ Fig5 sauvegardée : {path}")

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", required=True)
    parser.add_argument("--out-dir",  default=None)
    args = parser.parse_args()

    out_dir = args.out_dir or os.path.join(args.data_dir, "plots")
    os.makedirs(out_dir, exist_ok=True)

    print(f"\n{'='*60}")
    print("Génération des 5 figures — PQ Signatures (final)")
    print(f"Données : {args.data_dir}")
    print(f"Sorties : {out_dir}")
    print(f"{'='*60}\n")

    data = load_all(args.data_dir)
    print(f"✅ {sum(len(data[p]) for p in data)} fichiers CSV chargés\n")

    fig1_violin_comparison(data, out_dir)
    fig2_heatmap_overhead(data, out_dir)
    fig3_superadditivity(data, out_dir)
    fig4_tls_vs_quic_scatter(data, out_dir)
    fig5_category_summary(data, out_dir)

    print(f"\n{'='*60}")
    print(f"✅ 5 figures (PDF + PNG) sauvegardées dans : {out_dir}")
    print(f"{'='*60}\n")

if __name__ == "__main__":
    main()
