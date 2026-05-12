#!/usr/bin/env python3
"""
plot_violins_phase6.py
=======================
Violin plots Phase 6 — ML-DSA × HQC
Format identique au script original Montenegro et al.

Structure attendue (identique Phase 5) :
    6- hqc/
    ├── TLS/
    │   ├── csv/   ← CSV lus ici
    │   │   ├── ed25519_tls_ideal.csv
    │   │   ├── mldsa44_tls_ideal.csv
    │   │   ├── ed25519_tls_africa_local.csv
    │   │   └── ...
    │   └── plots/ ← PDF + SVG écrits ici
    └── QUIC/
        ├── csv/
        └── plots/

Sortie :
    TLS/plots/{sig}_tls_{scenario}.pdf + .svg
    QUIC/plots/{sig}_quic_{scenario}.pdf + .svg

Usage :
    # Depuis 6- hqc/
    python3 scripts/plot_violins_phase6.py

    # Avec chemin explicite
    python3 scripts/plot_violins_phase6.py \\
        --data-dir ~/Documents/TLS-QUIC/'6- hqc'/

    # Tous les scénarios (idéal + africains)
    python3 scripts/plot_violins_phase6.py \\
        --data-dir ~/Documents/TLS-QUIC/'6- hqc'/ \\
        --scenarios all
"""

import os
import glob
import argparse
import warnings
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns


# ── Filtres outliers (identiques Montenegro) ──────────────────────────────────
def filtrar_valores_extremos(df_long, umbral_ms=1000):
    """Supprime les valeurs > umbral_ms."""
    return df_long[df_long["Duration"] < umbral_ms]


def filtrar_outliers_iqr(df_long):
    """Filtre IQR par KEM — optionnel, non activé par défaut."""
    filtrados = []
    for kem, grupo in df_long.groupby("KEM", observed=False):
        q1 = grupo["Duration"].quantile(0.25)
        q3 = grupo["Duration"].quantile(0.75)
        iqr = q3 - q1
        lower = q1 - 1.5 * iqr
        upper = q3 + 1.5 * iqr
        filtrados.append(
            grupo[(grupo["Duration"] >= lower) & (grupo["Duration"] <= upper)]
        )
    return pd.concat(filtrados)


# ── Violin pour un seul CSV ───────────────────────────────────────────────────
def plot_violin(csv_file, out_dir, use_iqr=False):
    warnings.filterwarnings("ignore", category=FutureWarning)

    filename = os.path.basename(csv_file)
    # Format : {sig}_{proto}_{scenario}.csv
    # ex : ed25519_tls_ideal.csv / mldsa65_quic_africa_local.csv
    parts = filename.replace(".csv", "").split("_")

    # Trouver l'index du protocole
    proto_idx = None
    for i, p in enumerate(parts):
        if p.lower() in ("tls", "quic"):
            proto_idx = i
            break
    if proto_idx is None:
        print(f"  ⚠️  Protocole introuvable dans : {filename} — ignoré")
        return

    signature = "_".join(parts[:proto_idx])       # ed25519 / mldsa44 / secp384r1 ...
    tls_quic  = parts[proto_idx].upper()          # TLS ou QUIC
    scenario  = "_".join(parts[proto_idx + 1:])  # ideal / africa_local / ...

    # Chargement
    df = pd.read_csv(csv_file).dropna()
    if df.empty:
        print(f"  ⚠️  Fichier vide : {filename}")
        return

    # Format long
    df_long   = df.melt(var_name="KEM", value_name="Duration")
    kem_order = list(df.columns)
    df_long["KEM"] = pd.Categorical(
        df_long["KEM"], categories=kem_order, ordered=True
    )

    # Filtres outliers — même comportement que Montenegro
    df_long = filtrar_valores_extremos(df_long)
    if use_iqr:
        df_long = filtrar_outliers_iqr(df_long)

    if df_long.empty:
        print(f"  ⚠️  Données vides après filtrage : {filename}")
        return

    # Titre lisible
    scenario_labels = {
        "ideal":           "ideal conditions",
        "africa_local":    "Local YDE (35ms/2%)",
        "africa_backbone": "Backbone (200ms/4%)",
        "africa_degraded": "Degraded (200ms/10%)",
    }
    scen_label = scenario_labels.get(scenario, scenario)

    # ── Figure identique Montenegro ───────────────────────────────────────────
    # Phase 6 : KEMs HQC ont des noms plus longs → largeur adaptée
    n_kems    = len(df.columns)
    fig_width = max(12, n_kems * 2.2)

    sns.set(style="whitegrid")
    plt.figure(figsize=(fig_width, 6))

    sns.violinplot(
        x="KEM", y="Duration", data=df_long,
        inner=None,
        palette="Set2",
        bw=0.3,
    )
    sns.boxplot(
        x="KEM", y="Duration", data=df_long,
        showfliers=False,
        showcaps=True,
        boxprops=dict(visible=False),
        whiskerprops=dict(color='black'),
        capprops=dict(color='black'),
        medianprops=dict(color='red', linewidth=2),
        width=0.15,
    )

    plt.ylabel("Handshake duration (ms)")
    plt.xlabel("")
    # Rotation légère pour les noms HQC longs (hqc128, p256_hqc128, etc.)
    plt.xticks(fontsize=12, rotation=15, ha='right')
    plt.grid(True, axis='y')
    plt.title(
        f"Handshake duration on {tls_quic} with {signature} "
        f"signature algorithm — {scen_label}"
    )
    plt.tight_layout()

    # ── Sauvegarde dans {PROTO}/plots/ ────────────────────────────────────────
    os.makedirs(out_dir, exist_ok=True)
    base = f"{signature}_{tls_quic.lower()}_{scenario}"
    plt.savefig(os.path.join(out_dir, f"{base}.pdf"))
    plt.savefig(os.path.join(out_dir, f"{base}.svg"))
    plt.close()
    print(f"  ✅ {tls_quic}/plots/{base}.pdf")


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Violin plots Phase 6 HQC — format Montenegro"
    )
    parser.add_argument(
        "--data-dir",
        default=os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."),
        help="Répertoire racine Phase 6 (contient TLS/ et QUIC/). "
             "Défaut : répertoire parent du script (6- hqc/)."
    )
    parser.add_argument(
        "--scenarios",
        default="ideal",
        help=(
            "Scénarios à traiter, séparés par virgule.\n"
            "Valeurs : ideal, africa_local, africa_backbone, africa_degraded, all\n"
            "Défaut : ideal"
        )
    )
    parser.add_argument(
        "--iqr", action="store_true",
        help="Activer le filtre IQR (désactivé par défaut, comme Montenegro)"
    )
    args = parser.parse_args()

    data_dir = os.path.abspath(os.path.expanduser(args.data_dir))

    all_scenarios = ["ideal", "africa_local", "africa_backbone", "africa_degraded"]
    if args.scenarios.strip().lower() == "all":
        scenarios = all_scenarios
    else:
        scenarios = [s.strip() for s in args.scenarios.split(",")]
        invalid   = [s for s in scenarios if s not in all_scenarios]
        if invalid:
            print(f"⚠️  Scénarios inconnus ignorés : {invalid}")
        scenarios = [s for s in scenarios if s in all_scenarios]

    print(f"\n{'='*60}")
    print("Violin plots — Phase 6 HQC (format Montenegro)")
    print(f"Données    : {data_dir}")
    print(f"Scénarios  : {scenarios}")
    print(f"Filtre IQR : {'activé' if args.iqr else 'désactivé (comme Montenegro)'}")
    print(f"{'='*60}\n")

    total = 0
    for proto in ["TLS", "QUIC"]:
        csv_dir  = os.path.join(data_dir, proto, "csv")
        plot_dir = os.path.join(data_dir, proto, "plots")

        if not os.path.isdir(csv_dir):
            print(f"⚠️  Introuvable : {csv_dir}")
            continue

        csv_files = []
        for scen in scenarios:
            pattern = os.path.join(csv_dir, f"*_{proto.lower()}_{scen}.csv")
            found   = sorted(glob.glob(pattern))
            if not found:
                print(f"  ⚠️  Aucun CSV pour {proto}/{scen}")
            csv_files.extend(found)

        if not csv_files:
            continue

        print(f"→ {proto} — {len(csv_files)} fichier(s) → {plot_dir}/")
        for csv_file in csv_files:
            plot_violin(csv_file, plot_dir, use_iqr=args.iqr)
            total += 1

    print(f"\n{'='*60}")
    print(f"✅ {total} violin(s) générés")
    print(f"   TLS  → {os.path.join(data_dir, 'TLS',  'plots')}/")
    print(f"   QUIC → {os.path.join(data_dir, 'QUIC', 'plots')}/")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
