#!/usr/bin/env python3
"""
analysis_tls_quic_ge.py

Aggregate handshake CSVs from ideal and Gilbert–Elliot (stable/unstable) scenarios,
perform statistical analysis by KEM (traditional/hybrid/post-quantum) for each level
and scenario, cross-level ANOVA, TLS vs QUIC comparisons, and emit high-level conclusions.

Now with NaN filtering: skip tests for insufficient data.
"""

import os
import argparse
import pandas as pd
from scipy.stats import shapiro, levene, ttest_ind, f_oneway
from sklearn.linear_model import LinearRegression

# --- Configuration: map signature basename to levels
LEVEL_MAP = {"ed25519": 1, "secp384r1": 3, "secp521r1": 5}
# KEM list per level
KEM_TYPE = {
    1: ["P-256","x25519","p256_mlkem512","x25519_mlkem512","mlkem512"],
    3: ["P-384","x448","p384_mlkem768","x448_mlkem768","mlkem768"],
    5: ["P-521","p521_mlkem1024","mlkem1024"]
}

def load_ge_csvs(ideal_dir, ge_dirs):
    records = []
    # 0% loss / ideal handshake times + sizes
    for proto in ("tls","quic"):
        for sig, lvl in LEVEL_MAP.items():
            tfile = os.path.join(ideal_dir, f"{sig}_{proto}_ideal.csv")
            sfile = os.path.join(ideal_dir, f"{sig}_{proto}_size.csv")
            if os.path.isfile(tfile) and os.path.isfile(sfile):
                df_time = pd.read_csv(tfile).melt(var_name="KEM", value_name="Time_ms")
                df_size = pd.read_csv(sfile)
                size_col = "Suma_QUIC" if proto=="quic" else "Suma_Total"
                df_size = df_size.rename(columns={"KEM_ALG":"KEM", size_col:"Size_bytes"})
                df = pd.merge(df_time, df_size[["KEM","Size_bytes"]], on="KEM")
                df["Protocol"] = proto.upper()
                df["Level"]    = lvl
                df["Scenario"] = "Ideal"
                records.append(df)
    # Gilbert–Elliot scenarios
    for ge_dir in ge_dirs:
        scen = os.path.basename(ge_dir).lower()
        name = {"estable":"Stable","inestable":"Unstable"}.get(scen, scen.title())
        for proto in ("tls","quic"):
            for sig, lvl in LEVEL_MAP.items():
                fn = f"{sig}_{proto}_handshakes_merged_M{scen}.csv"
                path = os.path.join(ge_dir, fn)
                if not os.path.isfile(path):
                    continue
                df = pd.read_csv(path)
                df["Protocol"] = proto.upper()
                df["Level"]    = lvl
                df["Scenario"] = name
                records.append(df)
    if not records:
        raise RuntimeError("No CSVs found in ideal or GE dirs")
    return pd.concat(records, ignore_index=True)

def reshape(df):
    rows = []
    for _, r in df.iterrows():
        if r.Scenario=="Ideal":
            rows.append({
                "Protocol":   r.Protocol,
                "Level":      r.Level,
                "Scenario":   r.Scenario,
                "KEM":        r.KEM,
                "Time_ms":    r.Time_ms,
                "Size_bytes": r.Size_bytes
            })
        else:
            for kem in KEM_TYPE[r.Level]:
                tcol = f"{kem}_Time_ms"
                if tcol not in r or pd.isna(r[tcol]):
                    continue
                if f"{kem}_Bytes_Total" in r and pd.notna(r[f"{kem}_Bytes_Total"]):
                    size_val = r[f"{kem}_Bytes_Total"]
                else:
                    size_val = r.get(f"{kem}_Bytes_TCP",0) + r.get(f"{kem}_Bytes_TLS",0)
                rows.append({
                    "Protocol":   r.Protocol,
                    "Level":      r.Level,
                    "Scenario":   r.Scenario,
                    "KEM":        kem,
                    "Time_ms":    r[tcol],
                    "Size_bytes": size_val
                })
    return pd.DataFrame(rows)

def summary_by_kem(df, scenario):
    print(f"\n=== Per-Level KEM Comparisons (Scenario={scenario}) ===")
    for lvl in sorted(df.Level.unique()):
        for proto in sorted(df.Protocol.unique()):
            sub = df[(df.Level==lvl)&(df.Protocol==proto)&(df.Scenario==scenario)].dropna(subset=["Time_ms"])
            if sub.empty: continue
            print(f"\nLevel {lvl} – {proto}")
            stats = sub.groupby("KEM")["Time_ms"].agg(mean="mean", std="std", median="median", min="min", max="max")
            print(stats.to_markdown(floatfmt=".2f"))
            # Normality
            p_sw = {}
            for kem, group in sub.groupby("KEM"):
                if len(group.Time_ms) >= 3:
                    p_sw[kem] = shapiro(group.Time_ms)[1]
            if p_sw:
                print("Shapiro‐Wilk p-values:", ', '.join(f"{k}={v:.3f}" for k,v in p_sw.items()))
            # Homogeneity
            groups = [g.Time_ms for _,g in sub.groupby("KEM") if len(g.Time_ms) >= 2]
            if len(groups) >= 2:
                p_lev = levene(*groups)[1]
                print(f"Levene’s test p-value: {p_lev:.3f}")
            else:
                p_lev = None
            # Pairwise t-tests
            kems = [k for k,g in sub.groupby("KEM") if len(g.Time_ms) >= 2]
            for i in range(len(kems)):
                for j in range(i+1, len(kems)):
                    a = sub[sub.KEM==kems[i]].Time_ms
                    b = sub[sub.KEM==kems[j]].Time_ms
                    if len(a) >= 2 and len(b) >= 2:
                        eq = (p_lev is not None and p_lev > 0.05)
                        p = ttest_ind(a, b, equal_var=eq)[1]
                        print(f"t-test {kems[i]} vs {kems[j]}: p={p:.3f}")

def cross_level_anova(df, scenario):
    print(f"\n=== Cross-Level ANOVA (Scenario={scenario}) ===")
    for proto in sorted(df.Protocol.unique()):
        for kem in sorted(df.KEM.unique()):
            sub = df[(df.Protocol==proto)&(df.KEM==kem)&(df.Scenario==scenario)].dropna(subset=["Time_ms"])
            if sub.Level.nunique() < 2:
                continue
            groups = [sub[sub.Level==lvl].Time_ms for lvl in sorted(sub.Level.unique()) if len(sub[sub.Level==lvl].Time_ms) >= 2]
            if len(groups) >= 2:
                p = f_oneway(*groups)[1]
                print(f"{proto} – {kem}: ANOVA p={p:.3e}")

def tls_vs_quic(df, scenario):
    print(f"\n=== TLS vs QUIC Comparisons (Scenario={scenario}) ===")
    for lvl in sorted(df.Level.unique()):
        for kem in sorted(df.KEM.unique()):
            a = df[(df.Level==lvl)&(df.KEM==kem)&(df.Protocol=="TLS")&(df.Scenario==scenario)].Time_ms.dropna()
            b = df[(df.Level==lvl)&(df.KEM==kem)&(df.Protocol=="QUIC")&(df.Scenario==scenario)].Time_ms.dropna()
            if len(a) >= 2 and len(b) >= 2:
                p = ttest_ind(a, b, equal_var=False)[1]
                print(f"Level {lvl} – {kem}: TLS vs QUIC p={p:.3f}")

def overall_conclusions(df):
    print("\n=== Relative Increases vs Ideal ===")
    base = df[df.Scenario=="Ideal"].groupby(["Protocol","Level","KEM"])["Time_ms"].mean()
    for scenario in ("Stable","Unstable"):
        curr = df[df.Scenario==scenario].groupby(["Protocol","Level","KEM"])["Time_ms"].mean()
        inc = ((curr - base) / base * 100).groupby('Protocol').mean()
        print(f"\nAverage latency increase in {scenario}:")
        for proto, pct in inc.items():
            print(f"  {proto}: {pct:.1f}%")

def compute_ge_slopes(df):
    """
    Para cada combinación (Protocol, Level, KEM),
    ajusta una regresión lineal de mean(Time_ms) vs escenario indexado:
      Ideal→0, Stable→1, Unstable→2
    y devuelve el coeficiente (Slope_ms).
    """
    scen_idx = {"Ideal":0, "Stable":1, "Unstable":2}
    recs = []
    for (proto,lvl,kem), grp in df.groupby(["Protocol","Level","KEM"]):
        X, y = [], []
        for scen, idx in scen_idx.items():
            g = grp[grp.Scenario==scen]["Time_ms"].dropna()
            if len(g)>0:
                X.append([idx])
                y.append(g.mean())
        if len(X)>=2:
            slope = LinearRegression().fit(X, y).coef_[0]
        else:
            slope = float("nan")
        recs.append({"Protocol":proto, "Level":lvl, "KEM":kem, "Slope_ms":slope})
    return pd.DataFrame(recs)

def print_ge_tables_per_level(df, slopes_df):
    scenarios = ["Ideal", "Stable", "Unstable"]
    for level in sorted(df.Level.unique()):
        sub = df[df.Level==level]
        if sub.empty: continue

        print(f"\n## Level {level}\n")
        hdr = ["Protocol","KEM"] \
            + [f"Mean_{s}" for s in scenarios] \
            + [f"CV_{s}"   for s in scenarios] \
            + [f"O_{s}%"   for s in scenarios] \
            + [f"Size_{s}" for s in scenarios] \
            + ["Slope_ms"]
        print("| " + " | ".join(hdr) + " |")
        print("|" + "|".join("------" for _ in hdr) + "|")

        for proto in ["TLS","QUIC"]:
            for kem in sorted(sub.KEM.unique()):
                row = [proto, f"`{kem}`"]
                grp = sub[(sub.Protocol==proto)&(sub.KEM==kem)]

                # 1) Acumular métricas por escenario
                means, cvs, outs, sizes = [], [], [], []
                for scen in scenarios:
                    g = grp[grp.Scenario==scen]
                    times = g.Time_ms.dropna()
                    sz    = g.Size_bytes.dropna()
                    n = len(times)
                    if n == 0:
                        m = cv = o = size_m = float("nan")
                    else:
                        m = times.mean()
                        std = times.std(ddof=1) if n>1 else 0.0
                        cv = std/m if m else float("nan")
                        if n >= 4:
                            q1, q3 = times.quantile([0.25,0.75])
                            iqr = q3 - q1
                            lo, hi = q1 - 1.5*iqr, q3 + 1.5*iqr
                            o = ((times<lo)|(times>hi)).sum()/n*100
                        else:
                            o = 0.0
                        size_m = sz.mean() if len(sz)>0 else float("nan")
                    means .append(m)
                    cvs   .append(cv)
                    outs  .append(o)
                    sizes .append(size_m)

                # 2) Añadir en el orden de hdr
                row += [f"{x:.2f}" for x in means]
                row += [f"{x:.2f}" for x in cvs]
                row += [f"{x:.1f}%"  for x in outs]
                row += [f"{x:.0f}"  for x in sizes]

                # 3) pendiente
                s = slopes_df[
                    (slopes_df.Protocol==proto)&
                    (slopes_df.Level==level)&
                    (slopes_df.KEM==kem)
                ]["Slope_ms"]
                slope = s.iloc[0] if not s.empty else float("nan")
                row.append(f"{slope:.2f}")

                print("| " + " | ".join(row) + " |")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--ideal-dir",  required=True)
    p.add_argument("--ge-dirs", nargs=2, required=True)
    args = p.parse_args()

    df_raw = load_ge_csvs(args.ideal_dir, args.ge_dirs)
    df = reshape(df_raw)

    for scenario in ["Ideal","Stable","Unstable"]:
        summary_by_kem(df, scenario)
        cross_level_anova(df, scenario)
        tls_vs_quic(df, scenario)

    overall_conclusions(df)

    # calculamos slopes y luego imprimimos la tabla por nivel
    slopes_df = compute_ge_slopes(df)
    print_ge_tables_per_level(df, slopes_df)

if __name__=="__main__":
    main()

