#!/usr/bin/env python3
"""
analysis_tls_quic_loss.py

Aggregate handshake CSVs from ideal and loss scenarios, perform statistical analysis
by KEM (traditional/hybrid/post-quantum) for each level and loss percentage,
cross-level ANOVA, TLS vs QUIC comparisons, and emit high-level conclusions in English.
"""

import os
import argparse
import pandas as pd
from scipy.stats import shapiro, levene, ttest_ind, f_oneway, iqr, kruskal, mannwhitneyu
from sklearn.linear_model import LinearRegression
import numpy as np

# --- Configuration: map base name to levels and KEM types
LEVEL_MAP = {"ed25519": 1, "secp384r1": 3, "secp521r1": 5}
KEM_TYPE = {
    1: ["P-256","x25519","p256_mlkem512","x25519_mlkem512","mlkem512"],
    3: ["P-384","x448","p384_mlkem768","x448_mlkem768","mlkem768"],
    5: ["P-521","p521_mlkem1024","mlkem1024"]
}


def load_merged_csvs(ideal_dir, loss_dirs):
    records = []
    # Ideal (0% loss)
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
                df["LossPct"]  = 0
                records.append(df)
    # Loss scenarios
    for loss_dir in loss_dirs:
        pct = int(''.join(filter(str.isdigit, loss_dir)))
        for proto in ("tls","quic"):
            for sig, lvl in LEVEL_MAP.items():
                path = os.path.join(loss_dir, f"{sig}_{proto}_handshakes_merged_loss{pct}.csv")
                if not os.path.isfile(path):
                    continue
                df = pd.read_csv(path)
                df["Protocol"] = proto.upper()
                df["Level"]    = lvl
                df["LossPct"]  = pct
                records.append(df)
    if not records:
        raise RuntimeError("No CSVs found in ideal or loss dirs")
    return pd.concat(records, ignore_index=True)


def reshape(df):
    rows = []
    for _, r in df.iterrows():
        if r.LossPct == 0:
            rows.append({
                "Protocol":   r.Protocol,
                "Level":      r.Level,
                "LossPct":    r.LossPct,
                "KEM":        r.KEM,
                "Time_ms":    r.Time_ms,
                "Size_bytes": r.Size_bytes
            })
        else:
            for kem in KEM_TYPE[r.Level]:
                tcol = f"{kem}_Time_ms"
                if tcol not in r:
                    continue
                if f"{kem}_Bytes_Total" in r and pd.notna(r[f"{kem}_Bytes_Total"]):
                    size_val = r[f"{kem}_Bytes_Total"]
                else:
                    size_val = r.get(f"{kem}_Bytes_TCP",0) + r.get(f"{kem}_Bytes_TLS",0)
                rows.append({
                    "Protocol":   r.Protocol,
                    "Level":      r.Level,
                    "LossPct":    r.LossPct,
                    "KEM":        kem,
                    "Time_ms":    r[tcol],
                    "Size_bytes": size_val
                })
    return pd.DataFrame(rows)


def summary_by_kem(df, loss):
    print(f"\n=== Per-Level KEM Comparisons (Loss={loss}%) ===")
    for lvl in sorted(df.Level.unique()):
        for proto in sorted(df.Protocol.unique()):
            sub = df[(df.Level == lvl) & (df.Protocol == proto) & (df.LossPct == loss)]
            if sub.empty:
                continue

            print(f"\nLevel {lvl} – {proto}")

            # 1) Estadísticos descriptivos por KEM
            stats = sub.groupby("KEM")["Time_ms"].agg(
                mean="mean", std="std", median="median", min="min", max="max"
            ).reset_index()
            stats = stats.rename(columns={
                "mean": "Mean",
                "std": "DesvStd",
                "median": "Median",
                "min": "Min",
                "max": "Max"
            })

            # 1.1) Calcular outliers (método IQR) para cada KEM
            outliers = []
            for kem in stats.KEM:
                data = sub[sub.KEM == kem].Time_ms
                q1 = data.quantile(0.25)
                q3 = data.quantile(0.75)
                iqr = q3 - q1
                lower = q1 - 1.5 * iqr
                upper = q3 + 1.5 * iqr
                count = ((data < lower) | (data > upper)).sum()
                outliers.append(int(count))
            stats["Outliers"] = outliers

            print("\n**Descriptive statistics (with Outlier count):**")
            print(stats.to_markdown(index=False, floatfmt=".2f"))

            # 2) Shapiro-Wilk (normalidad)
            p_sw = []
            for kem in stats.KEM:
                grupo = sub[sub.KEM == kem].Time_ms
                pval = shapiro(grupo)[1]
                p_sw.append({"KEM": kem, "Shapiro_p": pval})
            df_sw = pd.DataFrame(p_sw)
            df_sw["Shapiro_p"] = df_sw["Shapiro_p"].map(lambda x: f"{x:.2e}")

            print("\n**Shapiro–Wilk (p-valores):**")
            print(df_sw.to_markdown(index=False))

            # 3) Levene (homogeneidad de varianzas)
            muestras = [sub[sub.KEM == kem].Time_ms for kem in stats.KEM]
            p_lev = levene(*muestras)[1]
            print(f"\n**Levene's test p-value:** {p_lev:.2e}")

            groups = [ sub[sub.KEM==kem].Time_ms for kem in sub.KEM.unique() ]
            stat, p_kw = kruskal(*groups)
            print(f"\n**Kruskal–Wallis p = {p_kw:.2e}")

            print("\n**Pairwise Mann–Whitney (p-values):**")
            kems = list(stats.KEM)
            rows_mw = []
            for i in range(len(kems)):
                for j in range(i+1, len(kems)):
                    a = sub[sub.KEM == kems[i]].Time_ms
                    b = sub[sub.KEM == kems[j]].Time_ms
                    stat, p_mw = mannwhitneyu(a, b, alternative="two-sided")
                    rows_mw.append({
                        "KEM1": kems[i],
                        "KEM2": kems[j],
                        "p-value": f"{p_mw:.2f}"
                    })
            df_mw = pd.DataFrame(rows_mw)
            print(df_mw.to_markdown(index=False))    

            # 4) t-tests por pares
            print("\n**Pairwise t-tests (p-values):**")
            kems = list(stats.KEM)
            rows_tt = []
            equal_var_flag = (p_lev > 0.05)
            for i in range(len(kems)):
                for j in range(i + 1, len(kems)):
                    a = sub[sub.KEM == kems[i]].Time_ms
                    b = sub[sub.KEM == kems[j]].Time_ms
                    p = ttest_ind(a, b, equal_var=equal_var_flag)[1]
                    rows_tt.append({
                        "KEM1": kems[i],
                        "KEM2": kems[j],
                        "p-value": f"{p:.2e}"
                    })
            df_tt = pd.DataFrame(rows_tt)


            print(df_tt.to_markdown(index=False))





def cross_level_anova(df, loss):
    print(f"\n=== Cross-Level ANOVA (Loss={loss}%) ===")
    for proto in sorted(df.Protocol.unique()):
        for kem in sorted(df.KEM.unique()):
            sub = df[(df.Protocol==proto)&(df.KEM==kem)&(df.LossPct==loss)]
            if sub.Level.nunique()<2: continue
            p = f_oneway(*[sub[sub.Level==lvl].Time_ms for lvl in sorted(sub.Level.unique())])[1]
            print(f"{proto} – {kem}: ANOVA p={p:.3e}")


def tls_vs_quic(df, loss):
    print(f"\n=== TLS vs QUIC Comparisons (Loss={loss}%) ===")
    for lvl in sorted(df.Level.unique()):
        for kem in sorted(df.KEM.unique()):
            a = df[(df.Level==lvl)&(df.KEM==kem)&(df.Protocol=="TLS")&(df.LossPct==loss)].Time_ms
            b = df[(df.Level==lvl)&(df.KEM==kem)&(df.Protocol=="QUIC")&(df.LossPct==loss)].Time_ms
            if a.empty or b.empty: continue
            p = ttest_ind(a,b, equal_var=False)[1]
            print(f"Level {lvl} – {kem}: TLS vs QUIC p={p:.3f}")


def overall_conclusions(df):
    print("\n=== Global Conclusions ===")
    for loss in sorted(df.LossPct.unique()):
        if loss==0: continue
        baseline = df[df.LossPct==0].groupby(["Protocol","Level","KEM"])['Time_ms'].mean()
        current = df[df.LossPct==loss].groupby(["Protocol","Level","KEM"])['Time_ms'].mean()
        inc = ((current - baseline)/baseline*100).groupby('Protocol').mean()
        print(f"Average latency increase at {loss}% loss:")
        for proto, pct in inc.items():
            print(f"  {proto}: {pct:.1f}%")
   

    

def overall_conclusionsExt(df):
    """
    Para cada porcentaje de pérdida (LossPct ≠ 0), esta función:
    1) Calcula conteo, medias y desviaciones (para CV) en 0% y en LossPct.
    2) Cuenta outliers en 0% y en LossPct.
    3) Calcula diferencias absolutas (Δ) en Mean, Outliers y CV.
    4) Ejecuta test de Mann–Whitney U entre muestras 0% vs LossPct.
    5) Imprime por nivel y protocolo una tabla Markdown con solo:
       KEM | N 0% | Mean 0% | Outliers 0% | CV 0% |
             N L% | Mean L% | Outliers L% | CV L% |
             Δ Mean (ms) | Δ Outliers | Δ CV | p-value 0 vs L
    """

    # --- X. Compute regression slopes w.r.t. LossPct ---
    # 1) First aggregate the mean handshake at each LossPct
    rel_loss = (
        df[df.LossPct > 0]
        .groupby(['Protocol','Level','KEM','LossPct'])['Time_ms']
        .mean()
        .reset_index(name='MeanTime')
    )

    slopes_loss = []
    for (proto, lvl, kem), grp in rel_loss.groupby(['Protocol','Level','KEM']):
        X = grp['LossPct'].values.reshape(-1,1)   # e.g. [1,5,10,20,...]
        y = grp['MeanTime'].values                # the corresponding mean handshake
        if len(np.unique(X)) < 2:
            slope = np.nan
        else:
            slope = LinearRegression().fit(X, y).coef_[0]
        slopes_loss.append({
            'Protocol': proto,
            'Level':    lvl,
            'KEM':      kem,
            'Slope_per_pct_loss': slope
        })

    slopes_loss_df = pd.DataFrame(slopes_loss)
    # 2) Save to CSV
    slopes_loss_df.to_csv(os.path.join(".", 'handshake_slopes_loss.csv'), index=False)

    print("\n=== Regression slopes (ms handshake increase per 1% loss) ===")
    print(slopes_loss_df.to_markdown(index=False, floatfmt=".2f"))
                
    for loss in sorted(df.LossPct.unique()):
        if loss == 0:
            continue

        print(f"\n=== Differences {loss}% loss ===")

        # 1) Agrupar a 0% con conteo, media y std
        base_grouped = (
            df[df.LossPct == 0]
            .groupby(["Protocol", "Level", "KEM"])["Time_ms"]
            .agg(count_0="count", mean_0="mean", std_0="std")
            .reset_index()
        )
        base_grouped["CV_0%"] = base_grouped["std_0"] / base_grouped["mean_0"]

        # 2) Agrupar a loss% con conteo, media y std
        curr_grouped = (
            df[df.LossPct == loss]
            .groupby(["Protocol", "Level", "KEM"])["Time_ms"]
            .agg(count_l="count", mean_l="mean", std_l="std")
            .reset_index()
        )
        curr_grouped["CV_l%"] = curr_grouped["std_l"] / curr_grouped["mean_l"]

        # 3) Conteo de outliers a 0%
        outliers_base = []
        for (proto, lvl, kem), group in df[df.LossPct == 0].groupby(
            ["Protocol", "Level", "KEM"]
        ):
            valores = group.Time_ms
            if len(valores) < 4:
                count_out = 0
            else:
                q1 = valores.quantile(0.25)
                q3 = valores.quantile(0.75)
                iqr = q3 - q1
                lower = q1 - 1.5 * iqr
                upper = q3 + 1.5 * iqr
                count_out = ((valores < lower) | (valores > upper)).sum()
            outliers_base.append(
                {
                    "Protocol": proto,
                    "Level": lvl,
                    "KEM": kem,
                    "Outliers_0%": int(count_out),
                }
            )
        df_out_base = pd.DataFrame(outliers_base)

        # 4) Conteo de outliers a loss%
        outliers_curr = []
        for (proto, lvl, kem), group in df[df.LossPct == loss].groupby(
            ["Protocol", "Level", "KEM"]
        ):
            valores = group.Time_ms
            if len(valores) < 4:
                count_out = 0
            else:
                q1 = valores.quantile(0.25)
                q3 = valores.quantile(0.75)
                iqr = q3 - q1
                lower = q1 - 1.5 * iqr
                upper = q3 + 1.5 * iqr
                count_out = ((valores < lower) | (valores > upper)).sum()
            outliers_curr.append(
                {
                    "Protocol": proto,
                    "Level": lvl,
                    "KEM": kem,
                    f"Outliers_{loss}%": int(count_out),
                }
            )
        df_out_curr = pd.DataFrame(outliers_curr)

        # 5) Unir todo
        merged = (
            base_grouped
            .merge(curr_grouped, on=["Protocol", "Level", "KEM"], how="inner")
            .merge(df_out_base, on=["Protocol", "Level", "KEM"], how="left")
            .merge(df_out_curr, on=["Protocol", "Level", "KEM"], how="left")
        )

        merged["Outliers_0%"] = merged["Outliers_0%"].fillna(0).astype(int)
        merged[f"Outliers_{loss}%"] = merged[f"Outliers_{loss}%"].fillna(0).astype(int)

        # 6) Calcular diferencias (Δ)
        merged["Δ Mean (ms)"] = merged["mean_l"] - merged["mean_0"]
        merged["Δ CV"] = merged["CV_l%"] - merged["CV_0%"]
        merged["Δ Outliers"] = merged[f"Outliers_{loss}%"] - merged["Outliers_0%"]

        # 7) p-value 0% vs loss% con Mann–Whitney
        p_vals = []
        for _, row in merged.iterrows():
            proto = row.Protocol
            level = row.Level
            kem = row.KEM

            a = df[
                (df.Protocol == proto)
                & (df.Level == level)
                & (df.KEM == kem)
                & (df.LossPct == 0)
            ].Time_ms
            b = df[
                (df.Protocol == proto)
                & (df.Level == level)
                & (df.KEM == kem)
                & (df.LossPct == loss)
            ].Time_ms

            if len(a) >= 3 and len(b) >= 3:
                _, pval = mannwhitneyu(a, b, alternative="two-sided")
                p_vals.append(pval)
            else:
                p_vals.append(float("nan"))
        merged[f"p-value 0 vs {loss}"] = p_vals

        # 8) Imprimir por nivel y protocolo con columnas seleccionadas
        for level in sorted(merged.Level.unique()):
            for proto in sorted(merged.Protocol.unique()):
                sub = merged[(merged.Level == level) & (merged.Protocol == proto)]
                if sub.empty:
                    continue

                print(f"\nLevel {level} – {proto}")

                cols_order = [
                    "KEM",
                    "count_0",
                    "mean_0",
                    "Outliers_0%",
                    "CV_0%",
                    "count_l",
                    "mean_l",
                    f"Outliers_{loss}%",
                    "CV_l%",
                    "Δ Mean (ms)",
                    "Δ Outliers",
                    "Δ CV",
                    f"p-value 0 vs {loss}",
                ]

                tmp = sub.copy()

                # Redondear medias y CV a 2 decimales
                tmp.loc[
                    :, ["mean_0", "mean_l", "CV_0%", "CV_l%", "Δ Mean (ms)", "Δ CV"]
                ] = tmp[
                    ["mean_0", "mean_l", "CV_0%", "CV_l%", "Δ Mean (ms)", "Δ CV"]
                ].round(2)

                # Asegurar enteros para conteos y outliers
                tmp.loc[:, "count_0"] = tmp["count_0"].astype(int)
                tmp.loc[:, "count_l"] = tmp["count_l"].astype(int)
                tmp.loc[:, "Outliers_0%"] = tmp["Outliers_0%"].astype(int)
                tmp.loc[:, f"Outliers_{loss}%"] = tmp[f"Outliers_{loss}%"].astype(int)
                tmp.loc[:, "Δ Outliers"] = tmp["Δ Outliers"].astype(int)

                # Formatear p-value a notación científica o "N/A"
                tmp.loc[:, f"p-value 0 vs {loss}"] = tmp[f"p-value 0 vs {loss}"].map(
                    lambda x: f"{x:.2e}" if pd.notna(x) else "N/A"
                )

                # Renombrar columnas
                to_print = tmp[cols_order].rename(
                    columns={
                        "count_0": "N 0%",
                        "mean_0": "Mean 0 %",
                        "Outliers_0%": "Outliers 0 %",
                        "CV_0%": "CV 0 %",
                        "count_l": f"N {loss}%",
                        "mean_l": f"Mean {loss} %",
                        f"Outliers_{loss}%": f"Outliers {loss} %",
                        "CV_l%": f"CV {loss} %",
                        "Δ Mean (ms)": "Δ Mean (ms)",
                        "Δ Outliers": "Δ Outliers",
                        "Δ CV": "Δ CV",
                        f"p-value 0 vs {loss}": f"p-value 0 vs {loss}",
                    }
                )

            

                # 9) Convertir todo a string y usar to_markdown para generar el Markdown
                to_print_str = to_print.astype(str)
                print(to_print_str.to_markdown())

def print_loss_tables_per_level(df_long, slopes_loss_df):
    """
    For each Level, prints a Markdown table with columns in this order:
      Protocol | KEM
      | Mean_0 Mean_5 Mean_10 Mean_20 
      | CV_0 CV_5 CV_10 CV_20 
      | O_0% O_5% O_10% O_20% 
      | Size_0 Size_5 Size_10 Size_20 
      | Slope_ms_per_%loss
    """
    levels     = sorted(df_long.Level.unique())
    loss_levels = [0, 5, 10, 20]

    for level in levels:
        sub = df_long[(df_long.Level == level) & (df_long.LossPct.isin(loss_levels))]
        if sub.empty:
            continue

        print(f"\n## Level {level}\n")
        # Build header
        hdr = ["Protocol", "KEM"]
        hdr += [f"Mean_{L}" for L in loss_levels]
        hdr += [f"CV_{L}"   for L in loss_levels]
        hdr += [f"O_{L}%"   for L in loss_levels]
        hdr += [f"Size_{L}" for L in loss_levels]         # one size column per loss
        hdr += ["Slope_ms_per_%loss"]

        # Print header
        print("| " + " | ".join(hdr) + " |")
        print("|" + "|".join(["------"] * len(hdr)) + "|")

        # Print rows
        for proto in ["TLS", "QUIC"]:
            for kem in sub.KEM.unique():
                row = [proto, f"`{kem}`"]
                grp = sub[(sub.Protocol == proto) & (sub.KEM == kem)]

                # collect mean times, cvs, outliers
                means, cvs, outs, sizes = [], [], [], []
                for L in loss_levels:
                    g2 = grp[grp.LossPct == L]
                    times = g2.Time_ms
                    n     = len(times)

                    if n == 0:
                        means.append("N/A")
                        cvs.append("N/A")
                        outs.append("N/A")
                        sizes.append("N/A")
                    else:
                        # time stats
                        mean = times.mean()
                        std  = times.std(ddof=1) if n>1 else 0.0
                        cv   = std/mean if mean else 0.0
                        if n >= 4:
                            q1, q3 = times.quantile([0.25,0.75])
                            iqr_   = q3 - q1
                            lo, hi = q1-1.5*iqr_, q3+1.5*iqr_
                            out_pc = ((times<lo)|(times>hi)).sum()/n*100
                        else:
                            out_pc = 0.0

                        means.append(f"{mean:.2f}")
                        cvs.append(f"{cv:.2f}")
                        outs.append(f"{out_pc:.1f}\\%")

                        # size stat
                        sz = g2.Size_bytes.mean()
                        sizes.append(f"{sz:.0f}")

                # slope lookup
                m = slopes_loss_df[
                    (slopes_loss_df.Protocol == proto) &
                    (slopes_loss_df.Level    == level) &
                    (slopes_loss_df.KEM      == kem)
                ]['Slope_per_pct_loss']
                slope = f"{m.iloc[0]:.2f}" if not m.empty else "N/A"

                row += means + cvs + outs + sizes + [slope]
                print("| " + " | ".join(row) + " |")



def print_loss_tables_per_level2(df_long, slopes_loss_df):
    """
    For each Level, prints a Markdown table with columns in this order:
      Protocol | KEM
      | Mean_0 Mean_5 Mean_10 Mean_20 | CV_0 CV_5 CV_10 CV_20 | O_0% O_5% O_10% O_20% | Slope
    """
    levels = sorted(df_long.Level.unique())
    loss_levels = [0, 5, 10, 20]

    for level in levels:
        sub = df_long[(df_long.Level == level) & (df_long.LossPct.isin(loss_levels))]
        if sub.empty:
            continue

        print(f"\n## Level {level}\n")
        # Build header
        hdr = ["Protocol","KEM"]
        # all means
        hdr += [f"Mean_{L}" for L in loss_levels]
        # all CVs
        hdr += [f"CV_{L}"   for L in loss_levels]
        # all Outliers
        hdr += [f"O_{L}%"   for L in loss_levels]
        # slope last
        hdr += ["Slope_ms_per_%loss"]

        # print header
        print("| " + " | ".join(hdr) + " |")
        print("|" + "|".join(["------"] * len(hdr)) + "|")

        # build rows
        for proto in ["TLS","QUIC"]:
            for kem in sub.KEM.unique():
                row = [proto, f"`{kem}`"]
                grp = sub[(sub.Protocol == proto) & (sub.KEM == kem)]

                # collect means, cvs, outliers in the new grouped order
                means, cvs, outs = [], [], []
                for L in loss_levels:
                    g2 = grp[grp.LossPct == L].Time_ms
                    n = len(g2)
                    if n == 0:
                        mean = cv = out_pc = float("nan")
                    else:
                        mean = g2.mean()
                        std  = g2.std(ddof=1) if n>1 else 0.0
                        cv   = std/mean if mean else 0.0
                        # outlier % via IQR
                        if n >= 4:
                            q1,q3 = g2.quantile([0.25,0.75])
                            iqr_ = q3 - q1
                            lo,hi = q1 - 1.5*iqr_, q3 + 1.5*iqr_
                            out_pc = ((g2<lo)|(g2>hi)).sum() / n * 100
                        else:
                            out_pc = 0.0
                    means.append(f"{mean:.2f}")
                    cvs.append(f"{cv:.2f}")
                    outs.append(f"{out_pc:.1f}\\%")

                row += means + cvs + outs

                # slope
                m = slopes_loss_df[
                    (slopes_loss_df.Protocol == proto) &
                    (slopes_loss_df.Level == level) &
                    (slopes_loss_df.KEM == kem)
                ]['Slope_per_pct_loss']
                slope = m.iloc[0] if not m.empty else float("nan")
                row.append(f"{slope:.2f}")

                print("| " + " | ".join(row) + " |")


                
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ideal-dir", required=True,
                        help="Directory with *_ideal.csv and *_size.csv files")
    parser.add_argument("--loss-dirs", nargs="+", required=True,
                        help="Directories named lossX containing merged loss CSVs")
    args = parser.parse_args()

    # 1) Load & reshape
    df_all  = load_merged_csvs(args.ideal_dir, args.loss_dirs)
    df_long = reshape(df_all)

    # 2) Per‐loss analyses
    for loss in sorted(df_long.LossPct.unique()):
        summary_by_kem(df_long, loss)
        cross_level_anova(df_long, loss)
        tls_vs_quic(df_long, loss)

    # 3) Compute slopes once (not per‐loss)
    from sklearn.linear_model import LinearRegression
    import numpy as np

    rel_loss = (
        df_long[df_long.LossPct > 0]
        .groupby(['Protocol','Level','KEM','LossPct'])['Time_ms']
        .mean()
        .reset_index(name='MeanTime')
    )
    slopes = []
    for (proto, lvl, kem), grp in rel_loss.groupby(['Protocol','Level','KEM']):
        X = grp['LossPct'].values.reshape(-1,1)
        y = grp['MeanTime'].values
        slope = np.nan if len(np.unique(X))<2 else LinearRegression().fit(X, y).coef_[0]
        slopes.append({
            'Protocol': proto,
            'Level':    lvl,
            'KEM':      kem,
            'Slope_per_pct_loss': slope
        })
    slopes_loss_df = pd.DataFrame(slopes)

    # 4) Print loss tables per level
    print_loss_tables_per_level(df_long, slopes_loss_df)

#def main():
 #   parser = argparse.ArgumentParser()
  #  parser.add_argument("--ideal-dir", required=True,
#                        help="Directory with *_ideal.csv and *_size.csv files")
  #  parser.add_argument("--loss-dirs", nargs="+", required=True,
 #                       help="Directories named lossX containing merged loss CSVs")
  #  args = parser.parse_args()

 #   df_all = load_merged_csvs(args.ideal_dir, args.loss_dirs)
 #   df_long = reshape(df_all)

 #   for loss in sorted(df_long.LossPct.unique()):
 #       summary_by_kem(df_long, loss)
 #       cross_level_anova(df_long, loss)
 #       tls_vs_quic(df_long, loss)
 #       print_loss_tables_per_level(df_long, loss)

    #overall_conclusions(df_long)
    #overall_conclusionsExt(df_long)

if __name__ == "__main__":
    main()
