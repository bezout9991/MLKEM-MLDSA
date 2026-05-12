# ANÁLISIS COMPLETO DE HANDSHAKE CON MÉTRICAS, GRÁFICOS Y ESTADÍSTICA EN MARKDOWN

import os
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from scipy.stats import ttest_ind, levene, shapiro, f_oneway
import subprocess

folder = "./handshake_data"
output_base = "full_report"
output_md = output_base + ".md"
pdf_output = output_base + ".pdf"

nivel_map = {"ed25519": 1, "secp384r1": 3, "secp521r1": 5}
tipos_kem_por_nivel = {
    1: {
        "P-256": "Traditional",
        "x25519": "Traditional",
        "p256_mlkem512": "Hybrid",
        "x25519_mlkem512": "Hybrid",
        "mlkem512": "Post-quantum"
    },
    3: {
        "P-384": "Traditional",
        "x448": "Traditional",
        "p384_mlkem768": "Hybrid",
        "x448_mlkem768": "Hybrid",
        "mlkem768": "Post-quantum"
    },
    5: {
        "P-521": "Traditional",
        "p521_mlkem1024": "Hybrid",
        "mlkem1024": "Post-quantum"
    }
}

md = ["# Full Handshake Performance Analysis in TLS and QUIC\n"]
resumen_global = []

for base, nivel in nivel_map.items():
    for proto in ["tls", "quic"]:
        ideal_path = os.path.join(folder, f"{base}_{proto}_ideal.csv")
        size_path = os.path.join(folder, f"{base}_{proto}_size.csv")
        if not os.path.exists(ideal_path) or not os.path.exists(size_path):
            continue

        df_time = pd.read_csv(ideal_path).melt(var_name="KEM", value_name="Time_ms")
        df_size = pd.read_csv(size_path)
        size_col = "Suma_QUIC" if proto == "quic" else "Suma_Total"
        df_size = df_size.rename(columns={"KEM_ALG": "KEM", size_col: "Size_bytes"})

        df = pd.merge(df_time, df_size[["KEM", "Size_bytes"]], on="KEM")
        df["Protocol"] = proto.upper()
        df["Level"] = nivel
        df["Type"] = df["KEM"].map(tipos_kem_por_nivel[nivel])
        resumen_global.append(df)

        md.append(f"\n## Level {nivel} — Protocol {proto.upper()}\n")
        md.append("### Summary Statistics by KEM\n")
        stats = df.groupby(["KEM", "Type"]).agg(
            mean_time=("Time_ms", "mean"),
            std_time=("Time_ms", "std"),
            median_time=("Time_ms", "median"),
            min_time=("Time_ms", "min"),
            max_time=("Time_ms", "max"),
            size_bytes=("Size_bytes", "mean")
        ).reset_index()

        md.append("| KEM | Type | Mean | Median | Std | Min | Max | Size (bytes) |")
        md.append("|-----|------|------|--------|-----|-----|-----|---------------|")
        for _, row in stats.iterrows():
            md.append(f"`{row.KEM}` | {row.Type} | {row.mean_time:.2f} | {row.median_time:.2f} | {row.std_time:.2f} | {row.min_time:.2f} | {row.max_time:.2f} | {int(row.size_bytes)}")

        
        # Estadística por tipo
        tipos = df["Type"].dropna().unique()
        for t in tipos:
            datos = df[df["Type"] == t]["Time_ms"]
            stat, p_shapiro = shapiro(datos)
            md.append(f"- Shapiro-Wilk for {t}: p = {p_shapiro:.4f}")

        if len(tipos) >= 2:
            grupos = [df[df["Type"] == t]["Time_ms"] for t in tipos]
            stat, p_levene = levene(*grupos)
            md.append(f"- Levene’s Test for homogeneity: p = {p_levene:.4f}")
            for i in range(len(tipos)):
                for j in range(i+1, len(tipos)):
                    a = grupos[i]
                    b = grupos[j]
                    eq = p_levene > 0.05
                    stat, pval = ttest_ind(a, b, equal_var=eq)
                    md.append(f"- T-test between {tipos[i]} and {tipos[j]}: p = {pval:.4f} ({'equal' if eq else 'unequal'} var)")

# ------------------------------------------------------------
# ANÁLISIS POR PROTOCOLO Y NIVEL EXCLUYENDO TIME_MS > 1000
# ------------------------------------------------------------

def count_outliers_iqr(series):
    q1 = series.quantile(0.25)
    q3 = series.quantile(0.75)
    iqr = q3 - q1
    lower = q1 - 1.5 * iqr
    upper = q3 + 1.5 * iqr
    return int(((series < lower) | (series > upper)).sum())

# Concatenar todos los datos
df_all = pd.concat(resumen_global, ignore_index=True)

# Filtrar valores extremos (> 1000 ms)
df_no_ext = df_all[df_all["Time_ms"] <= 1000].copy()

md.append("\n# Summary by Protocol and Level (excluding >1000 ms)\n")
md.append("| Protocol | Level | Mean | Std | CV | % Outliers |")
md.append("|----------|:-----:|-----:|----:|---:|-----------:|")

for (proto, lvl), grupo in df_no_ext.groupby(["Protocol", "Level"]):
    tiempos = grupo["Time_ms"]
    n = len(tiempos)
    mean_t = tiempos.mean()
    std_t = tiempos.std(ddof=1)
    cv_t = std_t / mean_t if (mean_t != 0 and n > 1) else float("nan")
    # Contar outliers POR IQR dentro de este subconjunto (tempos <= 1000)
    outl_count = count_outliers_iqr(tiempos)
    pct_outl = 100.0 * outl_count / n if n > 0 else float("nan")
    md.append(f"{proto} | {lvl} | {mean_t:.2f} | {std_t:.2f} | {cv_t:.2f} | {pct_outl:.2f}%")

# Precomputar Shapiro–Wilk (normalidad) por (Protocol, Level, KEM)
sw_pvals = {}
for (proto, lvl, kem), grupo in df_no_ext.groupby(["Protocol", "Level", "KEM"]):
    tiempos = grupo["Time_ms"]
    if len(tiempos) >= 3:
        stat_sw, p_sw = shapiro(tiempos)
    else:
        p_sw = float("nan")
    sw_pvals[(proto, lvl, kem)] = p_sw

# Precomputar Levene (homogeneidad de varianzas) por (Protocol, Level)
lev_pvals = {}
for (proto, lvl), grupo_nivel in df_no_ext.groupby(["Protocol", "Level"]):
    # Obtener lista de arrays de Time_ms para cada KEM en este (proto, lvl)
    arms = [sub["Time_ms"].values for _, sub in grupo_nivel.groupby("KEM")]
    if len(arms) >= 2:
        stat_lev, p_lev = levene(*arms)
    else:
        p_lev = float("nan")
    lev_pvals[(proto, lvl)] = p_lev

# ------------------------------------------------------------
# Detalle por Protocolo, Nivel y KEM (excluyendo >1000 ms),
# añadiendo Shapiro–Wilk y Levene
# ------------------------------------------------------------
md.append("\n# Detail by Protocol, Level and KEM (excluding >1000 ms)\n")
md.append("| Protocol | Level | KEM | Mean | Std | CV | % Outliers | Shapiro p | Levene p |")
md.append("|----------|:-----:|:----|-----:|----:|---:|-----------:|----------:|---------:|")

for (proto, lvl, kem), grupo in df_no_ext.groupby(["Protocol", "Level", "KEM"]):
    tiempos = grupo["Time_ms"]
    n = len(tiempos)
    mean_t = tiempos.mean()
    std_t = tiempos.std(ddof=1)
    cv_t = std_t / mean_t if (mean_t != 0 and n > 1) else float("nan")

    # Contar outliers por IQR en este subconjunto
    outl_count = count_outliers_iqr(tiempos)
    pct_outl = 100.0 * outl_count / n if n > 0 else float("nan")

    # Shapiro–Wilk p-valor para este grupo
    p_sw = sw_pvals.get((proto, lvl, kem), float("nan"))

    # Levene p-valor para todos los KEMs de este (proto, lvl)
    p_lev = lev_pvals.get((proto, lvl), float("nan"))

    md.append(
        f"{proto} | {lvl} | `{kem}` | "
        f"{mean_t:.2f} | {std_t:.2f} | {cv_t:.2f} | {pct_outl:.2f}% | "
        f"{p_sw:.2e} | {p_lev:.2e}"
    )

# ------------------------------------------------------------
# Sección nueva: Pairwise Welch’s t-test por Protocolo y Nivel
# ------------------------------------------------------------
md.append("\n# Pairwise Welch’s t-test (excluding >1000 ms)\n")
md.append("| Protocol | Level | KEM1 | KEM2 | Welch’s p-value |")
md.append("|----------|:-----:|:----:|:----:|----------------:|")

# Recorremos cada combinación de Protocol y Level
for (proto, lvl), grupo_nivel in df_no_ext.groupby(["Protocol", "Level"]):
    # Lista de KEMs en ese (proto, lvl)
    kems = sorted(grupo_nivel["KEM"].unique())
    # Para cada par distinto de KEMs
    for i in range(len(kems)):
        for j in range(i+1, len(kems)):
            kem1 = kems[i]
            kem2 = kems[j]
            # Extraemos tiempos de cada KEM
            a = grupo_nivel[grupo_nivel["KEM"] == kem1]["Time_ms"]
            b = grupo_nivel[grupo_nivel["KEM"] == kem2]["Time_ms"]
            # Solo si hay al menos 3 muestras en cada grupo
            if len(a) >= 3 and len(b) >= 3:
                stat_w, p_welch = ttest_ind(a, b, equal_var=False)
            else:
                p_welch = float("nan")
            # Formateamos y añadimos a markdown
            md.append(
                f"{proto} | {lvl} | `{kem1}` | `{kem2}` | {p_welch:.2e}"
            )
# ------------------------------------------------------------    

# Comparativa entre niveles (intra-KEM, intra-protocolo)
df_all = pd.concat(resumen_global)


# Comparación TLS vs QUIC para cada KEM y nivel
md.append("\n# TLS vs QUIC Comparison\n")
for nivel in [1,3,5]:
    df_lvl = df_all[df_all["Level"] == nivel]
    for tipo in df_lvl["Type"].dropna().unique():
        df_t = df_lvl[df_lvl["Type"] == tipo]
        if set(df_t["Protocol"]) == {"TLS", "QUIC"}:
            tls = df_t[df_t["Protocol"] == "TLS"]["Time_ms"]
            quic = df_t[df_t["Protocol"] == "QUIC"]["Time_ms"]
            stat, pval = ttest_ind(tls, quic, equal_var=False)
            md.append(f"- Level {nivel} — {tipo}: TLS mean = {tls.mean():.2f}, QUIC mean = {quic.mean():.2f}, p = {pval:.4f}")

# Ratio tiempo / tamaño
md.append("\n# Time vs Size Ratio\n")
df_all["Ratio"] = df_all["Time_ms"] / df_all["Size_bytes"]
ratio_stats = df_all.groupby(["Level", "Protocol", "Type"]).agg(
    ratio_mean=("Ratio", "mean"),
    ratio_std=("Ratio", "std")
).reset_index()
md.append("| Level | Protocol | Type | Mean Ratio (ms/byte) | Std |")
md.append("|-------|----------|------|----------------------|------|")
for _, row in ratio_stats.iterrows():
    md.append(f"{row.Level} | {row.Protocol} | {row.Type} | {row.ratio_mean:.6f} | {row.ratio_std:.6f}")



outliers_summary = []

for base, nivel in nivel_map.items():
    for proto in ["tls", "quic"]:
        ideal_path = os.path.join(folder, f"{base}_{proto}_ideal.csv")
        size_path = os.path.join(folder, f"{base}_{proto}_size.csv")
        if not os.path.exists(ideal_path) or not os.path.exists(size_path):
            continue

        df_time = pd.read_csv(ideal_path).melt(var_name="KEM", value_name="Time_ms")
        df_size = pd.read_csv(size_path)
        size_col = "Suma_QUIC" if proto == "quic" else "Suma_Total"
        df_size = df_size.rename(columns={"KEM_ALG": "KEM", size_col: "Size_bytes"})

        df = pd.merge(df_time, df_size[["KEM", "Size_bytes"]], on="KEM")
        df["Protocol"] = proto.upper()
        df["Level"] = nivel
        df["Type"] = df["KEM"].map(tipos_kem_por_nivel[nivel])

        # Outlier detection
        df["Outlier"] = False
        for kem in df["KEM"].unique():
            q1 = df[df["KEM"] == kem]["Time_ms"].quantile(0.25)
            q3 = df[df["KEM"] == kem]["Time_ms"].quantile(0.75)
            iqr = q3 - q1
            lower = q1 - 1.5 * iqr
            upper = q3 + 1.5 * iqr
            mask = (df["KEM"] == kem) & ((df["Time_ms"] < lower) | (df["Time_ms"] > upper))
            df.loc[mask, "Outlier"] = True

            total = len(df[df["KEM"] == kem])
            outliers = mask.sum()
            ratio = 100 * outliers / total
            outliers_summary.append({
                "Level": nivel,
                "Protocol": proto.upper(),
                "KEM": kem,
                "Outliers": outliers,
                "Total": total,
                "Percent": ratio
            })

        resumen_global.append(df)

# Añadir resumen de outliers
md.append("\n# Outlier Analysis (IQR Method)\n")
md.append("| Level | Protocol | KEM | Outliers | Total | Percent |")
md.append("|-------|----------|-----|----------|--------|---------|")
for o in outliers_summary:
    md.append(f"{o['Level']} | {o['Protocol']} | `{o['KEM']}` | {o['Outliers']} | {o['Total']} | {o['Percent']:.2f}%")

# Añadir gráfico de comparación de tamaño por KEM
import seaborn as sns
import matplotlib.pyplot as plt

plot_df = pd.concat(resumen_global)
plt.figure(figsize=(10, 5))
sns.barplot(data=plot_df, x="KEM", y="Size_bytes", hue="Protocol")
plt.title("Average Handshake Size by KEM and Protocol")
plt.xticks(rotation=45)
plt.ylabel("Bytes")
plt.tight_layout()
size_plot = "size_comparison_kem_protocol.png"
plt.savefig(size_plot)
plt.close()
md.append(f"![Handshake Size by KEM and Protocol](./{size_plot})\n")

resumen_transition = []


combined_df = pd.concat(resumen_global)

for proto in combined_df["Protocol"].unique():
    for from_level in [1]:
        for to_level in [3, 5]:
            for from_type in ["Traditional"]:
                for to_type in ["Hybrid", "Post-quantum"]:
                    df_from = combined_df[(combined_df["Protocol"] == proto) & (combined_df["Level"] == from_level) & (combined_df["Type"] == from_type)]
                    df_to = combined_df[(combined_df["Protocol"] == proto) & (combined_df["Level"] == to_level) & (combined_df["Type"] == to_type)]
                    if df_from.empty or df_to.empty:
                        continue
                    mean_from_time = df_from["Time_ms"].mean()
                    mean_to_time = df_to["Time_ms"].mean()
                    mean_from_size = df_from["Size_bytes"].mean()
                    mean_to_size = df_to["Size_bytes"].mean()
                    delta_time = mean_to_time - mean_from_time
                    delta_size = mean_to_size - mean_from_size
                    pct_time = 100 * delta_time / mean_from_time
                    pct_size = 100 * delta_size / mean_from_size

                    resumen_transition.append({
                        "Protocol": proto,
                        "From_Level": from_level,
                        "To_Level": to_level,
                        "From_Type": from_type,
                        "To_Type": to_type,
                        "Delta_Time": delta_time,
                        "Delta_Size": delta_size,
                        "Pct_Time": pct_time,
                        "Pct_Size": pct_size
                    })


# Añadir transición de híbrido → post-cuántico
for proto in combined_df["Protocol"].unique():
    for from_level, to_level in [(1,3), (1,5), (3,5)]:
        for from_type, to_type in [("Hybrid", "Post-quantum")]:
            df_from = combined_df[(combined_df["Protocol"] == proto) & (combined_df["Level"] == from_level) & (combined_df["Type"] == from_type)]
            df_to = combined_df[(combined_df["Protocol"] == proto) & (combined_df["Level"] == to_level) & (combined_df["Type"] == to_type)]
            if df_from.empty or df_to.empty:
                continue
            mean_from_time = df_from["Time_ms"].mean()
            mean_to_time = df_to["Time_ms"].mean()
            mean_from_size = df_from["Size_bytes"].mean()
            mean_to_size = df_to["Size_bytes"].mean()
            delta_time = mean_to_time - mean_from_time
            delta_size = mean_to_size - mean_from_size
            pct_time = 100 * delta_time / mean_from_time
            pct_size = 100 * delta_size / mean_from_size

            resumen_transition.append({
                "Protocol": proto,
                "From_Level": from_level,
                "To_Level": to_level,
                "From_Type": from_type,
                "To_Type": to_type,
                "Delta_Time": delta_time,
                "Delta_Size": delta_size,
                "Pct_Time": pct_time,
                "Pct_Size": pct_size
            })




# --- 4. Combined Impact: Changing Level and KEM Type ---
md.append("\n# Combined Impact: Changing Level and KEM Type\n")
md.append("This section evaluates the compounded penalty when upgrading security level and KEM category.\n")

# 1) Agregamos medias y tamaños por Protocol, Level, Type
agg = (
    pd.concat(resumen_global)
      .groupby(["Protocol","Level","Type"])
      .agg(
          MeanTime=("Time_ms","mean"),
          MeanSize=("Size_bytes","mean")
      )
      .reset_index()
)

# 2) Generamos las transiciones
resumen_transition = []
for proto in agg.Protocol.unique():
    for from_level, to_level in [(1,3),(1,5),(3,5)]:
        for from_type in ["Traditional","Hybrid"]:
            for to_type in ["Hybrid","Post-quantum"]:
                a = agg[(agg.Protocol==proto)&(agg.Level==from_level)&(agg.Type==from_type)]
                b = agg[(agg.Protocol==proto)&(agg.Level==to_level)&(agg.Type==to_type)]
                if a.empty or b.empty:
                    continue

                t0, s0 = float(a.MeanTime), float(a.MeanSize)
                t1, s1 = float(b.MeanTime), float(b.MeanSize)
                dt = t1 - t0
                ds = s1 - s0
                pct_t = (dt/t0)*100
                pct_s = (ds/s0)*100

                resumen_transition.append({
                    "Protocol": proto,
                    "From":      f"{from_level} {from_type}",
                    "To":        f"{to_level} {to_type}",
                    "ΔTime_ms":  dt,
                    "ΔSize_B":   ds,
                    "%ΔTime":    pct_t,
                    "%ΔSize":    pct_s
                })

# 3) Imprimimos la tabla ordenada por %ΔTime descendente
df_trans = pd.DataFrame(resumen_transition).sort_values("%ΔTime", ascending=False)
md.append("\n## Transition Summary Table")
md.append("| Protocol | From → To | ΔTime (ms) | ΔSize (bytes) | %ΔTime | %ΔSize |")
md.append("|----------|-----------|------------:|--------------:|-------:|-------:|")
for _, r in df_trans.iterrows():
    md.append(
        f"{r['Protocol']} | {r['From']} → {r['To']} | "
        f"{r['ΔTime_ms']:.2f} | {int(r['ΔSize_B'])} | "
        f"{r['%ΔTime']:.1f}% | {r['%ΔSize']:.1f}%"
    )



with open(output_md, "w") as f:
    f.write("\n".join(md))


    
print(f"✅ Full analysis Markdown report generated: {output_md}")



