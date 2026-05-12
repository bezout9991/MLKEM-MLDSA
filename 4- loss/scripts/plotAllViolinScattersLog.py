import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os
import glob
import warnings
import numpy as np
import sys



def filtrar_valores_extremos(df_long, umbral_ms=6000):
    return df_long[df_long["Duration"] < umbral_ms]
    
def filtrar_outliers_iqr(df_long):
    filtrados = []
    for kem, grupo in df_long.groupby("KEM", observed=False):
        q1 = grupo["Duration"].quantile(0.25)
        q3 = grupo["Duration"].quantile(0.75)
        iqr = q3 - q1
        lower = q1 - 1.5 * iqr
        upper = q3 + 1.5 * iqr
        filtrados.append(grupo[(grupo["Duration"] >= lower) & (grupo["Duration"] <= upper)])
    return pd.concat(filtrados)

def plot_handshake_durations(csv_file, output_dir="plotsOutliersViolinExtremos"):
    warnings.filterwarnings("ignore", category=FutureWarning)

    filename = os.path.basename(csv_file) 
    parts = filename.replace(".csv", "").split("_")

    if len(parts) != 3:
        print(f"❌ Nombre inválido: {filename} — esperado formato <firma>_<tls|quic>_<loss>.csv")
        return

    signature_algorithm, tls_quic, loss = parts[0], parts[1].upper(), parts[2].upper()

    # Cargar datos
    df = pd.read_csv(csv_file).dropna()
    if df.empty:
        print(f"⚠️  Archivo vacío tras eliminar NaNs: {filename}")
        return

    # Reformatear a formato largo
    df_long = df.melt(var_name="KEM", value_name="Duration")
    kem_order = list(df.columns)
    df_long["KEM"] = pd.Categorical(df_long["KEM"], categories=kem_order, ordered=True)

    # Crea una nueva columna en escala logarítmica
    df_long["LogDuration"] = np.log10(df_long["Duration"])

    # Posiciones desplazadas para el stripplot
    kem_indices = {kem: i for i, kem in enumerate(kem_order)}
    df_long["x_pos"] = df_long["KEM"].map(lambda kem: kem_indices[kem] - 0.15)

    sns.set(style="whitegrid")
    plt.figure(figsize=(12, 6))



    kem_list = df_long["KEM"].unique()
    color_palette = sns.color_palette("Set2", len(kem_list))  # O usa Set2, tab10, etc.
    color_dict = dict(zip(kem_list, color_palette))
    df_long["color"] = df_long["KEM"].astype(str).map(color_dict)

    # Boxplot normal
    sns.boxplot(
        x="KEM", y="LogDuration", data=df_long,
        showfliers=False,
        palette=color_dict,              # <- AQUI
        showcaps=True,
        boxprops=dict(visible=False),
        whiskerprops=dict(color='black'), 
        capprops=dict(color='black'),
        medianprops=dict(color='red', linewidth=2),
        flierprops=dict(marker='+', color='black', alpha=0.5),
        width=0.15
    )

    sns.violinplot(
        x="KEM", y="LogDuration", data=df_long,
        inner=None,  # muestra líneas de cuartiles
        palette=color_dict,              # <- AQUI
        bw=0.3,            # suavizado intermedio
        #cut=0,             # limitar extensión
        #scale="width",     # mismo ancho
        #width=0.9          # grosor de los violines
    )

    # Stripplot desplazado
    plt.scatter(
        df_long["x_pos"], df_long["LogDuration"],
        color="black",
        #c=df_long["color"],       # Asigna colores por KEM
        alpha=0.3, marker="x",
        #edgecolors="gray",
        #linewidths=0.5,
        zorder=3
    )

    plt.ylabel("Log10 Handshake duration (ms)")
    plt.xlabel("")
    plt.xticks(ticks=range(len(kem_order)), labels=kem_order, fontsize=14)
    plt.grid(True, axis='y')
    plt.title(f"Handshake duration on {tls_quic} with {signature_algorithm} signature algorithm")
    plt.tight_layout()

    os.makedirs(output_dir, exist_ok=True)
    output_file_pdf = os.path.join(output_dir, f"{signature_algorithm}_{tls_quic.lower()}_{loss.lower()}.pdf")
    output_file_svg = os.path.join(output_dir, f"{signature_algorithm}_{tls_quic.lower()}_{loss.lower()}.svg")

    plt.savefig(output_file_pdf)
    plt.savefig(output_file_svg)
    plt.close()
    print(f"✅ Gráfico guardado: {output_file_pdf} y {output_file_svg}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Uso: {sys.argv[0]} <directorio_con_csvs>")
        sys.exit(1)

    directorio_csv = sys.argv[1]

    if not os.path.isdir(directorio_csv):
        print(f"❌ El directorio '{directorio_csv}' no existe.")
        sys.exit(1)

    csv_files = glob.glob(os.path.join(directorio_csv, "*.csv"))
    if not csv_files:
        print(f"❌ No se encontraron archivos CSV en {directorio_csv}")
    else:
        for csv_file in csv_files:
            if "handshakes" in os.path.basename(csv_file).lower():
                continue 
            output_dir = os.path.join(directorio_csv, "plotsOutliersViolinExtremos")
            os.makedirs(output_dir, exist_ok=True)
            plot_handshake_durations(csv_file, output_dir)
            