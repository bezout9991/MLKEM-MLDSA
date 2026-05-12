import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os
import glob
import warnings


def filtrar_valores_extremos(df_long, umbral_ms=1000):
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
        print(f"❌ Nombre inválido: {filename} — esperado formato <firma>_<tls|quic>.csv")
        return

    signature_algorithm = parts[0]
    tls_quic = parts[1].upper()

    # Cargar datos
    df = pd.read_csv(csv_file).dropna()

  
    if df.empty:
        print(f"⚠️  Archivo vacío tras eliminar NaNs: {filename}")
        return

    # Reformatear a formato largo
    df_long = df.melt(var_name="KEM", value_name="Duration")

    kem_order = list(df.columns)
    df_long["KEM"] = pd.Categorical(df_long["KEM"], categories=kem_order, ordered=True)


    # Eliminar outliers extremos por IQR
    df_long = filtrar_valores_extremos(df_long)

    sns.set(style="whitegrid")
    plt.figure(figsize=(12, 6))

    # Diagrama de violín con color por KEM
#    sns.violinplot(x="KEM", y="Duration", data=df_long, inner=None)
    sns.violinplot(
        x="KEM", y="Duration", data=df_long,
        inner=None,  # muestra líneas de cuartiles
        palette="Set2",    # paleta de colores
        bw=0.3,            # suavizado intermedio
        #cut=0,             # limitar extensión
        #scale="width",     # mismo ancho
        #width=0.9          # grosor de los violines
    )
    # Boxplot encima, con los mismos colores
    #sns.boxplot(x="KEM", y="Duration", data=df_long,
     #           showfliers=False,
     #           flierprops=dict(marker='+', color='black', alpha=0.5),
     #           width=0.2)

    sns.boxplot(
    x="KEM", y="Duration", data=df_long,
    showfliers=False,              # Opcional: oculta los puntos fuera del IQR
    showcaps=True,                 # Muestra los extremos (caps)
    boxprops=dict(visible=False), # Oculta solo la caja
    whiskerprops=dict(color='black'), 
    capprops=dict(color='black'),
    medianprops=dict(color='red', linewidth=2),
    width=0.15
    )

    plt.ylabel("Handshake duration (ms)")
    plt.xlabel("")
    plt.xticks(fontsize=14)  # Ajusta el número según el tamaño deseado
    plt.grid(True, axis='y')
    plt.title(f"Handshake duration on {tls_quic} with {signature_algorithm} signature algorithm")
    plt.tight_layout()

    output_dir ="./plotsOutliersViolinExtremos"

    os.makedirs(output_dir, exist_ok=True)
    output_file_pdf = os.path.join(output_dir, f"{signature_algorithm}_{tls_quic.lower()}.pdf")
    output_file_svg = os.path.join(output_dir, f"{signature_algorithm}_{tls_quic.lower()}.svg")

    plt.savefig(output_file_pdf)
    plt.savefig(output_file_svg)
    plt.close()
    print(f"✅ Gráfico guardado.")

if __name__ == "__main__":
    csv_files = glob.glob("*.csv")

    if not csv_files:
        print("❌ No se encontraron archivos CSV en el directorio.")
    else:
        for csv_file in csv_files:
            plot_handshake_durations(csv_file)
