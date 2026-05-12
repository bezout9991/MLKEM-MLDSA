import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os
import glob
import warnings
from collections import defaultdict


import matplotlib as mpl

# Tamaños fijos para todo
LABEL_SIZE = 14   # para nombres de ejes
TICK_SIZE  = 20   # para etiquetas de ticks

mpl.rcParams.update({
    "font.family": "DejaVu Sans",  # o tu preferida
    "axes.labelsize": LABEL_SIZE,
    "xtick.labelsize": TICK_SIZE,
    "ytick.labelsize": TICK_SIZE,
    "pdf.fonttype": 42,  # consistencia en PDF/SVG
    "ps.fonttype": 42,
})

# Fija el tema de seaborn sin cambiar tamaños
sns.set_theme(style="whitegrid")

# ====== Filtros (como en tu script) ======
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
    return pd.concat(filtrados) if filtrados else df_long

def formatear_etiquetas_kem(etiquetas):
    nuevas = []
    for e in etiquetas:
        if not isinstance(e, str):
            nuevas.append(e)
            continue

        # Solo para híbridos tipo *_mlkem*
        if "_mlkem" in e.lower():
            partes = e.split("_")
            base = partes[0]
            kem = partes[1].lower()  # mlkem768

            # Formato especial para los que empiezan con "p"
            if base.lower().startswith("p"):
                # P-384 o P-521
                base = "P-" + base[1:]
            # Mantenemos x448, x25519, etc. tal cual
            nueva = f"{base}\n{kem}"
            nuevas.append(nueva)
        else:
            # No híbrido → lo dejamos igual
            nuevas.append(e)
    return nuevas

# ====== Utilidades ======
def parse_filename(fname):
    """
    Acepta patrones tipo: <firma>_<tls|quic>_loquesea.csv
    Ej.: ed25519_tls_ideal.csv -> ('ed25519', 'tls', 'ideal')
    Si no hay tercer trozo, devuelve '' en la tercera posición.
    """
    base = os.path.basename(fname).replace(".csv", "")
    parts = base.split("_")
    if len(parts) < 2:
        return None, None, None
    firma = parts[0]
    proto = parts[1].lower()
    resto = "_".join(parts[2:]) if len(parts) > 2 else ""
    return firma, proto, resto

def cargar_formato_largo(csv_file):
    df = pd.read_csv(csv_file).dropna()
    if df.empty:
        return None, None  # (df_long, kem_order)
    df_long = df.melt(var_name="KEM", value_name="Duration")
    kem_order = list(df.columns)
    df_long["KEM"] = pd.Categorical(df_long["KEM"], categories=kem_order, ordered=True)

    # Filtros (mismos que usabas)
    df_long = filtrar_valores_extremos(df_long)
    # Si quieres activar IQR: descomenta la siguiente línea
    # df_long = filtrar_outliers_iqr(df_long)

    return df_long, kem_order

def aplicar_limites_y_ticks(ax, xlim, ylim, xticks=None, yticks=None):
    ax.set_xlim(xlim)
    ax.set_ylim(ylim)
    if xticks is not None:
        ax.set_xticks(xticks)
    if yticks is not None:
        ax.set_yticks(yticks)

def plot_violin_con_box(ax, df_long, firma):
    # No vuelvas a llamar a sns.set() aquí
    sns.violinplot(
        ax=ax, x="KEM", y="Duration", data=df_long,
        inner=None, palette="Set2", bw=0.3
    )
    sns.boxplot(
        ax=ax, x="KEM", y="Duration", data=df_long,
        showfliers=False, showcaps=True,
        boxprops=dict(visible=False),
        whiskerprops=dict(color='black'),
        capprops=dict(color='black'),
        medianprops=dict(color='red', linewidth=2),
        width=0.15
    )

    # Etiquetas y estilo: tamaños fijos
    ax.set_ylabel("Handshake duration (ms)", fontsize=LABEL_SIZE)
    ax.set_xlabel("", fontsize=LABEL_SIZE)

    # 🔒 Ticks con el mismo tamaño SIEMPRE
    ax.tick_params(axis='both', which='both', labelsize=TICK_SIZE)

    ax.grid(True, axis='y')

    cuadro_texto = f"Signature: {firma}"
    ax.text(0.95, 0.95, cuadro_texto,
         ha='right', va='top', transform=plt.gca().transAxes,
         fontsize=18,
         bbox=dict(boxstyle="square,pad=0.5", facecolor="white", edgecolor="gray", alpha=0.8))
    
    etiquetas_actuales = [tick.get_text() for tick in ax.get_xticklabels()]
    etiquetas_nuevas = formatear_etiquetas_kem(etiquetas_actuales)
    ax.set_xticklabels(etiquetas_nuevas, ha='center', fontsize=TICK_SIZE + 4)

# ====== Flujo principal ======
def main():
    warnings.filterwarnings("ignore", category=FutureWarning)
    csv_files = glob.glob("*.csv")
    if not csv_files:
        print("❌ No se encontraron archivos CSV en el directorio.")
        return

    # Indexar por firma -> {'tls': [files], 'quic': [files]}
    index_por_firma = defaultdict(lambda: {'tls': [], 'quic': []})
    for f in csv_files:
        firma, proto, _ = parse_filename(f)
        if firma is None or proto not in ("tls", "quic"):
            # Ignora archivos que no cumplan el patrón
            continue
        index_por_firma[firma][proto].append(f)

    outdir = "./plotsOutliersViolinExtremos"
    os.makedirs(outdir, exist_ok=True)

    # Recorremos cada firma que tenga al menos un tls y un quic
    for firma, grupos in index_por_firma.items():
        tls_files = grupos["tls"]
        quic_files = grupos["quic"]
        if not tls_files or not quic_files:
            continue  # Necesitamos el par

        # Heurística simple: tomamos el primer tls y el primer quic encontrados
        tls_csv = sorted(tls_files)[0]
        quic_csv = sorted(quic_files)[0]

        # Cargar datos
        tls_long, tls_kems = cargar_formato_largo(tls_csv)
        quic_long, quic_kems = cargar_formato_largo(quic_csv)

        if tls_long is None or quic_long is None:
            print(f"⚠️  Archivos vacíos tras NaNs o filtrado para {firma}. Saltando…")
            continue

        # Unificar orden de KEMs para consistencia visual (unión de columnas)
        union_kems = list(dict.fromkeys((tls_kems or []) + (quic_kems or [])))  # mantiene orden de aparición
        for dfl in (tls_long, quic_long):
            dfl["KEM"] = pd.Categorical(dfl["KEM"], categories=union_kems, ordered=True)

        # ====== Cálculo de límites y ticks globales del PAR ======
        # Creamos un eje temporal para extraer ticks automáticos homogéneos
        fig_tmp, ax_tmp = plt.subplots()
        ax_tmp.plot([0, 1], [tls_long["Duration"].min(), quic_long["Duration"].max()])  # marcador
        # Limites Y globales (y redondeo suave opcional)
        y_min = min(tls_long["Duration"].min(), quic_long["Duration"].min())
        y_max = max(tls_long["Duration"].max(), quic_long["Duration"].max())
        # pequeño padding
        margen = 0.05 * (y_max - y_min if y_max > y_min else 1.0)
        y_min_g = max(0, y_min - margen)
        y_max_g = y_max + margen

        ax_tmp.set_ylim(y_min_g, y_max_g)
        yticks_globales = ax_tmp.get_yticks()
        plt.close(fig_tmp)

        # X no es numérico (KEMs), dejamos que cada figura muestre el mismo orden de categorías
        xlim_dummy = (-0.5, len(union_kems) - 0.5)
        ylim_global = (y_min_g, y_max_g)

        # ====== FIGURA TLS ======
        fig_tls, ax_tls = plt.subplots(figsize=(12, 6))
        plot_violin_con_box(ax_tls, tls_long, firma)
        aplicar_limites_y_ticks(ax_tls, xlim_dummy, ylim_global, yticks=yticks_globales)

        # Guardar TLS
        base_tls = f"{firma}_tls_sameScale"
        fig_tls.tight_layout()
        fig_tls.savefig(os.path.join(outdir, base_tls + ".pdf"))
        fig_tls.savefig(os.path.join(outdir, base_tls + ".svg"))
        plt.close(fig_tls)

        # ====== FIGURA QUIC ======
        fig_quic, ax_quic = plt.subplots(figsize=(12, 6))
        plot_violin_con_box(ax_quic, quic_long, firma)
        aplicar_limites_y_ticks(ax_quic, xlim_dummy, ylim_global, yticks=yticks_globales)

        # Guardar QUIC
        base_quic = f"{firma}_quic_sameScale"
        fig_quic.tight_layout()
        fig_quic.savefig(os.path.join(outdir, base_quic + ".pdf"))
        fig_quic.savefig(os.path.join(outdir, base_quic + ".svg"))
        plt.close(fig_quic)

        print(f"✅ {firma}: escalas sincronizadas para\n   - {tls_csv}\n   - {quic_csv}")

if __name__ == "__main__":
    main()
