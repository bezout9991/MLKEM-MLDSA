import os
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
import re
import argparse

# --------------------- CLI arguments ---------------------
parser = argparse.ArgumentParser(description="Genera violin plots de delay con límites Y opcionales.")
parser.add_argument("--folder", default=".", help="Carpeta donde están los CSVs (por defecto actual).")
parser.add_argument("--ymin", type=float, default=0, help="Límite inferior del eje Y.")
parser.add_argument("--ymax", type=float, default=None, help="Límite superior del eje Y.")
args = parser.parse_args()

folder = args.folder

# --------------------- Recolección de datos ---------------------
dataframes = []
pattern = re.compile(r'(?P<sigalg>[^_]+)_(?P<protocol>[^_]+)_delay(?P<delay>\d+)\.csv')

for filename in os.listdir(folder):
    match = pattern.match(filename)
    if match:
        sigalg = match.group('sigalg')
        protocol = match.group('protocol')
        delay = int(match.group('delay'))
        filepath = os.path.join(folder, filename)

        df = pd.read_csv(filepath)
        kem_columns = [col for col in df.columns if col not in ['Signature', 'Protocol', 'Delay (ms)']]

        df_long = df.melt(id_vars=[], value_vars=kem_columns,
                          var_name='KEM', value_name='Handshake Time (ms)')
        df_long['KEM'] = pd.Categorical(df_long['KEM'], categories=kem_columns, ordered=True)
        df_long['Delay (ms)'] = delay
        df_long['Signature'] = sigalg
        df_long['Protocol'] = protocol
        dataframes.append(df_long)

if not dataframes:
    raise SystemExit("❌ No se encontraron CSVs que cumplan el patrón esperado.")

df_total = pd.concat(dataframes, ignore_index=True)
df_total = df_total.sort_values(by='Delay (ms)')

# --------------------- Filtrado IQR ---------------------
Q1 = df_total['Handshake Time (ms)'].quantile(0.25)
Q3 = df_total['Handshake Time (ms)'].quantile(0.75)
IQR = Q3 - Q1
df_filtered = df_total[
    (df_total['Handshake Time (ms)'] >= Q1 - 1.5 * IQR) &
    (df_total['Handshake Time (ms)'] <= Q3 + 1.5 * IQR)
]

# --------------------- Gráfico ---------------------
plt.figure(figsize=(8, 6), constrained_layout=True)
sns.violinplot(
    x='Delay (ms)',
    y='Handshake Time (ms)',
    hue='KEM',
    data=df_filtered,
    palette='Set2',
    cut=0,
    inner='box',
    linewidth=1,
    saturation=1
)

sig_used = df_total['Signature'].unique()[0]
proto_used = df_total['Protocol'].unique()[0]

plt.ylabel('Handshake Time (ms)', fontsize=16)
plt.xlabel('Delay (ms)', fontsize=16)
plt.legend(title='KEM', loc='upper left', title_fontsize=16, fontsize=14)
plt.text(0.95, 0.95,
         f"Signature: {sig_used}",
         ha='right', va='top', transform=plt.gca().transAxes,
         fontsize=14,
         bbox=dict(boxstyle="square,pad=0.5", facecolor="white", edgecolor="gray", alpha=0.8))
plt.grid(True)
plt.subplots_adjust(left=0.15, right=0.98, bottom=0.15, top=0.95)
plt.yticks(fontsize=20)
plt.xticks(fontsize=20)

# 🔹 Aplicar los límites de escala si se indican
if args.ymin is not None or args.ymax is not None:
    ymin = 0 if args.ymin is None else args.ymin
    ymax = plt.gca().get_ylim()[1] if args.ymax is None else args.ymax
    plt.ylim(ymin, ymax)

# --------------------- Guardado ---------------------
os.makedirs(folder, exist_ok=True)
output_file_pdf = os.path.join(folder, f"{proto_used}_delays_{sig_used}_sameScale.pdf")
output_file_svg = os.path.join(folder, f"{proto_used}_delays_{sig_used}_sameScale.svg")

plt.savefig(output_file_pdf)
plt.savefig(output_file_svg)
plt.close()
print(f"✅ Gráfico guardado con eje Y entre {args.ymin} y {args.ymax}.")
