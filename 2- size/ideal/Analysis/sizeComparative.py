import pandas as pd
import glob
import os

# === Configuration ===

# Map signature algorithm (from filename) to security level
LEVEL_MAP = {
    "ed25519": 1,
    "secp384r1": 3,
    "secp521r1": 5
}

# KEM categories by level (if you need to filter traditional/hybrid/post-quantum)
KEM_TYPES = {
    1: {
        "P-256":           "Traditional",
        "x25519":          "Traditional",
        "p256_mlkem512":   "Hybrid",
        "x25519_mlkem512": "Hybrid",
        "mlkem512":        "Post-Quantum"
    },
    3: {
        "P-384":            "Traditional",
        "x448":             "Traditional",
        "p384_mlkem768":    "Hybrid",
        "x448_mlkem768":    "Hybrid",
        "mlkem768":         "Post-Quantum"
    },
    5: {
        "P-521":                "Traditional",
        "p521_mlkem1024":       "Hybrid",
        "mlkem1024":            "Post-Quantum"
    }
}

# === Load and Normalize CSVs ===

quic_dfs = []
for path in glob.glob("*_quic.csv"):
    sigalg = os.path.basename(path).split("_")[0].lower()
    level = LEVEL_MAP[sigalg]
    df = pd.read_csv(path).rename(columns={
        "KEM_ALG":    "KEM",
        "Suma_QUIC":  "Traffic_Bytes"
    })
    df["Protocol"] = "QUIC"
    df["Level"]    = level
    quic_dfs.append(df[["KEM", "Traffic_Bytes", "Protocol", "Level"]])

tls_dfs = []
for path in glob.glob("*_tls.csv"):
    sigalg = os.path.basename(path).split("_")[0].lower()
    level = LEVEL_MAP[sigalg]
    df = pd.read_csv(path).rename(columns={
        "KEM_ALG":    "KEM",
        "Suma_TCP":   "Traffic_TCP",
        "Suma_TLS":   "Traffic_TLS",
        "Suma_Total": "Traffic_Bytes"
    })
    df["Protocol"] = "TLS"
    df["Level"]    = level
    tls_dfs.append(df[["KEM", "Traffic_Bytes", "Traffic_TCP", "Traffic_TLS", "Protocol", "Level"]])

# Combine into master DataFrames
df_quic = pd.concat(quic_dfs, ignore_index=True)
df_tls  = pd.concat(tls_dfs,  ignore_index=True)
df_all  = pd.concat([
    df_quic[["KEM","Traffic_Bytes","Protocol","Level"]],
    df_tls[["KEM","Traffic_Bytes","Protocol","Level"]]
], ignore_index=True)

# === 1. Pivot total traffic per Protocol/Level/KEM ===

traffic = (
    df_all
    .pivot_table(
        index=["Level","KEM"],
        columns="Protocol",
        values="Traffic_Bytes"
    )
    .reset_index()
)
traffic["TLS_over_QUIC"] = traffic["TLS"] / traffic["QUIC"]
print("\n=== Traffic by Level & KEM ===")
print(traffic)

# === 2. TLS breakdown: TCP vs TLS 1.3 bytes ===

tls_breakdown = (
    df_tls
    .pivot_table(
        index=["Level","KEM"],
        values=["Traffic_TCP","Traffic_TLS","Traffic_Bytes"]
    )
    .reset_index()
)
print("\n=== TLS Traffic Breakdown ===")
print(tls_breakdown)

# === 3. Overhead introduced by Hybrid KEMs ===

# Compute overhead vs Traditional and vs Post-Quantum, per Level & Protocol
overhead_records = []
for protocol in ["QUIC","TLS"]:
    for level in [1,3,5]:
        subset = traffic[traffic["Level"]==level]
        trad = subset.loc[subset["KEM"].map(KEM_TYPES[level])=="Traditional", protocol].mean()
        postq= subset.loc[subset["KEM"].map(KEM_TYPES[level])=="Post-Quantum", protocol].mean()
        for kem in subset["KEM"]:
            if KEM_TYPES[level].get(kem) == "Hybrid":
                hybrid_val = subset.loc[subset["KEM"]==kem, protocol].iloc[0]
                overhead_records.append({
                    "Protocol": protocol,
                    "Level": level,
                    "Hybrid_KEM": kem,
                    "Overhead_vs_Traditional": hybrid_val - trad,
                    "Overhead_vs_PostQuantum":  hybrid_val - postq
                })

overhead_df = pd.DataFrame(overhead_records)
print("\n=== Hybrid Overhead (bytes) ===")
print(overhead_df)

# === 4. Key Findings ===


print("\n=== Key Findings ===")

# (a) Highest traffic KEM per protocol
for protocol in ["QUIC","TLS"]:
    row_max = traffic.loc[traffic[protocol].idxmax()]
    print(f"- {protocol}: maximum traffic = {row_max[protocol]:.0f} bytes "
          f"for {row_max.KEM} (Level {row_max.Level})")

# (b) Lowest traffic KEM per protocol
for protocol in ["QUIC","TLS"]:
    row_min = traffic.loc[traffic[protocol].idxmin()]
    print(f"- {protocol}: minimum traffic = {row_min[protocol]:.0f} bytes "
          f"for {row_min.KEM} (Level {row_min.Level})")

# (c) Largest TLS/QUIC ratio
row_ratio = traffic.loc[traffic["TLS_over_QUIC"].idxmax()]
print(f"- Largest TLS/QUIC ratio = {row_ratio.TLS_over_QUIC:.2f}× "
      f"for {row_ratio.KEM} (Level {row_ratio.Level})")

# (d) Average overhead by hybrid category
avg_overhead = overhead_df.groupby("Protocol").agg({
    "Overhead_vs_Traditional":"mean",
    "Overhead_vs_PostQuantum":"mean"
})
print("\n- Average hybrid overhead (bytes):")
print(avg_overhead)

# === End of Script ===
