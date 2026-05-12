#!/usr/bin/env python3
import os, argparse, numpy as np, pandas as pd
from scipy.stats import mannwhitneyu

try:
    from tabulate import tabulate
except ImportError:
    def tabulate(data, headers=[], tablefmt="simple", floatfmt=".2f"):
        rows = [headers] + [[str(x) for x in row] for row in data]
        widths = [max(len(str(r[i])) for r in rows) for i in range(len(rows[0]))]
        return "\n".join("  ".join(str(r).ljust(w) for r,w in zip(row,widths)) for row in rows)

SIG_PAIRS = [("ed25519","mldsa44",1),("secp384r1","mldsa65",3),("secp521r1","mldsa87",5)]

KEMS_MLKEM = {1:["P-256","x25519","mlkem512","p256_mlkem512"],
              3:["P-384","x448","mlkem768","p384_mlkem768"],
              5:["P-521","mlkem1024","p521_mlkem1024"]}

KEMS_HQC   = {1:["P-256","x25519","hqc128","p256_hqc128"],
              3:["P-384","x448","hqc192","p384_hqc192"],
              5:["P-521","hqc256","p521_hqc256"]}

def mw(a,b):
    try: _,p = mannwhitneyu(a,b,alternative="two-sided"); return p
    except: return float("nan")

def p_fmt(p):
    if np.isnan(p): return "nan"
    if p<0.001: return "***"
    if p<0.01:  return "**"
    if p<0.05:  return "*"
    return "ns"

def load_csv(path):
    if not os.path.isfile(path): return None
    df = pd.read_csv(path)
    return {k: df[k].dropna().astype(float).values for k in df.columns}

def load_all(data_dir, kems_repr):
    data = {"TLS":{}, "QUIC":{}}
    sigs = ["ed25519","secp384r1","secp521r1","mldsa44","mldsa65","mldsa87"]
    conditions = {
        "ideal":           lambda s,p: f"{s}_{p.lower()}_ideal.csv",
        "africa_local":    lambda s,p: f"{s}_{p.lower()}_africa_local.csv",
        "africa_degraded": lambda s,p: f"{s}_{p.lower()}_africa_degraded.csv",
        "ge_stable":       lambda s,p: os.path.join("ge", f"{s}_{p.lower()}_ge_stable.csv"),
        "ge_unstable":     lambda s,p: os.path.join("ge", f"{s}_{p.lower()}_ge_unstable.csv"),
    }
    for proto in ["TLS","QUIC"]:
        for sig in sigs:
            data[proto][sig] = {}
            for cond, fname_fn in conditions.items():
                path = os.path.join(data_dir, proto.upper(), "csv", fname_fn(sig, proto))
                d = load_csv(path)
                if d: data[proto][sig][cond] = d
    return data

def section1(data, kems, label):
    print(f"\n{'='*75}")
    print(f"SECTION 1 — GE vs PERTE UNIFORME ({label})")
    print(f"{'='*75}")
    conds = [("ideal","Ideal"),("africa_local","Unif.35ms/2%"),
             ("africa_degraded","Unif.200ms/10%"),("ge_stable","GE Stable"),("ge_unstable","GE Instable")]
    for proto in ["TLS","QUIC"]:
        print(f"\n── {proto} ──")
        for sc,sp,lvl in SIG_PAIRS:
            print(f"\n  L{lvl} | {sc} vs {sp}")
            for sig in [sc,sp]:
                rows = []
                for kem in kems[lvl]:
                    if kem not in data[proto].get(sig,{}).get("ideal",{}): continue
                    ideal = np.mean(data[proto][sig]["ideal"][kem])
                    row = [sig, kem]
                    for ck,cl in conds:
                        if ck in data[proto].get(sig,{}) and kem in data[proto][sig][ck]:
                            m = np.mean(data[proto][sig][ck][kem])
                            d = (m-ideal)/ideal*100
                            row.append(f"{m:.1f}ms" if ck=="ideal" else f"{m:.1f}({d:+.0f}%)")
                        else: row.append("—")
                    rows.append(row)
                if rows:
                    print(tabulate(rows, headers=["Sig","KEM"]+[c[1] for c in conds], tablefmt="github"))

def section2(data, kems, label):
    print(f"\n{'='*75}")
    print(f"SECTION 2 — ML-DSA vs CLASSIQUE SOUS GE ({label})")
    print(f"{'='*75}")
    conds = [("ideal","Ideal"),("africa_degraded","Unif.200ms/10%"),
             ("ge_stable","GE Stable"),("ge_unstable","GE Instable")]
    for proto in ["TLS","QUIC"]:
        print(f"\n── {proto} ──")
        for sc,sp,lvl in SIG_PAIRS:
            print(f"\n  L{lvl} : {sc} -> {sp}")
            rows = []
            for kem in kems[lvl]:
                row = [kem]
                for ck,cl in conds:
                    try:
                        ac = data[proto][sc][ck][kem]
                        ap = data[proto][sp][ck][kem]
                        d = (np.mean(ap)-np.mean(ac))/np.mean(ac)*100
                        row.append(f"{d:+.1f}%{p_fmt(mw(ac,ap))}")
                    except: row.append("—")
                rows.append(row)
            print(tabulate(rows, headers=["KEM"]+[c[1] for c in conds], tablefmt="github"))

def section3(data, kems, label):
    print(f"\n{'='*75}")
    print(f"SECTION 3 — TLS vs QUIC SOUS GE ({label})")
    print(f"{'='*75}")
    conds = [("ideal","Ideal"),("africa_degraded","Unif.200ms/10%"),
             ("ge_stable","GE Stable"),("ge_unstable","GE Instable")]
    for sc,sp,lvl in SIG_PAIRS:
        for sig in [sc,sp]:
            print(f"\n── L{lvl} | {sig} ──")
            rows = []
            for kem in kems[lvl]:
                row = [kem]
                for ck,cl in conds:
                    try:
                        t = np.mean(data["TLS"][sig][ck][kem])
                        q = np.mean(data["QUIC"][sig][ck][kem])
                        d = (t-q)/q*100
                        w = "TLS" if t<q else "QUIC"
                        row.append(f"{d:+.1f}%({w})")
                    except: row.append("—")
                rows.append(row)
            print(tabulate(rows, headers=["KEM"]+[c[1] for c in conds], tablefmt="github"))

def section4(data, kems, label):
    print(f"\n{'='*75}")
    print(f"SECTION 4 — TABLEAU RESUME ARTICLE ({label})")
    print(f"{'='*75}")
    conds = [("ideal","Ideal"),("africa_local","Unif.35ms/2%"),
             ("africa_degraded","Unif.200ms/10%"),("ge_stable","GE Stable"),("ge_unstable","GE Instable")]
    for proto in ["TLS","QUIC"]:
        print(f"\n{proto}")
        rows = []
        for sc,sp,lvl in SIG_PAIRS:
            kem_pq = kems[lvl][-1]
            for sig in [sc,sp]:
                row = [f"L{lvl}", sig, kem_pq]
                for ck,cl in conds:
                    try: row.append(f"{np.mean(data[proto][sig][ck][kem_pq]):.1f}")
                    except: row.append("—")
                rows.append(row)
        print(tabulate(rows, headers=["Niv.","Sig","KEM"]+[c[1] for c in conds], tablefmt="github"))

def main():
    parser = argparse.ArgumentParser(description="Analyse GE — Etude 1 et/ou Etude 2")
    parser.add_argument("--study1-dir", default=None, help="Dossier 5- pq-signatures/ (ML-KEM)")
    parser.add_argument("--study2-dir", default=None, help="Dossier 6- hqc/ (HQC)")
    parser.add_argument("--sections",   default="1,2,3,4")
    args = parser.parse_args()
    sections = [int(s) for s in args.sections.split(",")]

    if not args.study1_dir and not args.study2_dir:
        print("ERREUR : --study1-dir et/ou --study2-dir requis")
        print("  Etude 1 seule : python3 analysis_ge.py --study1-dir '5- pq-signatures'/")
        print("  Etude 2 seule : python3 analysis_ge.py --study2-dir '6- hqc'/")
        print("  Les deux      : python3 analysis_ge.py --study1-dir ... --study2-dir ...")
        return

    if args.study1_dir:
        print(f"\nChargement Etude 1 : {args.study1_dir}")
        d1 = load_all(args.study1_dir, KEMS_MLKEM)
        for proto in ["TLS","QUIC"]:
            conds = set(c for s in d1[proto] for c in d1[proto][s])
            print(f"  {proto}: {sorted(conds)}")
        print(f"\n{'#'*75}\n### ETUDE 1 - ML-DSA x ML-KEM\n{'#'*75}")
        if 1 in sections: section1(d1, KEMS_MLKEM, "ML-KEM")
        if 2 in sections: section2(d1, KEMS_MLKEM, "ML-KEM")
        if 3 in sections: section3(d1, KEMS_MLKEM, "ML-KEM")
        if 4 in sections: section4(d1, KEMS_MLKEM, "ML-KEM")

    if args.study2_dir:
        print(f"\nChargement Etude 2 : {args.study2_dir}")
        d2 = load_all(args.study2_dir, KEMS_HQC)
        for proto in ["TLS","QUIC"]:
            conds = set(c for s in d2[proto] for c in d2[proto][s])
            print(f"  {proto}: {sorted(conds)}")
        print(f"\n{'#'*75}\n### ETUDE 2 - ML-DSA x HQC\n{'#'*75}")
        if 1 in sections: section1(d2, KEMS_HQC, "HQC")
        if 2 in sections: section2(d2, KEMS_HQC, "HQC")
        if 3 in sections: section3(d2, KEMS_HQC, "HQC")
        if 4 in sections: section4(d2, KEMS_HQC, "HQC")

    print(f"\n{'='*75}\nAnalyse GE terminee.\n{'='*75}\n")

if __name__ == "__main__":
    main()
