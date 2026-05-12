#!/usr/bin/env python3
"""
Unified Delay Analysis Script (with inf handling)
This script loads handshake timing CSVs (ideal + delays) for TLS & QUIC,
performs stats, regression, Spearman, ANOVA, outliers, plots, and generates a report.
Inf values are converted to NaN before pivot/heatmap operations.
"""
import os
import re
import glob
import subprocess
import numpy as np
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from scipy.stats import spearmanr, f_oneway
from sklearn.linear_model import LinearRegression
import statsmodels.formula.api as smf
import statsmodels.api as sm
import warnings

warnings.filterwarnings("ignore", category=FutureWarning)


# --- Configuration ---
CSV_DIR ="./handshake_data"
DATA_DIR = './'
OUTPUT_DIR = os.path.join(DATA_DIR, 'output')
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Mapping from file prefix to security level
LEVEL_MAP = { 'ed25519':1, 'secp384r1':3, 'secp521r1':5 }

# Regex to match CSV filenames
def parse_metadata(fname):
    m = re.match(r"(?P<sigalg>ed25519|secp384r1|secp521r1)_(?P<proto>quic|tls)_(?:ideal|delay(?P<delay>\d+))\.csv", fname, re.IGNORECASE)
    if not m:
        return None
    sig = m.group('sigalg').lower()
    proto = m.group('proto').upper()
    delay = 0 if m.group('delay') is None else int(m.group('delay'))
    level = LEVEL_MAP[sig]
    return sig, proto, level, delay

# --- 1. Load and concatenate data ---
records = []
for path in glob.glob(os.path.join(CSV_DIR, '*.csv')):
    meta = parse_metadata(os.path.basename(path))
    if not meta: continue
    sig, proto, level, delay = meta
    df = pd.read_csv(path)
    df_long = df.melt(var_name='KEM', value_name='HandshakeTime')
    df_long['Protocol'] = proto
    df_long['Level'] = level
    df_long['Delay_ms'] = delay
    records.append(df_long)

df = pd.concat(records, ignore_index=True)

# --- 2. Summary statistics by delay ---
summary = df.groupby(['Protocol','Level','Delay_ms','KEM'])['HandshakeTime'] \
    .agg(Mean='mean', Std='std', Count='count', Min='min', Max='max', Median='median').reset_index()
summary.to_csv(os.path.join(OUTPUT_DIR,'handshake_delay_summary.csv'), index=False)

# --- 3. Compute relative increase vs ideal ---
ideal = summary[summary.Delay_ms==0][['Protocol','Level','KEM','Mean']].rename(columns={'Mean':'IdealMean'})
rel = summary.merge(ideal, on=['Protocol','Level','KEM'])
rel['PctIncrease'] = (rel['Mean'] - rel['IdealMean']) / rel['IdealMean'] * 100
# Convert any infinite to NaN before pivot
rel.replace([np.inf, -np.inf], np.nan, inplace=True)
rel.to_csv(os.path.join(OUTPUT_DIR,'relative_increase.csv'), index=False)

# --- 4. Compute regression slopes ---
slopes = []
for (proto, lvl, kem), grp in rel.groupby(['Protocol','Level','KEM']):
    X = grp['Delay_ms'].values.reshape(-1,1)
    y = grp['Mean'].values
    if len(np.unique(X))<2:
        slope = np.nan
    else:
        slope = LinearRegression().fit(X,y).coef_[0]
    slopes.append({'Protocol':proto,'Level':lvl,'KEM':kem,'Slope':slope})
slopes = pd.DataFrame(slopes)
slopes.to_csv(os.path.join(OUTPUT_DIR,'handshake_slopes.csv'), index=False)

# --- 5. Spearman trends ---
trends = []
for (proto,lvl,kem), grp in df.groupby(['Protocol','Level','KEM']):
    corr, p = spearmanr(grp['Delay_ms'], grp['HandshakeTime'])
    trends.append({'Protocol':proto,'Level':lvl,'KEM':kem,'SpearmanR':corr,'PValue':p})
trends = pd.DataFrame(trends)
trends['Significant'] = trends['PValue']<0.05
trends.to_csv(os.path.join(OUTPUT_DIR,'spearman_trends.csv'), index=False)

# --- 6. ANOVA Protocol x Delay for each level ---
anovas = {}
for lvl in sorted(df['Level'].unique()):
    sub = df[df['Level']==lvl]
    model = smf.ols('HandshakeTime ~ C(Protocol)*Delay_ms', data=sub).fit()
    anova = sm.stats.anova_lm(model, typ=2)
    anovas[lvl] = anova

# --- 7. Outlier counts ---
out = []
for (proto,lvl,delay,kem), grp in df.groupby(['Protocol','Level','Delay_ms','KEM']):
    q1,q3 = grp['HandshakeTime'].quantile([0.25,0.75])
    iqr = q3-q1
    mask = (grp['HandshakeTime']<q1-1.5*iqr)|(grp['HandshakeTime']>q3+1.5*iqr)
    count = mask.sum()
    pct = 100*count/len(grp)
    out.append({'Protocol':proto,'Level':lvl,'Delay_ms':delay,'KEM':kem,'Outliers':count,'Total':len(grp),'PctOutliers':pct})
out = pd.DataFrame(out)
out.to_csv(os.path.join(OUTPUT_DIR,'outlier_counts.csv'), index=False)



