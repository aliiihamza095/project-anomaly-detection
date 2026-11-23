"""EDA and first design-validation test for Report 2 (Group 10, Login Behavior Anomaly Detection).
Reads data/login_data.csv produced by generate_login_data.py (seed 42). Evaluation labels (is_anomaly,
anomaly_type, benign_event) are used only for plots and scoring, never as detector input."""
import json
from pathlib import Path

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    precision_score, recall_score, f1_score, confusion_matrix,
    average_precision_score,
)

# Resolve paths relative to this script, not the terminal's current directory.
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / 'data'
FIG_DIR = BASE_DIR / 'fig'
FIG_DIR.mkdir(parents=True, exist_ok=True)

plt.rcParams.update({'font.family': 'DejaVu Serif', 'font.size': 8, 'axes.titlesize': 9, 'axes.spines.top': False, 'axes.spines.right': False})

login_path = DATA_DIR / 'login_data.csv'
truth_path = DATA_DIR / 'user_ground_truth.csv'
if not login_path.is_file():
    raise FileNotFoundError(f'Login dataset not found: {login_path}')
if not truth_path.is_file():
    raise FileNotFoundError(f'Ground-truth file not found: {truth_path}')

d = pd.read_csv(login_path, parse_dates=['timestamp'])
u = pd.read_csv(truth_path)

required_d = {
    'timestamp', 'user_id', 'device_id', 'location_category',
    'round_trip_time_ms', 'login_result', 'failed_attempts',
    'is_anomaly', 'anomaly_type', 'benign_event',
}
required_u = {'user_id', 'user_type'}
missing_d = required_d.difference(d.columns)
missing_u = required_u.difference(u.columns)
if missing_d:
    raise ValueError(f'login_data.csv is missing columns: {sorted(missing_d)}')
if missing_u:
    raise ValueError(f'user_ground_truth.csv is missing columns: {sorted(missing_u)}')

d = d.merge(u[['user_id', 'user_type']], on='user_id', how='left', validate='many_to_one')
if d['user_type'].isna().any():
    missing_users = d.loc[d['user_type'].isna(), 'user_id'].unique().tolist()
    raise ValueError(f'No user_type found for user_id values: {missing_users[:10]}')
if d.empty:
    raise ValueError('The login dataset is empty.')
if d['timestamp'].isna().any():
    raise ValueError('Some timestamp values could not be parsed. Check data/login_data.csv.')

d = d.sort_values('timestamp').reset_index(drop=True)
start = d.timestamp.min().normalize()
d['day'] = (d.timestamp - start).dt.days
d['hour'] = d.timestamp.dt.hour + d.timestamp.dt.minute / 60
TYPES = ['day_shift', 'evening', 'night_shift', 'remote_mixed']
LABEL = {'day_shift': 'Day shift', 'evening': 'Evening', 'night_shift': 'Night shift', 'remote_mixed': 'Remote or mixed'}
out = {}

# ---------------- summary numbers
out['rows'] = len(d); out['users'] = d.user_id.nunique(); out['days'] = int(d.day.max() + 1)
out['start'] = str(d.timestamp.min().date()); out['end'] = str(d.timestamp.max().date())
out['anom_rows'] = int(d.is_anomaly.sum()); out['anom_pct'] = round(100 * d.is_anomaly.mean(), 2)
out['anom_types'] = d[d.is_anomaly == 1].anomaly_type.value_counts().to_dict()
out['benign'] = d[d.benign_event != 'none'].benign_event.value_counts().to_dict()
out['fail_rows'] = int((d.login_result == 'failure').sum())
out['per_user'] = d.groupby('user_id').size().agg(['min', 'median', 'max']).to_dict()
out['normal_failed_attempts_ge1_pct'] = round(100 * (d[d.is_anomaly == 0].failed_attempts >= 1).mean(), 1)
by_type = d[d.is_anomaly == 0].groupby('user_type').size()
out['rows_by_type'] = by_type.to_dict()

# ---------------- Fig 1: hour of day by user type (normal records)
fig, ax = plt.subplots(1, 4, figsize=(6.4, 1.9), sharey=False)
for a, t in zip(ax, TYPES):
    h = d[(d.user_type == t) & (d.is_anomaly == 0)].hour
    a.hist(h, bins=np.arange(0, 25, 1), color='#4C72B0', edgecolor='white', linewidth=0.4)
    a.set_title(LABEL[t], fontsize=8); a.set_xticks([0, 6, 12, 18, 24]); a.set_xlabel('Hour of day')
ax[0].set_ylabel('Logins')
plt.tight_layout(); plt.savefig(FIG_DIR / 'fig1_hours.png', dpi=220); plt.close()

# ---------------- Fig 2: location category share by user type (normal records)
LOCS = ['campus', 'home_city', 'branch_office', 'public_wifi', 'vpn', 'other_city', 'foreign_unknown']
ct = (
    d[d.is_anomaly == 0]
    .groupby(['user_type', 'location_category']).size()
    .unstack(fill_value=0)
    .reindex(index=TYPES, columns=LOCS, fill_value=0)
)
row_totals = ct.sum(axis=1).replace(0, np.nan)
ct = ct.div(row_totals, axis=0).fillna(0) * 100
fig, a = plt.subplots(figsize=(6.0, 2.4))
left = np.zeros(len(TYPES)); cols = ['#4C72B0', '#55A868', '#8172B2', '#CCB974', '#64B5CD', '#DD8452', '#C44E52']
for loc, c in zip(LOCS, cols):
    a.barh([LABEL[t] for t in TYPES], ct[loc].values, left=left, color=c, label=loc.replace('_', ' '), edgecolor='white', linewidth=0.4)
    left += ct[loc].values
a.set_xlabel('Share of normal logins (%)'); a.invert_yaxis(); a.legend(ncol=4, fontsize=6.5, loc='upper center', bbox_to_anchor=(0.5, -0.28), frameon=False)
plt.tight_layout(); plt.savefig(FIG_DIR / 'fig2_locations.png', dpi=220); plt.close()

# ---------------- Fig 3: injected anomalies and harmless events
fig, ax = plt.subplots(1, 2, figsize=(6.4, 2.2), gridspec_kw={'width_ratios': [1.5, 1]})
at = d[d.is_anomaly == 1].anomaly_type.value_counts()
ax[0].barh([s.replace('_', ' ') for s in at.index], at.values, color='#C44E52'); ax[0].invert_yaxis(); ax[0].set_title('Injected anomalies (labeled 1)')
for i, v in enumerate(at.values): ax[0].text(v + 3, i, str(v), va='center', fontsize=7)
bt = d[d.benign_event != 'none'].benign_event.value_counts()
ax[1].barh([s.replace('benign_', '').replace('_', ' ') for s in bt.index], bt.values, color='#55A868'); ax[1].invert_yaxis(); ax[1].set_title('Harmless events (labeled 0)')
for i, v in enumerate(bt.values): ax[1].text(v + 1, i, str(v), va='center', fontsize=7)
ax[0].set_xlabel('Records'); ax[1].set_xlabel('Records')
plt.tight_layout(); plt.savefig(FIG_DIR / 'fig3_events.png', dpi=220); plt.close()

# ---------------- Fig 4: round-trip time by location
order = ['campus', 'branch_office', 'home_city', 'public_wifi', 'other_city', 'vpn', 'foreign_unknown']
fig, a = plt.subplots(figsize=(6.0, 2.3))
a.boxplot([d[d.location_category == l].round_trip_time_ms for l in order], tick_labels=[l.replace('_', '\n') for l in order], showfliers=False,
          patch_artist=True, boxprops=dict(facecolor='#9ecae1'), medianprops=dict(color='black'))
a.set_ylabel('Round-trip time (ms)')
plt.tight_layout(); plt.savefig(FIG_DIR / 'fig4_rtt.png', dpi=220); plt.close()
out['rtt_median'] = {l: int(d[d.location_category == l].round_trip_time_ms.median()) for l in order}

# ---------------- time split and profiles (training window only)
SPLIT = 31
train = d[d.day < SPLIT].copy()
test = d[d.day >= SPLIT].copy()
if train.empty or test.empty:
    available_days = int(d.day.max() + 1)
    raise ValueError(
        f'The fixed time split (day {SPLIT}) needs records before and after day {SPLIT}. '
        f'The dataset currently spans only {available_days} day(s). Adjust SPLIT if needed.'
    )
out['train_rows'] = len(train); out['test_rows'] = len(test)
out['train_anom'] = int(train.is_anomaly.sum()); out['test_anom'] = int(test.is_anomaly.sum())
prof = {}
for uid, g in train.groupby('user_id'):
    ang = g.hour.values / 24 * 2 * np.pi
    s, c = np.sin(ang).mean(), np.cos(ang).mean()
    R = max(np.hypot(s, c), 1e-6)
    mean_h = (np.arctan2(s, c) % (2 * np.pi)) * 24 / (2 * np.pi)
    std_h = max(np.sqrt(-2 * np.log(min(R, 0.999999))) * 24 / (2 * np.pi), 1.0)
    prof[uid] = dict(mean_h=mean_h, std_h=std_h, devices=set(g.device_id),
                     loc_freq=(g.location_category.value_counts(normalize=True)).to_dict())
rtt_summary = train.groupby('location_category').round_trip_time_ms.agg(['mean', 'std'])
# A category with one training record has an undefined standard deviation.
rtt_summary['std'] = rtt_summary['std'].replace(0, np.nan)
rtt_global_mean = float(train.round_trip_time_ms.mean())
rtt_global_std = float(train.round_trip_time_ms.std())
if not np.isfinite(rtt_global_std) or rtt_global_std == 0:
    rtt_global_std = 1.0

def features(df):
    f = pd.DataFrame(index=df.index)
    # Every user should have a profile from the training window.
    unknown_users = set(df.user_id.unique()) - set(prof)
    if unknown_users:
        raise ValueError(
            'These users have no records in the training window, so no baseline profile '
            f'can be built: {sorted(unknown_users)[:10]}'
        )

    mh = df.user_id.map(lambda x: prof[x]['mean_h'])
    sh = df.user_id.map(lambda x: prof[x]['std_h'])
    dev = np.abs(((df.hour - mh + 12) % 24) - 12)
    f['hour_dev'] = dev
    f['hour_z'] = dev / sh
    f['new_device'] = [
        int(device not in prof[uid]['devices'])
        for uid, device in zip(df.user_id, df.device_id)
    ]
    f['loc_rarity'] = [
        -np.log(prof[uid]['loc_freq'].get(location, 0) + 0.005)
        for uid, location in zip(df.user_id, df.location_category)
    ]
    f['failed_attempts'] = df.failed_attempts

    def rtt_z_value(value, location):
        if location in rtt_summary.index:
            mean = rtt_summary.loc[location, 'mean']
            std = rtt_summary.loc[location, 'std']
        else:
            mean, std = rtt_global_mean, rtt_global_std
        if pd.isna(mean):
            mean = rtt_global_mean
        if pd.isna(std) or std == 0:
            std = rtt_global_std
        return (value - mean) / std

    f['rtt_z'] = [
        rtt_z_value(value, location)
        for value, location in zip(df.round_trip_time_ms, df.location_category)
    ]

    # Rolling velocity features use only the current and preceding events.
    tmp = df[['user_id', 'timestamp']].copy()
    tmp['fail'] = (df.login_result == 'failure').astype(int)
    tmp['one'] = 1
    return f, tmp

full = d.copy()
F, tmp = features(full)
def rolling(col, win):
    res = pd.Series(index=full.index, dtype=float)
    for uid, g in tmp.groupby('user_id'):
        s = g.set_index('timestamp')[col].rolling(win, min_periods=1).sum()
        res.loc[g.index] = s.values
    return res
F['fails_10m'] = rolling('fail', '10min'); F['logins_60m'] = rolling('one', '60min')
FEATS = ['hour_dev', 'hour_z', 'new_device', 'loc_rarity', 'failed_attempts', 'rtt_z', 'fails_10m', 'logins_60m']
Ftr = F.loc[train.index, FEATS].copy()
Fte = F.loc[test.index, FEATS].copy()
# Keep model inputs finite; imputation values are learned from training data only.
Ftr = Ftr.replace([np.inf, -np.inf], np.nan)
Fte = Fte.replace([np.inf, -np.inf], np.nan)
train_medians = Ftr.median().fillna(0)
Ftr = Ftr.fillna(train_medians).fillna(0)
Fte = Fte.fillna(train_medians).fillna(0)
y = test.is_anomaly.astype(int).values
if Ftr.empty or Fte.empty:
    raise ValueError('Training or test feature table is empty; check the time split.')

# ---------------- statistical detector: z-score and rule thresholds
def stat_flags(f):
    r1 = (f.hour_z > 3).astype(int); r2 = f.new_device.astype(int); r3 = (f.loc_rarity > 4.6).astype(int); r4 = (f.fails_10m >= 5).astype(int)
    return pd.DataFrame({'unusual_hour': r1, 'new_device': r2, 'rare_location': r3, 'failure_burst': r4})
fl = stat_flags(Fte); n_rules = fl.sum(axis=1); pred_stat = (n_rules >= 1).astype(int).values

# ---------------- Isolation Forest (global model on user-relative features)
iso = IsolationForest(
    n_estimators=100, max_samples=min(256, len(Ftr)), random_state=42
).fit(Ftr)
sc_tr = -iso.score_samples(Ftr); sc_te = -iso.score_samples(Fte)
thr = np.quantile(sc_tr, 0.96); pred_if = (sc_te > thr).astype(int)
out['if_threshold'] = float(thr)

def evaluate(pred, name, score=None):
    cm = confusion_matrix(y, pred, labels=[0, 1])
    res = dict(precision=round(precision_score(y, pred, zero_division=0), 3), recall=round(recall_score(y, pred, zero_division=0), 3), f1=round(f1_score(y, pred, zero_division=0), 3),
               tn=int(cm[0, 0]), fp=int(cm[0, 1]), fn=int(cm[1, 0]), tp=int(cm[1, 1]))
    if score is not None:
        res['pr_auc'] = (
            round(average_precision_score(y, score), 3)
            if np.any(y == 1) else None
        )
    t = test.assign(p=pred)
    res['recall_by_type'] = t[t.is_anomaly == 1].groupby('anomaly_type').p.mean().round(2).to_dict()
    res['benign_flagged'] = t[t.benign_event != 'none'].groupby('benign_event').p.mean().round(2).to_dict()
    res['benign_n'] = t[t.benign_event != 'none'].groupby('benign_event').size().to_dict()
    normal_count = res['tn'] + res['fp']
    res['fp_pct_of_normal'] = round(100 * res['fp'] / normal_count, 2) if normal_count else 0.0
    out[name] = res
evaluate(pred_stat, 'stat', score=n_rules.values)
evaluate(pred_if, 'iforest', score=sc_te)
out['stat_rule_counts'] = fl.sum().to_dict()
out['test_by_type'] = test[test.is_anomaly == 1].anomaly_type.value_counts().to_dict()

# ---------------- Fig 5: feature separation (normal vs anomaly) on test window
fig, ax = plt.subplots(1, 3, figsize=(6.4, 2.0))
nrm = Fte[y == 0]; ano = Fte[y == 1]
for a, col, ttl, clip in zip(ax, ['hour_z', 'loc_rarity', 'fails_10m'], ['Hour deviation (z)', 'Location rarity', 'Failures in 10 min'], [12, 7, 16]):
    bins = np.linspace(0, clip, 25)
    if len(nrm):
        a.hist(np.clip(nrm[col], 0, clip), bins=bins, alpha=0.7, density=True, color='#4C72B0', label='normal')
    if len(ano):
        a.hist(np.clip(ano[col], 0, clip), bins=bins, alpha=0.7, density=True, color='#C44E52', label='anomaly')
    a.set_title(ttl, fontsize=8); a.set_yscale('log')
ax[0].set_ylabel('Density (log)'); ax[0].legend(fontsize=6.5, frameon=False)
plt.tight_layout(); plt.savefig(FIG_DIR / 'fig5_features.png', dpi=220); plt.close()

# ---------------- Fig 7: recall by anomaly type for both detectors
types = list(out['test_by_type'].keys())
fig, a = plt.subplots(figsize=(6.0, 2.3)); w = 0.38; x = np.arange(len(types))
a.bar(x - w/2, [out['stat']['recall_by_type'].get(t, 0) for t in types], w, label='Statistical / rule-based', color='#4C72B0')
a.bar(x + w/2, [out['iforest']['recall_by_type'].get(t, 0) for t in types], w, label='Isolation Forest', color='#DD8452')
a.set_xticks(x); a.set_xticklabels([t.replace('_', '\n') for t in types]); a.set_ylabel('Recall'); a.set_ylim(0, 1.05); a.legend(fontsize=7, frameon=False)
plt.tight_layout(); plt.savefig(FIG_DIR / 'fig7_recall.png', dpi=220); plt.close()
results_path = BASE_DIR / 'eda_results.json'
with results_path.open('w', encoding='utf-8') as result_file:
    json.dump(out, result_file, indent=1, default=str)

print(json.dumps(out, indent=1, default=str)[:6000])
print(f'\nFigures saved in: {FIG_DIR}')
print(f'Results saved to: {results_path}')
