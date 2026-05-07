import numpy as np
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec

np.random.seed(42)

# --- Simulation Parameters ---
N_STABLE = 80
N_TOTAL = 100
STABLE_VALUE = 10.0
ANOMALY_VALUE = 13.0
STD_FLOOR = 0.1
THRESHOLD = 2.5
INF_CAP = 29.0

# --- Generate observations ---
observations = np.array([STABLE_VALUE] * N_STABLE + [ANOMALY_VALUE] * (N_TOTAL - N_STABLE))

# Rolling Z-score — two scenarios computed independently
# Scenario A (no floor): uses the window std as-is; if std==0, z is undefined → we mark it inf
# Scenario B (with floor): std is clamped to STD_FLOOR before dividing
z_no_floor = []
z_with_floor = []

for i in range(1, N_TOTAL + 1):
    window = observations[:i]
    mean = np.mean(window)
    std  = np.std(window)
    current = observations[i - 1]

    # No floor: std=0 → division undefined → treat as inf
    if std < 1e-12:
        z_nf = np.inf if abs(current - mean) > 1e-12 else 0.0
    else:
        z_nf = abs((current - mean) / std)

    # With floor
    eff_std = max(std, STD_FLOOR)
    z_wf = abs((current - mean) / eff_std)

    z_no_floor.append(z_nf)
    z_with_floor.append(z_wf)

x = np.arange(1, N_TOTAL + 1)
z_with_floor = np.array(z_with_floor)

# Identify the first inf point
inf_indices = [i for i, z in enumerate(z_no_floor) if np.isinf(z)]
inf_start_idx = inf_indices[0] if inf_indices else N_STABLE
inf_start_x   = x[inf_start_idx]

# Build plottable version: cap inf at INF_CAP, keep finite values as-is
z_no_floor_plot = np.array([INF_CAP if np.isinf(z) else z for z in z_no_floor])

# --- Plot ---
fig = plt.figure(figsize=(14, 8))
fig.patch.set_facecolor('#0f1117')

gs = gridspec.GridSpec(2, 1, hspace=0.32)
ax_obs = fig.add_subplot(gs[0])
ax_z   = fig.add_subplot(gs[1])

for ax in [ax_obs, ax_z]:
    ax.set_facecolor('#1a1d27')
    ax.tick_params(colors='#aaaaaa', labelsize=11)
    ax.xaxis.label.set_color('#aaaaaa')
    ax.yaxis.label.set_color('#aaaaaa')
    for spine in ax.spines.values():
        spine.set_edgecolor('#2e3248')
    ax.grid(color='#2e3248', linewidth=0.5, linestyle='--', alpha=0.6)

# --- Top panel ---
ax_obs.plot(x[:N_STABLE], observations[:N_STABLE],
            color='#4fc3f7', linewidth=1.8, label='Stable observations')
ax_obs.plot(x[N_STABLE:], observations[N_STABLE:],
            color='#ff6b6b', linewidth=1.8, linestyle='--', label='Anomalous observations')
ax_obs.axvline(x=inf_start_x, color='#ff6b6b', linewidth=1, linestyle=':', alpha=0.6)
ax_obs.annotate('Spike begins', xy=(inf_start_x, ANOMALY_VALUE),
                xytext=(inf_start_x - 18, STABLE_VALUE + 0.3),
                color='#ff6b6b', fontsize=11,
                arrowprops=dict(arrowstyle='->', color='#ff6b6b', lw=1.2))
ax_obs.set_ylabel('Metric Value', fontsize=12)
ax_obs.set_title('Observed Metric — Perfectly Stable Host with Injected Spike',
                 color='#e0e0e0', fontsize=13, pad=10)
ax_obs.set_ylim(STABLE_VALUE - 1, ANOMALY_VALUE + 1.5)
ax_obs.legend(fontsize=11, facecolor='#1a1d27', edgecolor='#2e3248',
              labelcolor='#cccccc', loc='upper left')
ax_obs.set_xlim(1, N_TOTAL)

# --- Bottom panel ---
# Shade the undefined region
ax_z.axvspan(inf_start_x, N_TOTAL + 1, color='#ff6b6b', alpha=0.10, zorder=1)

# Stable segment of no-floor line (z=0 throughout)
ax_z.plot(x[:inf_start_idx], z_no_floor_plot[:inf_start_idx],
          color='#ff6b6b', linewidth=2.4, zorder=3,
          label='Without STD floor (std = 0 → Z = ∞)')

# Vertical jump to show the instant leap to ∞
ax_z.annotate('', xy=(inf_start_x, INF_CAP), xytext=(inf_start_x, 0),
              arrowprops=dict(arrowstyle='->', color='#ff6b6b', lw=2.4))

# Horizontal line at INF_CAP across the anomaly region
ax_z.plot(x[inf_start_idx:], z_no_floor_plot[inf_start_idx:],
          color='#ff6b6b', linewidth=2.4, zorder=3)

# With-floor line
ax_z.plot(x, z_with_floor, color='#69f0ae', linewidth=2.4, zorder=4,
          label=f'With STD floor (min std = {STD_FLOOR})')

# Detection threshold
ax_z.axhline(y=THRESHOLD, color='#ffd54f', linewidth=1.4, linestyle='--',
             zorder=2, label=f'Detection threshold (Z = {THRESHOLD})')

# Label on the inf line
ax_z.annotate('Z → ∞  (capped at 29 for display)',
              xy=(inf_start_x + 2, INF_CAP),
              xytext=(inf_start_x - 30, INF_CAP - 5),
              color='#ff6b6b', fontsize=11, ha='left',
              arrowprops=dict(arrowstyle='->', color='#ff6b6b', lw=1.2),
              bbox=dict(boxstyle='round,pad=0.3', facecolor='#1a1d27',
                        edgecolor='#ff6b6b', alpha=0.85))

# Y-axis: replace top tick with ∞
ax_z.set_yticks([0, 5, 10, 15, 20, 25, INF_CAP])
ax_z.set_yticklabels(['0', '5', '10', '15', '20', '25', '∞'],
                     fontsize=11, color='#aaaaaa')

ax_z.set_ylabel('Z-Score (|z|)', fontsize=12)
ax_z.set_xlabel('Observation Index', fontsize=12)
ax_z.set_title('Z-Score Comparison — With vs. Without STD Floor',
               color='#e0e0e0', fontsize=13, pad=10)
ax_z.legend(fontsize=11, facecolor='#1a1d27', edgecolor='#2e3248',
            labelcolor='#cccccc', loc='upper left')
ax_z.set_xlim(1, N_TOTAL)
ax_z.set_ylim(-0.5, 32)

plt.suptitle('Effect of STD Floor on Anomaly Detection Sensitivity',
             color='#ffffff', fontsize=15, fontweight='bold')

fig.subplots_adjust(top=0.92)

plt.savefig('std_floor_simulation.png',
            dpi=150, bbox_inches='tight', facecolor=fig.get_facecolor())
plt.show()
print("Plot saved.")