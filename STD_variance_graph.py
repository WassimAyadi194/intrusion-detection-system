import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np
import math

np.random.seed(42)
t = np.arange(100)
spike_idx = 70

# High variance signal — very noisy baseline
high_var = 50 + np.random.normal(0, 20, 100)

# Low variance signal — extremely stable baseline
low_var = 50 + np.random.normal(0, 0.5, 100)

# Same absolute spike for both
spike_value = 85
high_var[spike_idx] = spike_value
low_var[spike_idx] = spike_value

def compute_mean(values):
    return sum(values) / len(values)

def compute_stddev(values, mean):
    if len(values) < 2:
        return 0.0
    variance = sum((v - mean) ** 2 for v in values) / len(values)
    return math.sqrt(variance)

# Compute stats
mean_h = compute_mean(high_var)
std_h = compute_stddev(high_var, mean_h)
eff_std_h = max(std_h, 0.1)
z_h = (high_var[spike_idx] - mean_h) / eff_std_h

mean_l = compute_mean(low_var)
std_l = compute_stddev(low_var, mean_l)
eff_std_l = max(std_l, 0.1)
z_l = (low_var[spike_idx] - mean_l) / eff_std_l

# ── Plot ──────────────────────────────────────────────────────────────────────
fig, axs = plt.subplots(2, 1, figsize=(12, 8), sharex=True)
fig.patch.set_facecolor('#0f0f1a')

SPIKE_COLOR   = '#ff4d4d'
HIGH_COLOR    = '#4da6ff'
LOW_COLOR     = '#4dffb0'
MEAN_COLOR    = '#ffd700'
BAND_ALPHA    = 0.15
ANNOT_ALPHA   = 0.85

for ax in axs:
    ax.set_facecolor('#16162a')
    ax.tick_params(colors='#aaa')
    ax.spines[:].set_color('#333')

# ── Top: High Variance ────────────────────────────────────────────────────────
ax = axs[0]

# σ bands (1, 2, 3)
for k, alpha in [(3, 0.06), (2, 0.10), (1, 0.18)]:
    ax.fill_between(t, mean_h - k*std_h, mean_h + k*std_h,
                    color=HIGH_COLOR, alpha=alpha)

ax.plot(t, high_var, color=HIGH_COLOR, lw=1.2, label='Signal', zorder=2)
ax.axhline(mean_h, color=MEAN_COLOR, linestyle='--', lw=1.2, label=f'Mean = {mean_h:.1f}')

# Spike point
ax.plot(spike_idx, high_var[spike_idx], 'o',
        color=SPIKE_COLOR, markersize=10, zorder=5, label=f'Anomaly = {spike_value}')

# Annotate Z-score with a bracket
ax.annotate('', xy=(spike_idx + 1.5, spike_value),
            xytext=(spike_idx + 1.5, mean_h),
            arrowprops=dict(arrowstyle='<->', color=SPIKE_COLOR, lw=1.8))
ax.text(spike_idx + 3, (spike_value + mean_h) / 2,
        f'Z = {z_h:.1f}σ\n(blends in)',
        color=SPIKE_COLOR, fontsize=10, va='center', alpha=ANNOT_ALPHA,
        bbox=dict(boxstyle='round,pad=0.3', fc='#0f0f1a', ec=SPIKE_COLOR, alpha=0.7))

ax.set_title(f'High Variance (σ = {std_h:.1f})  →  Spike is only Z = {z_h:.1f}  →  Low Sensitivity',
             color='white', fontsize=12, pad=8)
ax.legend(facecolor='#1e1e30', labelcolor='white', framealpha=0.8, loc='upper left')
ax.set_ylabel('Value', color='#aaa')
ax.set_ylim(mean_h - 4*std_h, mean_h + 4*std_h + 5)

# σ labels on y-axis right side
for k in [1, 2, 3]:
    for sign, label in [(1, f'+{k}σ'), (-1, f'−{k}σ')]:
        ax.text(101, mean_h + sign * k * std_h, label,
                color=HIGH_COLOR, fontsize=7, va='center', alpha=0.6)

# ── Bottom: Low Variance ──────────────────────────────────────────────────────
ax = axs[1]

# σ bands (1, 2, 3)
for k, alpha in [(3, 0.06), (2, 0.10), (1, 0.18)]:
    ax.fill_between(t, mean_l - k*std_l, mean_l + k*std_l,
                    color=LOW_COLOR, alpha=alpha)

ax.plot(t, low_var, color=LOW_COLOR, lw=1.2, label='Signal', zorder=2)
ax.axhline(mean_l, color=MEAN_COLOR, linestyle='--', lw=1.2, label=f'Mean = {mean_l:.1f}')

# Spike point
ax.plot(spike_idx, low_var[spike_idx], 'o',
        color=SPIKE_COLOR, markersize=10, zorder=5, label=f'Anomaly = {spike_value}')

# Annotate Z-score with a bracket
ax.annotate('', xy=(spike_idx + 1.5, spike_value),
            xytext=(spike_idx + 1.5, mean_l),
            arrowprops=dict(arrowstyle='<->', color=SPIKE_COLOR, lw=1.8))
ax.text(spike_idx + 3, (spike_value + mean_l) / 2,
        f'Z = {z_l:.1f}σ',
        color=SPIKE_COLOR, fontsize=10, va='center', alpha=ANNOT_ALPHA,
        bbox=dict(boxstyle='round,pad=0.3', fc='#0f0f1a', ec=SPIKE_COLOR, alpha=0.7))

ax.set_title(f'Low Variance (σ = {std_l:.2f})  →  Spike is Z = {z_l:.1f}  →  High Sensitivity',
             color='white', fontsize=12, pad=8)
ax.legend(facecolor='#1e1e30', labelcolor='white', framealpha=0.8, loc='upper left')
ax.set_ylabel('Value', color='#aaa')
ax.set_xlabel('Time', color='#aaa')

# Keep y-axis tight so the spike dominates visually
ax.set_ylim(mean_l - 5, spike_value + 5)

# σ labels on y-axis right side
for k in [1, 2, 3]:
    for sign, label in [(1, f'+{k}σ'), (-1, f'−{k}σ')]:
        y = mean_l + sign * k * std_l
        if ax.get_ylim()[0] < y < ax.get_ylim()[1]:
            ax.text(101, y, label, color=LOW_COLOR, fontsize=7, va='center', alpha=0.6)

# ── Super-title ───────────────────────────────────────────────────────────────
fig.suptitle(
    'Same Absolute Spike, Different Z-Scores',
    color='white', fontsize=14, y=0.99, fontweight='bold'
)

plt.tight_layout()
plt.savefig('anomaly_zscore.png', dpi=150,
            bbox_inches='tight', facecolor=fig.get_facecolor())
plt.show()
print(f"High variance: mean={mean_h:.1f}, std={std_h:.1f}, Z={z_h:.1f}")
print(f"Low  variance: mean={mean_l:.1f}, std={std_l:.2f}, Z={z_l:.1f}")