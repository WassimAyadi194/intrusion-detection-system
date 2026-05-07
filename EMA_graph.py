import matplotlib.pyplot as plt
import numpy as np

np.random.seed(42)
t = np.arange(0, 60)

observations = 10 + 0.15 * t + np.random.normal(0, 1, len(t))
observations[45:47] = [35, 38]  # spike

# EMA with low alpha (stable baseline)
alpha = 0.1
ema = np.zeros_like(observations)
ema[0] = observations[0]

for i in range(1, len(observations)):
    ema[i] = alpha * observations[i] + (1 - alpha) * ema[i - 1]

# EMA with higher alpha (more reactive baseline)
alpha2 = 0.5
ema_fast = np.zeros_like(observations)
ema_fast[0] = observations[0]

for i in range(1, len(observations)):
    ema_fast[i] = alpha2 * observations[i] + (1 - alpha2) * ema_fast[i - 1]

plt.figure(figsize=(10, 5))

plt.plot(t, observations, 'o', color='blue', markersize=4, label='Observations')
plt.plot(t, ema, '-', color='red', linewidth=2, label=f'EMA (α={alpha})')
plt.plot(t, ema_fast, '-', color='green', linewidth=2, label=f'EMA (α={alpha2})')

plt.xlabel('Time')
plt.ylabel('Metric Value')
plt.title('EMA Baseline Evolution Comparison')
plt.legend()
plt.grid(False)

plt.annotate('Spike absorbed\n(low α)', xy=(46, 36), xytext=(35, 25),
             arrowprops=dict(arrowstyle='->', color='black'))

plt.tight_layout()
plt.show()