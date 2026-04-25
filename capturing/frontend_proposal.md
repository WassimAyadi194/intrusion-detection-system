# Antigravity IDS — Frontend Architecture Proposal

---

## 1. Frontend Architecture Proposal

### Navigation Model
A **single-window, left-sidebar tab navigation** with 5 sections. No routing overhead, no web browser — this is a local desktop tool and should behave like one.

```
┌──────────────────────────────────────────────────────────────────┐
│  Sidebar (collapsible)   │  Main Content Area                   │
│  ─────────────────────── │                                       │
│  [●] Dashboard           │  ← Active view renders here          │
│  [●] Alerts              │                                       │
│  [●] Host Explorer       │                                       │
│  [●] Baseline & Metrics  │                                       │
│  [●] System Logs         │                                       │
│                          │                                       │
│  ─────────────────────── │                                       │
│  [Status bar]            │  Queue depths, capture state, uptime  │
└──────────────────────────────────────────────────────────────────┘
```

### Page Breakdown

#### Page 1 — Dashboard (default view)
Live operational overview. Refreshes every 2–5 seconds by polling the SQLite DB.

- **Top strip**: 4 KPI tiles — alerts in last 60s, active hosts seen, queue depths (engine + collector), capture state (RUNNING / STALLED / STOPPED).
- **Center-left**: Real-time alert feed (last 50 alerts, reverse-chronological, color-coded by severity).
- **Center-right**: Per-metric sparklines for the top 3 most active hosts (packet_count, syn_count, unique_ports, unique_destinations) — pulled from `live_metrics`.
- **Bottom bar**: Heartbeat indicator + stall warning badge (maps to the `StallMonitor` / `QueueMonitor` backend threads).

#### Page 2 — Alerts
Historical alert browser sourced from the `alerts` table.

- Filterable table: by `severity`, `metric` (type), `host_ip`, time range.
- Row expansion: shows full `description`, `value`, `baseline_avg ± baseline_std` for anomaly alerts, `novelty` for connection alerts.
- Severity column drives row background color (no ambiguity, at-a-glance triage).
- Alert detail panel (right-side drawer or bottom pane): when clicking a `PORT_SCAN` alert, shows the scan direction (vertical/horizontal) from the `metric` field; for `ANOMALY` alerts shows the Z-score reconstructed as `(value - baseline_avg) / baseline_std`.

#### Page 3 — Host Explorer
Per-host deep-dive. Central object is a **host IP** selected from a list.

- Host list panel (left): all IPs seen in `live_metrics` within a configurable lookback window.
- Detail panel (right):
  - Baseline profile: `avg_syn ± std_syn`, `avg_unique_ports ± std_unique_ports`, etc., from the `baseline` table.
  - Metric history chart: all 4 metrics over time for that host from `live_metrics`.
  - Alert history: filtered `alerts` table rows for that `host_ip`.
  - Novelty badge: `new` / `known` / `recurring` / `loopback` from the most recent connection alert for that host.

#### Page 4 — Baseline & Metrics
For understanding the statistical state of the system — directly maps to what `baseline_trainer.py` and `anomaly_detector.py` operate on.

- **Baseline table**: scrollable read-only table showing every row in the `baseline` table with all 8 stats columns + `last_updated`.
- **Live metrics timeline**: stacked time-series chart showing metric windows across all hosts (last 24h, pruned to retention window).
- **Anomaly threshold overlay**: draw a horizontal reference line at `mean + 2.5*std` for any selected metric/host pair so the user can visually see where the Z-score threshold sits.
- **Re-train button**: triggers `baseline_trainer.py` on demand (does not exist as a UI button today, but the trainer is already a standalone callable — this is the *only* backend-adjacent UI action proposed).

#### Page 5 — System Logs
Read-only view of the `logs` table.

- Filterable by `level` (DEBUG/INFO/WARNING/ERROR), `module`, and time range.
- Auto-scroll toggle (useful for live tail mode).
- WARNING/ERROR rows highlighted in yellow/red.
- No editing — purely observational.

---

## 2. Key Metrics & Data to Display

All data is grounded in what the DB actually stores. Nothing invented.

### From `alerts` table
| Field | What to show |
|---|---|
| `severity` | Color-coded badge: CRITICAL=red, HIGH=orange, MEDIUM=yellow, INFO=grey |
| `metric` / `type` | Alert type label: `PORT_SCAN`, `PACKET_FLOOD`, `ANOMALY`, `CONNECTION` |
| `host_ip` | Clickable — navigates to Host Explorer for that IP |
| `description` | Full human-readable message |
| `value` + `baseline_avg` + `baseline_std` | For anomaly alerts only: show as `450 SYN/s (baseline: ~12 ± 3.2)` |
| `novelty` | For connection alerts only: `new` / `known` / `recurring` / `loopback` tag |
| `timestamp` | Relative time (e.g., "3s ago") + absolute on hover |

### From `live_metrics` table
| Field | What to show |
|---|---|
| `syn_count` | Per-host SYN rate per 10s window |
| `unique_ports` | Port diversity per host per window |
| `unique_destinations` | Destination spread per host |
| `packet_count` | Total packet volume per host per window |
| `timestamp` | X-axis for all time-series charts |

### From `baseline` table
| Field | What to show |
|---|---|
| `avg_syn`, `std_syn` | Normal SYN rate range for that host |
| `avg_unique_ports`, `std_unique_ports` | Normal port diversity |
| `avg_unique_destinations`, `std_unique_destinations` | Normal destination spread |
| `avg_packet_count`, `std_packet_count` | Normal packet volume |
| `last_updated` | Staleness indicator (warn if > 1h old) |

### From `logs` table
| Field | What to show |
|---|---|
| `level` | Color-coded tag |
| `module` | Which subsystem emitted the log |
| `message` | Full log text |
| `timestamp` | Chronological ordering |

### System health (derived, not from DB — from queue monitoring threads)
The heartbeat thread logs queue depths to `logs`. Parse those log entries to show:
- `engine_queue` depth
- `collector_queue` depth
- Last heartbeat timestamp (stale > 65s = problem)

---

## 3. Recommended Visualizations

### 3.1 Alert Severity Distribution — Donut Chart
**Why**: At a glance, is the system seeing mostly noise (INFO/MEDIUM) or real threats (HIGH/CRITICAL)? A bar chart would work, but the donut is more space-efficient in the dashboard's KPI strip.
**Data**: Aggregate `alerts` by `severity` for the last N minutes. Configurable time window.

### 3.2 Per-Host Metric Sparklines — Line Charts (small multiples)
**Why**: The `live_metrics` table is a rolling 10-second window time series. The most natural representation is a compact line chart per host, per metric. Show the last 30–60 windows (5–10 minutes). This directly reflects how `flush_window()` operates.
**Key overlay**: Draw the baseline `mean ± 2.5*std` band on each sparkline. Any data point breaching that band visually corresponds to an actual anomaly alert having fired.

### 3.3 Alert Timeline — Horizontal Event Strip
**Why**: Alerts are discrete events on a time axis. A scatter/dot chart on a time axis (like a Gantt without duration) lets the user see clustering — e.g., a burst of HIGH alerts from 10:02–10:04 indicating a sustained port scan. Coloring by severity gives immediate density insight.
**Data**: `alerts.timestamp` + `alerts.severity`, last 1 hour by default.

### 3.4 Host Activity Heatmap — Grid (Host × Metric)
**Why**: When monitoring 10+ hosts, individual sparklines become impractical. A heatmap where rows = host IPs and columns = the 4 metrics, with cell color intensity proportional to Z-score deviation from baseline, gives a single-screen threat surface view.
**Data**: Computed client-side from `live_metrics` latest window + `baseline` table.

### 3.5 Baseline Profile — Bar Chart with Error Bars
**Why**: For each host, `baseline` has mean + std per metric. A bar chart with ±1 std error bars is the most direct visual of "what is normal for this host." This appears in the Host Explorer page.

### 3.6 Queue Depth — Real-Time Gauge or Sparkline
**Why**: Queue depth directly indicates processing lag. The `QueueMonitor` warns at 500 items; show a gauge with a 500-item danger zone marker. Poll from heartbeat log entries.

---

## 4. User Interaction & UX Flow

### Primary workflow: Alert Triage
1. User opens Dashboard → sees alert feed and KPI tiles.
2. A `CRITICAL` anomaly alert appears for `192.168.1.200` → user clicks the host IP.
3. Navigated to Host Explorer for that IP → sees:
   - The metric in question (`syn_count = 450`) vs. its baseline (`avg=12, std=3.2`).
   - The metric time-series chart showing the spike.
   - The full alert history for that host.
4. User decides it's a real threat or a false positive.

### Filters (Alerts page)
- **Severity multi-select**: checkboxes for MEDIUM / HIGH / CRITICAL (INFO/LOW excluded from DB, so no filter needed).
- **Metric/type dropdown**: `port_scan`, `packet_flood`, `anomaly`, `connection`.
- **Host IP free-text**: substring match on `host_ip`.
- **Time range picker**: presets (last 1h, 6h, 24h) + custom range.

### Host Explorer interactions
- **Host list sort**: by most recent alert, by most traffic, by novelty (`new` hosts first).
- **Metric selector**: choose which of the 4 metrics to display in the history chart.
- **Lookback slider**: how many hours of `live_metrics` to show (1–24, constrained to retention window).
- **Baseline age warning**: if `last_updated` > 1h, show a warning badge prompting re-training.

### System Logs interactions
- **Level filter**: checkboxes for DEBUG / INFO / WARNING / ERROR.
- **Module filter**: dropdown populated from distinct `module` values in the DB.
- **Auto-scroll toggle**: follow latest entries vs. free scroll.
- **Search**: substring filter on `message`.

### Controls that map to real system behavior
- **Re-train baseline** button (Baseline & Metrics page): calls `BaselineTrainer.train()`. This is the only write-side action. Disable when fewer than 10 windows exist for a host (maps to the trainer's minimum window requirement).
- **No start/stop capture from UI** (unless you add IPC — don't over-engineer it).

---

## 5. Alerting & Monitoring Interface Design

### Real-time vs Historical
| Data type | Cadence | Presentation |
|---|---|---|
| New alerts | Poll `alerts` table every 2s, filter by `timestamp > last_seen_id` | Live feed (Dashboard), appended to top |
| Live metrics | Poll `live_metrics` latest window per host every 10s (matches flush_window) | Sparklines on Dashboard, updated in-place |
| Baseline | Read once on host selection, re-read on demand | Static profile in Host Explorer |
| System logs | Poll `logs` table every 3s | Auto-scroll log view on System Logs page |
| Queue depth / heartbeat | Parse heartbeat log entries (every 60s from backend) | Gauge on status bar |

### Alert surfacing rules (mirror AlertGate logic in the UI)
- **CRITICAL**: Immediately surface as a full-width banner notification at the top of the window. Auto-dismiss after 30s or on user acknowledgment.
- **HIGH**: Red badge on the Alerts tab + new row at top of alert feed. No banner.
- **MEDIUM**: Orange badge count increment on Alerts tab. No banner.
- **INFO/LOW**: Never in the Alerts table (not written to DB). Only visible in System Logs.

This mirrors the backend's severity-stratified persistence exactly — don't invent a separate UI-level severity filter that contradicts what the backend already decided.

### Anomaly alert display
For anomaly alerts, the `baseline_avg` and `baseline_std` fields are populated. Display them as:
```
[CRITICAL] ANOMALY — syn_count
192.168.1.200 — 450 SYN packets in 10s
Baseline: ~12.0 ± 3.2   Z-score: ≈ 136   ← reconstructed client-side
```
The reconstructed Z-score `(value - baseline_avg) / max(baseline_std, 0.1)` gives the user the actual deviation magnitude, which is more informative than the severity label alone.

### Stall / health warnings
- If the latest heartbeat log entry is older than 65 seconds: show a persistent yellow banner "**Capture may be stalled** — no heartbeat in Xs."
- If any queue depth log entry shows > 500 items: amber queue depth indicator on the status bar.
- If flush_window duration exceeded WINDOW_SIZE (logged as WARNING by the backend): surface in the System Logs page with a highlighted row and a dedicated "Performance Warnings" counter in the status bar.

---

## 6. Tech Stack Recommendation: PySide6 vs PyQt6

### Comparison

| Dimension | PySide6 | PyQt6 |
|---|---|---|
| **License** | LGPL 3 (commercial use free; no copyleft obligation for linking) | GPL 3 / commercial (GPL requires open-sourcing your app OR paying Riverbank for a license) |
| **Maintainer** | Qt Company (same company that builds Qt itself) | Riverbank Computing (third-party binding) |
| **API surface** | Virtually identical to PyQt6 | Virtually identical to PySide6 |
| **Qt version alignment** | Always first-party — new Qt features land in PySide6 simultaneously | Sometimes lags behind Qt releases by weeks/months |
| **Signal/slot syntax** | `Signal`, `Slot` decorators | `pyqtSignal`, `pyqtSlot` decorators |
| **Performance** | Identical — both are thin C++ bindings | Identical |
| **Tooling** | Qt Designer, Qt Creator fully supported | Qt Designer supported |
| **Long-term support** | Backed by Qt Company's own roadmap | Dependent on Riverbank's maintenance bandwidth |
| **Community size** | Growing (historically smaller than PyQt) | Historically larger, more Stack Overflow answers |

### Verdict: **Use PySide6**

**Licensing is the decisive factor.** This is an academic project (PFE), but if it ever moves to deployment or open-source publication, PyQt6's GPL would either force you to open-source the entire application or pay a commercial license. PySide6 has no such constraint — LGPL means you can link to it freely.

**First-party alignment is the long-term stability argument.** PySide6 is maintained by The Qt Company, the same team that ships Qt itself. New Qt features, bug fixes, and Python version support land in PySide6 first or simultaneously. PyQt6 is a one-person operation at Riverbank — that's a dependency risk for a multi-year project.

**Performance is a non-argument.** Both are C++ bindings to the same Qt library. There is no measurable runtime difference for a dashboard polling SQLite at 2–10 second intervals.

**Migration cost is near zero.** The API is 99% identical. The only differences are:
- `pyqtSignal` → `Signal`
- `pyqtSlot` → `Slot`
- Some enum access syntax (`Qt.Alignment` vs `Qt.AlignmentFlag`)

**Recommendation for this project specifically**: Start with PySide6. Use `QTimer` for DB polling, `QThread` or `QRunnable` for any blocking DB reads (avoid blocking the GUI thread on SQLite queries), and `QChart` / `QtCharts` for the sparklines and timeline — it's bundled with PySide6 and requires no extra dependency. Use `QTableView` + `QAbstractTableModel` for the alerts and logs tables rather than `QTableWidget` — it scales to thousands of rows without UI freeze.

---

> **Summary of constraints respected**: Every UI element, data field, and visualization in this proposal maps to an existing table column, a real backend behavior, or a real alert/log format. No invented endpoints, no websockets, no push APIs — SQLite polling is the correct access pattern for a system that already uses WAL mode and connection-per-use.
