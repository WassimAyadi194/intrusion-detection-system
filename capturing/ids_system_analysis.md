# IDS System — Technical Architecture Analysis

---

## 1. System Overview

This is a **host-deployed, network-level Intrusion Detection System (IDS)** that monitors live TCP/UDP traffic in real time. It operates on two parallel detection planes:

- **Rule-based detection** — stateful, per-packet detectors that fire the moment a threshold or behavioral signature is crossed (port scanning, packet floods, connection tracking).
- **Statistical anomaly detection** — a rolling baseline of normal per-host behavior (SYN rate, port diversity, destination spread, packet volume); deviations beyond a Z-score threshold trigger alerts.

The system is **passive** (read-only on the network), **SQLite-backed**, and **multi-threaded**. It produces structured alerts with severity classifications and persists them to a local database, while also emitting real-time console output.

---

## 2. Architecture Breakdown

```
┌──────────────────────────────────────────────────────────────────────┐
│                           main/main.py                               │
│  Entry point — wires all components together and starts the threads  │
└──────────┬───────────────────────────────────────────────────────────┘
           │
    ┌──────▼──────────────────┐
    │  capturing/             │
    │  ├── interface_utils.py │  Discovers Wi-Fi / Ethernet / Loopback
    │  └── packet_capture.py  │  tshark subprocess → Packet objects → 2 queues
    └──────┬──────────────────┘
           │  engine_queue        collector_queue
    ┌──────▼──────┐         ┌─────▼─────────────────────┐
    │  engine/    │         │  baseline/                 │
    │  ids_engine │         │  ├── data_collector.py     │
    │  .py        │         │  ├── baseline_trainer.py   │
    └──────┬──────┘         │  └── anomaly_detector.py  │
           │                └─────┬─────────────────────┘
    ┌──────▼────────────────┐     │
    │  detections/          │     │ process_anomaly()
    │  ├── port_scan.py     │◄────┘
    │  ├── connection_      │
    │  │   tracking.py      │
    │  ├── packets_         │
    │  │   threshold.py     │
    │  └── alert_gate.py    │ ← single suppression point for ALL alert types
    └──────┬────────────────┘
           │
    ┌──────▼─────────────────┐
    │  database/init_db.py   │  SQLite (WAL mode): baseline, live_metrics,
    │  ids.db                │  alerts, logs tables
    └────────────────────────┘
           │
    ┌──────▼──────────┐
    │  logs/          │
    │  ids_logger.py  │  Dual output: stdout (all levels) + async DB write (INFO+)
    └─────────────────┘
```

### Module Responsibilities

| Module | Role |
|---|---|
| `config.py` | Single source of truth for all tunable constants — DB name, EMA alpha, retry limits, retention window. One edit propagates everywhere. |
| `capturing/interface_utils.py` | Queries `tshark -D` to enumerate network interfaces; selects only Wi-Fi, Ethernet, and Loopback by name. |
| `capturing/packet_capture.py` | Spawns and manages a `tshark` subprocess; parses its pipe-delimited output into lightweight `Packet` objects; feeds two independent queues with backpressure. Runs 4 background threads: capture, stall monitor, queue monitor, heartbeat. |
| `baseline/data_collector.py` | Consumes `collector_queue`; aggregates per-host metrics (SYN count, unique ports, unique destinations, packet count) over 10-second windows; flushes to `live_metrics` DB table and triggers anomaly evaluation. |
| `baseline/baseline_trainer.py` | Offline/on-demand trainer: reads `live_metrics`, computes per-host mean and std dev for each metric, and upserts into the `baseline` table using EMA blending to prevent cold retraining wipes. |
| `baseline/anomaly_detector.py` | Per-host Z-score evaluator: loads baseline from DB (with a 5-min TTL cache), computes Z-score per metric, maps scores to severity levels. Pure logic, no side effects. |
| `engine/ids_engine.py` | Central coordination hub: drains `engine_queue` in batches (≤64 packets per iteration); fans packets out to all rule-based detectors; receives anomaly results from `data_collector`; routes all raw alerts through `AlertGate`; persists approved non-INFO/LOW alerts. |
| `detections/port_scan.py` | Stateful SYN-packet tracker for vertical (one source, many ports on one target) and horizontal (one source, one port, many targets) scan patterns. |
| `detections/connection_tracking.py` | Tracks TCP connection lifecycle (SYN → FIN/RST); classifies sources as new/known/recurring/loopback; emits INFO-level events. |
| `detections/packets_threshold.py` | Sliding-window absolute packet counter per source IP; fires MEDIUM alert on packet flood. |
| `detections/alert_gate.py` | Thread-safe cooldown-based deduplication gate; keyed on `(src, type, metric)`; severity-differentiated cooldowns; CRITICAL always passes. |
| `database/init_db.py` | Creates the 4-table schema, sets WAL journal mode, and handles incremental column migrations via guarded `ALTER TABLE`. |
| `logs/ids_logger.py` | Hierarchical `ids.*` logger namespace; dual sink: synchronous stdout + asynchronous batched DB writer (50 records or 5-second interval, whichever first); drops DB records rather than blocking the hot path. |

---

## 3. Data Flow Pipeline

```
Step 1 — INTERFACE DISCOVERY
  main.py → interface_utils.get_relevant_interfaces()
  └─ Runs `tshark -D`, parses output, filters to Wi-Fi/Ethernet/Loopback

Step 2 — PACKET CAPTURE
  PacketCapture.start_capture(ifaces)
  └─ Spawns tshark as subprocess (pipe-delimited field extraction)
  └─ Reads stdout line-by-line → _parse_tshark_line() → Packet object
  └─ Backpressure check:
       ├─ Hard limit (6000 pkts): DROP ALL
       └─ Soft limit (2000 pkts): DROP loopback-sourced packets only

Step 3 — DUAL QUEUE DISPATCH (fan-out)
  Every accepted Packet is placed on BOTH:
  ├─ engine_queue     → DetectionEngine (rule-based real-time detection)
  └─ collector_queue  → LiveMetricsCollector (statistical baseline collection)

Step 4a — RULE-BASED DETECTION (engine_queue consumer)
  DetectionEngine.run()
    ├─ Drains up to 64 packets per loop iteration
    └─ Per packet → process_packet():
         ├─ PortScanDetector.analyze_packet()
         ├─ ConnectionTracker.analyze_packet()
         └─ PacketThresholdDetector.analyze_packet()
       → raw_alerts[]

Step 4b — METRICS COLLECTION (collector_queue consumer)
  LiveMetricsCollector.run()
    ├─ process_packet(): accumulates SYN count, unique ports/dests, pkt count per src IP
    └─ Every 10s → flush_window():
         ├─ Atomic swap of host_data dict (avoids data races during DB write)
         ├─ Writes snapshot to live_metrics table in SQLite
         └─ Calls engine.process_anomaly(host_ip, **metrics) for each host

Step 5 — ANOMALY DETECTION (triggered by flush_window)
  AnomalyDetector.analyze(host_ip, ...)
    ├─ Loads baseline for host (DB read, cached 5 min)
    └─ For each of 4 metrics: compute Z-score → if |Z| ≥ 2.5 → generate alert dict

Step 6 — ALERT GATING (all paths converge here)
  AlertGate.process(raw_alert)
    ├─ Key: (src, type, metric)
    ├─ CRITICAL: always passes
    ├─ Loopback sources: 60s (INFO/LOW) or 120s (others) cooldown
    ├─ HIGH severity: 5s cooldown
    └─ Everything else: 15s cooldown

Step 7 — PERSISTENCE & OUTPUT
  DetectionEngine._save_alerts(allowed_alerts)
    ├─ INFO/LOW severity: printed to console only, NOT written to DB
    ├─ MEDIUM/HIGH/CRITICAL: persisted to alerts table via retry-wrapped executemany
    └─ Console: `[SEVERITY] TYPE | message`

Step 8 — LOGGING (parallel to all steps)
  ids_logger._DBHandler (background thread)
    ├─ All modules emit via get_logger(__name__)
    └─ INFO+ written to logs table in batches; DEBUG to stdout only
```

---

## 4. Core Logic & Methods

### 4.1 Rule-Based Detectors

#### Port Scan Detection (`port_scan.py`)
Two independent scan types, both operating only on SYN packets within a 30-second sliding window:

- **Vertical scan**: One source IP probing ≥8 distinct ports on a *single destination* → `(src, dst)` keyed table. Fires `HIGH` alert.
- **Horizontal scan**: One source IP probing a single port on ≥10 *distinct destinations* → `(src, dport)` keyed table. Fires `HIGH` alert.

On detection, the tracking state for that key is *deleted* immediately (fire-once behavior within the window). A throttled cleanup pass runs every 10 seconds to evict stale window entries.

#### Packet Flood Detection (`packets_threshold.py`)
Sliding 10-second window per source IP. Counter increments on every packet; if it reaches **3,000 packets within the window**, fires a `MEDIUM` alert and resets the counter. Window rolls over when the 10s boundary passes.

#### Connection Tracking (`connection_tracking.py`)
Tracks TCP connections by `(src, dst, sport, dport)` tuples:
- **SYN**: registers connection, classifies source novelty (`new` / `known` / `recurring` / `loopback`) based on SYN history and baseline host list.
- **FIN/RST**: removes connection record, emits termination event.
- All events are `INFO` severity — primarily for visibility, not threat response.

Novelty classification:
- **loopback**: source is 127.x or ::1
- **recurring**: has sent ≥10 SYNs cumulatively in this session
- **known**: IP exists in the baseline table
- **new**: none of the above

#### Alert Gate (`alert_gate.py`)
A centralized, thread-safe suppression layer. All raw alerts from all detectors — including anomaly alerts — must pass through `AlertGate.process()`. Deduplication key is `(src, type, metric)`. Cooldown is severity-aware:

| Severity | Source | Cooldown |
|---|---|---|
| CRITICAL | any | 0 (always passes) |
| HIGH | external | 5s |
| INFO/LOW | loopback | 60s |
| other | loopback | 120s |
| other | external | 15s |

### 4.2 Statistical Anomaly Detection

#### Baseline Training (`baseline_trainer.py`)
Requires a minimum of **10 metric windows** per host before training. For each host, computes population mean and standard deviation across all `live_metrics` windows for four metrics: SYN count, unique ports, unique destinations, packet count.

**EMA blending** (α = 0.1, configurable): When a prior baseline row exists, new statistics are blended in rather than replaced:

```
updated_stat = (1 - α) × old_stat + α × new_stat
```

With α = 0.1, the baseline retains 90% of its prior value on each retraining, making it resistant to transient traffic spikes while still adapting over time.

#### Anomaly Scoring (`anomaly_detector.py`)
Per metric, a standard Z-score is computed:

```
Z = (observed_value - baseline_mean) / max(baseline_std, 0.1)
```

The `STD_FLOOR = 0.1` prevents division by zero when baseline is perfectly stable.

Severity mapping:

| |Z| Range | Severity |
|---|---|
| ≥ 4.0 | CRITICAL |
| ≥ 3.0 | HIGH |
| ≥ 2.5 | MEDIUM |
| < 2.5 | no alert |

The four checked metrics correspond directly to known attack signals:
- `syn_count` → SYN flood / DoS
- `unique_ports` → port scan
- `unique_destinations` → lateral movement / horizontal spread
- `packet_count` → volumetric flood

---

## 5. Database Design & Usage

**Engine**: SQLite with **WAL (Write-Ahead Logging)** mode — set once at initialization, enabling concurrent reads while writes proceed, critical for a multi-threaded system.

### Tables

#### `baseline`
```
host_ip TEXT PRIMARY KEY
avg_syn, std_syn REAL
avg_unique_ports, std_unique_ports REAL
avg_unique_destinations, std_unique_destinations REAL
avg_packet_count, std_packet_count REAL
last_updated TIMESTAMP
```
One row per observed host IP. Upserted on each training run. This is the "memory" of normal behavior.

#### `live_metrics`
```
id INTEGER PRIMARY KEY AUTOINCREMENT
host_ip TEXT
timestamp INTEGER          ← Unix epoch
syn_count INTEGER
unique_ports INTEGER
unique_destinations INTEGER
packet_count INTEGER
```
Append-only rolling log of 10-second metric windows. Pruned at startup: rows older than **24 hours** are deleted in a single indexed `DELETE` (using a dedicated `timestamp` index). Two indexes: `(host_ip, timestamp)` for training queries, `(timestamp)` for pruning.

#### `alerts`
```
id INTEGER PRIMARY KEY AUTOINCREMENT
host_ip TEXT
metric TEXT
value REAL              ← observed metric value (anomaly only)
baseline_avg REAL NULL  ← baseline context (anomaly only)
baseline_std REAL NULL  ← baseline context (anomaly only)
severity TEXT
timestamp INTEGER
description TEXT
novelty TEXT NULL       ← connection tracker context only
```
Unified schema for all alert types. Rule-based alerts leave numeric baseline fields as NULL; anomaly alerts populate them. INFO/LOW severity alerts are **never written** to this table.

#### `logs`
```
id INTEGER PRIMARY KEY AUTOINCREMENT
timestamp TEXT
level TEXT
module TEXT
message TEXT
```
Asynchronous operational log. Written in batches of 50 or every 5 seconds by a background `LogDBWriter` thread. Indexed by `level` and `timestamp`.

### DB Access Patterns
- **Retry logic**: All DB writes use a retry loop (2 retries, 0.2s fixed backoff), configurable via `config.py`. This handles transient WAL contention without crashing.
- **Connection-per-use**: The system does not maintain a persistent connection pool; each write opens, commits, and closes — appropriate for SQLite's concurrency model.
- **Baseline cache**: `AnomalyDetector` holds an in-process dict cache of baseline rows with a 5-minute TTL, preventing per-window DB reads on every `flush_window` cycle.

---

## 6. Outputs & System Behavior

### Console Output
Real-time stdout for every allowed alert:
```
[HIGH] PORT_SCAN | VERTICAL SCAN: 192.168.1.42 → 10.0.0.1
[MEDIUM] PACKET_FLOOD | PACKET FLOOD DETECTED from 192.168.1.100
[ANOMALY] CRITICAL | 192.168.1.200 | Abnormal connection rate from 192.168.1.200 — 450 SYN packets in 10s (normal: ~12)
[INFO] CONNECTION | Connection detected: 192.168.1.55 -> 10.0.0.2 [new]
```

### Database Output
- **`alerts` table**: persists all MEDIUM/HIGH/CRITICAL events with full context, queryable post-hoc.
- **`live_metrics` table**: rolling record of observed per-host traffic statistics per 10s window.
- **`logs` table**: structured operational log of the IDS process itself.

### Monitoring & Health
Four background threads within `PacketCapture` ensure operational visibility:
- **StallMonitor**: warns if no packets received within 30 seconds.
- **QueueMonitor**: warns if either queue exceeds 500 items (processing lag indicator).
- **Heartbeat**: logs "system healthy" with queue depths every 60 seconds.
- **StderrReader**: forwards tshark stderr to DEBUG log.

### Graceful Shutdown
On `KeyboardInterrupt`: collector stops and performs a final `flush_window()` to avoid losing the current window's data, then joins the collector thread, stops packet capture, and flushes the async log writer before process exit.

---

## 7. High-Level Abstractions

### Pattern 1: Fan-Out Producer / Multi-Consumer Queue Architecture
`PacketCapture` is a single producer feeding two independent consumer queues (`engine_queue`, `collector_queue`). This **fan-out** pattern decouples the two processing planes — real-time rule-based detection and statistical aggregation — so neither can starve or block the other. Backpressure is enforced via soft/hard queue depth limits rather than blocking the producer thread.

### Pattern 2: Dual-Mode Detection (Rule-Based + Statistical)
The system employs a **hybrid detection strategy**:
- Rule-based detectors provide immediate, interpretable responses to known attack signatures with fixed thresholds. They are high-precision but require manual threshold tuning.
- Statistical baseline detection adapts to each host's individual traffic profile. It can surface anomalies that don't match any fixed signature, at the cost of requiring a training phase.

This combination reduces both false negatives (missed novel attacks) and false positives (known-good traffic triggering rigid rules).

### Pattern 3: EMA-Smoothed Adaptive Baseline
Rather than recomputing the baseline from scratch on each training cycle, the system applies **Exponential Moving Average** blending. This makes the baseline a long-memory statistical model: it adapts slowly to genuine behavioral changes while absorbing short-term traffic spikes. This is conceptually equivalent to a low-pass filter applied to the statistical summary of host behavior.

### Pattern 4: Centralized Alert Suppression Gate
All detection paths — three rule-based detectors and the anomaly detector — converge through a **single `AlertGate` instance** before any output or persistence. This is a textbook application of the *chain of responsibility* / *filter* pattern. It ensures that deduplication, cooldown logic, and loopback suppression are never duplicated across detectors and cannot be bypassed.

### Pattern 5: Severity-Stratified Persistence
The system applies a **severity filter at the persistence boundary**: INFO and LOW alerts are printed but never written to the database. This keeps the `alerts` table operationally clean and reduces storage churn from high-frequency INFO events (connection tracking fires on every SYN), while preserving visibility via console output.

### Pattern 6: Layered Operational Observability
The system is designed with observable health at multiple layers:
- **Packet capture layer**: stall detection, heartbeat, queue depth monitoring.
- **Collection layer**: flush-duration drift warning, startup cleanup audit.
- **Engine layer**: DB write failure with alert-drop accounting.
- **Log layer**: async DB writer with drop-on-full to never block the hot path.

This is a *defense in depth* approach applied to the system's own health monitoring — each layer can degrade independently without cascading into total failure.

### Pattern 7: Config-Driven Architecture
`config.py` acts as a **single configuration namespace** imported by all other modules. There are no magic numbers scattered through the codebase — every tunable (EMA alpha, retention hours, DB retry behavior) is named and centralized. This pattern makes the system easy to tune without requiring code changes across multiple files.
