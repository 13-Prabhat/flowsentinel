# FlowSentinel Architecture Specification

FlowSentinel is an open-source, explainable network intrusion detection system (NIDS) designed to detect network attacks from flow metadata without inspecting encrypted packet payloads.

---

## 1. System Overview and Context

```
+--------------------+        +-----------------------------------------------+        +----------------------+
|   Network Inputs   |        |             FlowSentinel Core                 |        |      Consumers       |
|                    |        |                                               |        |                      |
| - NIC / SPAN port  |------->| Packet Source -> Parser -> Flow Table         |------->| - SOC Analyst        |
| - PCAP files       |        |    -> Features -> Detectors (Rules + ML)      |        | - REST API Clients   |
| - Public Datasets  |        |    -> Explainer -> Alert Store (SQLite)       |        | - Web Dashboard      |
+--------------------+        +-----------------------------------------------+        +----------------------+
```

### Context Boundary and Assumptions
- **Link Layer**: Ethernet II (Link Type 1), optional 802.1Q VLAN tag.
- **Network Layer**: IPv4.
- **Transport Layer**: TCP, UDP, ICMP.
- **Payload Inspection**: Never required or performed by default; detection operates on packet timing, directions, headers, flags, volume, and Shannon entropy.

---

## 2. Processing Pipeline and Component Responsibilities

```
[Packet Source] (FR-CAP)
       | (ts, raw_frame)
       v
[Packet Parser] (FR-PAR)
       | Packet object (immutable)
       v
[Flow Assembler] (FR-FLW) <---> [Sliding-Window Manager] (FR-FEA-03, FR-FEA-07)
       | Emitted Flow Record          | Recent host window stats
       +---------------+--------------+
                       |
                       +-----------------------+
                       |                       |
                       v                       v
               [Rule Detectors]         [ML Detectors]
               (FR-DET-01..08)          (FR-ML-01..10)
                       |                       |
                       +-----------+-----------+
                                   | Detections
                                   v
                           [Alert Explainer] (FR-EXP-01..06)
                                   | Plain-language reasons & SHAP
                                   v
                           [Alert Manager] (FR-ALR-01..07)
                                   | Deduplication, Cooldown, Severity
                                   v
                          [SQLite Alert Store] (WAL mode)
                                   |
                       +-----------+-----------+
                       |                       |
                       v                       v
                 [REST API]             [Web Dashboard]
                 (FR-API)                   (FR-UI)
```

### Component Directory & Responsibilities

| Component | Target Path | Responsibility | SRS Reference |
|---|---|---|---|
| **Packet Source** | `flowsentinel.parser.pcap`, `flowsentinel.capture.live` | Yields raw frames and microsecond/nanosecond timestamps from classic pcap or live interfaces. | FR-CAP-01..09 |
| **Packet Parser** | `flowsentinel.parser.packet`, `flowsentinel.parser.frames` | Decodes raw frames into immutable `Packet` instances; handles VLAN, TSO, padding, fragments. | FR-PAR-01..11 |
| **Flow Assembler** | `flowsentinel.flows.table` | Maintains active flow table keyed by canonical 5-tuple; enforces idle/active timeouts and bounded flow table evictions. | FR-FLW-01..09 |
| **Feature Extractor** | `flowsentinel.features.*` | Computes per-flow statistical features (`f_*`) and per-source sliding-window features (`h_*`). | FR-FEA-01..07 |
| **Rule Detectors** | `flowsentinel.detectors.rules.*` | Evaluates transparent thresholds: port scans, SYN floods, brute force, host sweeps. | FR-DET-01..08 |
| **ML Detectors** | `flowsentinel.detectors.ml.*` | Unsupervised Isolation Forest and supervised classifiers (Random Forest/XGBoost) with checksum validation. | FR-ML-01..10 |
| **Explainer** | `flowsentinel.explain.*` | Translates rule thresholds and ML feature contributions (SHAP) into plain-language explanations. | FR-EXP-01..06 |
| **Alert Manager** | `flowsentinel.alerts.*` | De-duplicates alerts within cooldowns, assigns severity, and persists to SQLite (WAL mode). | FR-ALR-01..07 |
| **Interfaces** | `flowsentinel.cli`, `flowsentinel.api`, `flowsentinel.dashboard` | CLI commands (`analyze`, `capture`, `train`, `evaluate`, `serve`), FastAPI service, no-CDN dashboard. | FR-CLI, FR-API, FR-UI |
| **Configuration & Monitoring** | `flowsentinel.config`, `flowsentinel.monitoring` | YAML hierarchical config with env overrides, metric counters, Population Stability Index (PSI) drift monitoring. | FR-CFG, FR-MON |

---

## 3. Data Flow and Concurrency Model

### 3.1 Offline Pipeline (Batch PCAP Analysis)
1. Sequentially read packets from file via `read_pcap(path)`.
2. Parse frame into `Packet`.
3. Submit `Packet` to `FlowTable`:
   - Update existing flow or create new flow.
   - Update host sliding-window state.
   - Check and yield expired flows (idle/active timeouts).
   - Evaluate host-window rule detectors.
4. On EOF, flush all open flows from `FlowTable`.
5. Run ML detectors on emitted flow features.
6. Feed detections through Explainer into AlertManager.
7. Print CLI summary and persist/export alerts as requested.

### 3.2 Live Pipeline (Interface Sniffing)
1. **Capture Thread**: Listens on the selected network adapter and enqueues `(timestamp, raw_frame)` into a bounded queue (`queue.Queue(maxsize=10000)`). If full, increment `dropped_packets` and discard (FR-CAP-07, NFR-SCL-01).
2. **Processing Thread**: Dequeues frames, runs parsing, flow assembly, feature extraction, and detection. Writes alerts atomically to SQLite.
3. **Service Thread**: FastAPI / Uvicorn runs independently and serves the REST API and web UI directly from the SQLite database.

---

## 4. Key Data Schemas

### 4.1 Canonical 5-Tuple Key (A.9)
```python
(protocol, (min_ip, min_port), (max_ip, max_port))
```
- Protocol number (6=TCP, 17=UDP, 1=ICMP).
- Endpoints are sorted numerically by IPv4 integer representation, then port.
- Initiator endpoint defines the "forward" direction (`fwd`), responder defines "backward" (`bwd`).

### 4.2 Feature Schema Version 1 (SRS Section 7.3)
- **Flow features (`f_`)**:
  - `f_duration_s`: `end_ts - start_ts` (seconds)
  - `f_pkts_fwd`, `f_pkts_bwd`: packet counts
  - `f_bytes_fwd`, `f_bytes_bwd`: IP payload/header byte counts
  - `f_pps`, `f_bps`: packets and bytes per second (0 if duration == 0)
  - `f_len_min`, `f_len_mean`, `f_len_max`, `f_len_std`: packet length running stats
  - `f_iat_min`, `f_iat_mean`, `f_iat_max`, `f_iat_std`: inter-arrival time running stats
  - `f_syn`, `f_fin`, `f_rst`, `f_psh`, `f_ack`, `f_urg`: TCP flag counts
  - `f_win_fwd`, `f_win_bwd`: initial TCP window size
  - `f_payload_pkts`: packets with payload > 0
- **Host sliding-window features (`h_`)**:
  - `h_unique_dst_ports`: distinct destination ports contacted in window
  - `h_unique_dst_hosts`: distinct destination IPs contacted in window
  - `h_new_conn_rate`: connections initiated per second
  - `h_syn_only_ratio`: SYN packets without ACK / total TCP packets from host
  - `h_failed_ratio`: RST or unanswered connections / total connections
  - `h_port_entropy_bits`: Shannon entropy $H = -\sum p \log_2 p$ of contacted ports

### 4.3 Alert Record & SQLite Schema (SRS Section 7.4)
- Table `alerts`: `id`, `ts`, `type`, `severity`, `detector`, `score`, `src_ip`, `dst_ip`, `dst_port`, `protocol`, `flow_id`, `reasons` (JSON), `suppressed_count`, `model_version`.
- Table `meta`: `schema_version`.
- WAL mode enabled for concurrent reader/writer isolation.

---

## 5. Security & Privacy Guarantees
- **No Payload Storage**: Payloads are never retained in memory or disk (NFR-SEC-05).
- **Safe Parsing**: Fixed memory bounds on all queues and tables (NFR-SCL-01).
- **Model Checksums**: Every trained model file is verified with SHA-256 before deserialization (FR-ML-07, NFR-SEC-02).
- **Safe YAML**: Only `yaml.safe_load` permitted (FR-CFG-04, NFR-SEC-01).
- **Local API Binding**: Defaults strictly to `127.0.0.1` unless overridden with authentication token (FR-API-04, NFR-SEC-03).
