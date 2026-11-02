# FlowSentinel Development Roadmap

This document outlines the phased engineering milestones to bring **FlowSentinel** from its initial prototype to a production-ready, fully verified v1.0 release satisfying the Software Requirements Specification (SRS v1.0).

---

## Milestone Overview

```
+-----------------------------------------------------------------------------------+
|  M1: Foundations (v0.1.0)                                                        |
|  - Packet Parser & Pcap Reader (Completed)                                        |
|  - Bidirectional Flow Assembly & Timeouts (In Progress)                           |
|  - Flow Feature Extraction (Welford statistics, TCP flags)                        |
|  - CLI 'flowsentinel analyze' & Structured Logging                                |
|  - CI & Anonymised Pcap Fixture Validation                                        |
+-----------------------------------------------------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|  M2: Rules, Host Windows & Alert Storage (v0.2.0)                                 |
|  - Per-Source Host Sliding Windows & Shannon Entropy                              |
|  - Rule Detectors (Port scan, SYN flood, Brute force, Host sweep)                 |
|  - Alert Manager: Cooldown Suppression, Severity, SQLite WAL Store                 |
|  - YAML Configuration & Precedence Engine                                         |
|  - Docker Attack Lab & Labelled Traffic Generation                                |
+-----------------------------------------------------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|  M3: Machine Learning & Explainability (v0.3.0)                                   |
|  - Isolation Forest (Unsupervised) & Random Forest / XGBoost (Supervised)         |
|  - Model Metadata Sidecar & SHA-256 Anti-Tamper Verification                      |
|  - SHAP Value Explanations & Plain-Language Reason Templates                      |
|  - Hybrid Detection Mode (Rules + ML Ensemble)                                    |
|  - Model Training & Evaluation Benchmarks (Generalisation Gap, Confusion Matrices)|
+-----------------------------------------------------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|  M4: Live Mode, API, UI, C++ Parser & Hardening (v1.0.0)                          |
|  - Live Interface Capture Thread with Bounded Queue & Drop Counter                |
|  - Optional C++ Parser Extension (pybind11) with Transparent Python Fallback      |
|  - FastAPI REST Service (Health, Alerts, Flows, Stats, Bearer Token Auth)         |
|  - Web Dashboard (Zero-CDN, Self-Contained HTML/JS, Polling UI)                   |
|  - PSI Feature Drift Monitoring                                                   |
|  - Robustness Fuzzing (10,000 mutated frames) & 80% Coverage Enforcement          |
+-----------------------------------------------------------------------------------+
```

---

## Detailed Milestones & Tasks

### Milestone 1: Foundations (v0.1.0)
**Goal:** Ingest pcap files, assemble bidirectional flows, compute flow features, and output analysis via CLI.
- [x] **Task 1.1: Packet Parsing** (`flowsentinel.parser.frames`, `packet.py`, `pcap.py`)
  - Ethernet II, 802.1Q VLAN, IPv4, TCP, UDP, ICMP.
  - TSO zero-length handling, fragment offset handling, padding exclusion.
  - Verified against Scapy parity on test fixture (AT-02).
- [x] **Task 1.2: Test Infrastructure & Fixture**
  - Anonymized fixture generator (`scripts/generate_sample_fixture.py`).
  - Unit tests for frames, packets, pcap parsing (`tests/test_frames.py`, `test_packet.py`, `test_pcap.py`).
  - Scapy Windows driver bypass in `tests/conftest.py`.
- [ ] **Task 1.3: Bidirectional Flow Assembly** (`flowsentinel.flows.table`, `record.py`)
  - Canonical 5-tuple ordering (A.9).
  - Forward/backward direction tracking relative to initiator.
  - Idle timeout (default 60s) and active timeout (default 120s) (FR-FLW-03).
  - TCP teardown on bidirectional FIN or RST (FR-FLW-04).
  - UDP/ICMP timeout support (FR-FLW-09).
  - Deterministic flow identifier generation (FR-FLW-07).
  - Stream termination flush (FR-FLW-05).
- [ ] **Task 1.4: Flow Feature Computation** (`flowsentinel.features.flow`)
  - Duration, forward/backward packet & byte counts, pps, bps.
  - Packet length and inter-arrival time (IAT) min, max, mean, std via one-pass Welford algorithm.
  - TCP flag counts and initial window sizes (FR-FEA-01, FR-FEA-02).
  - Zero/undefined protection: default to 0, never NaN or inf (FR-FEA-04).
  - Feature export to pandas DataFrame / CSV (FR-FEA-06).
- [ ] **Task 1.5: Core CLI & Logging** (`flowsentinel.cli`, `flowsentinel.logging`)
  - CLI `flowsentinel analyze <pcap>` (FR-CLI-01, AT-01).
  - Exit codes: 0 (success), 1 (runtime error), 2 (usage/argument error).
  - Flags: `--help`, `--version`, `--format table|json`, `--log-level`, `--debug`.
  - Structured logging without credentials/payloads (FR-MON-03, NFR-SEC-06).

### Milestone 2: Rule Detectors, Lab & Alert Storage (v0.2.0)
**Goal:** Sliding-window host analysis, transparent rule detection, deduplicated SQLite alert storage, and reproducible Docker attack lab.
- [ ] **Task 2.1: Host Sliding Windows & Entropy** (`flowsentinel.features.window`)
  - 10s sliding window per source host (FR-FEA-03, FR-FEA-07).
  - Unique destination ports & hosts tracking.
  - New connection rate, SYN-only ratio, failed connection ratio.
  - Shannon entropy computation ($H = -\sum p \log_2 p$).
- [ ] **Task 2.2: Flow Table Hardening** (`flowsentinel.flows.table`)
  - Bounded flow table (100,000 maximum active flows) with LRU eviction (FR-FLW-06).
  - Monotonic clock protection on out-of-order packets (FR-FLW-08).
- [ ] **Task 2.3: Rule Detectors** (`flowsentinel.detectors.rules`)
  - Port-scan detector ($N \ge 50$ ports in 10s, $H \ge 4.0$ bits) (FR-DET-01, AT-03).
  - SYN-flood detector (rate $> 200$/s, completion $< 10\%$) (FR-DET-02, AT-04).
  - Brute-force detector ($\ge 20$ connections to 21/22/23/3389 in 60s) (FR-DET-03, AT-05).
  - Host-sweep detector ($\ge 20$ hosts in window) (FR-DET-04).
  - Pluggable `BaseDetector` interface and enable/disable configuration (FR-DET-05..07).
- [ ] **Task 2.4: Alert Storage & Deduplication** (`flowsentinel.alerts`)
  - Alert record data model (FR-ALR-01, Section 7.4).
  - Cooldown deduplication with suppression count (FR-DET-08).
  - SQLite persistence with WAL mode and schema versioning (FR-ALR-03, NFR-REL-03).
  - Alert query and export to JSON Lines / CSV (FR-ALR-04, FR-ALR-05).
  - 30-day retention purge (FR-ALR-06).
- [ ] **Task 2.5: Configuration Management** (`flowsentinel.config`)
  - YAML configuration loader with safe parsing (`yaml.safe_load`) (FR-CFG-04, NFR-SEC-01).
  - Precedence: CLI > `FLOWSENTINEL_*` env vars > YAML config file > built-in defaults (FR-CFG-02).
  - Schema range validation and `flowsentinel config validate` (FR-CFG-03, FR-CLI-05).
- [ ] **Task 2.6: Docker Attack Lab** (`lab/`)
  - Isolated Docker network (no host/internet routing) (FR-LAB-01..05).
  - Victim container with web (Nginx/Apache) and OpenSSH.
  - Attacker container with Nmap, hping3, Hydra.
  - Capture point and label generation scripts producing CSV ground truth.

### Milestone 3: Machine Learning & Explainability (v0.3.0)
**Goal:** Supervised and unsupervised ML models, SHAP explanations, and rigorous model evaluation.
- [ ] **Task 3.1: Model Training & Inference** (`flowsentinel.detectors.ml`)
  - Unsupervised Isolation Forest on benign flow features (FR-ML-01).
  - Supervised classifier (Random Forest / XGBoost) on labelled traffic (FR-ML-02).
  - Class imbalance handling with weights or resampling (FR-ML-04).
  - Model serialization with JSON metadata sidecar and SHA-256 verification (FR-ML-06, FR-ML-07, NFR-SEC-02).
  - Tunable detection threshold for target FPR (FR-ML-08).
- [ ] **Task 3.2: Explainability Engine** (`flowsentinel.explain`)
  - Human-readable reason generator for rules (FR-EXP-01, FR-EXP-02).
  - TreeSHAP integration for top-k feature attribution (FR-EXP-03).
  - Plain-language reason templates without ML jargon (FR-EXP-04).
  - Hybrid detection combining rules and ML (FR-ML-09).
- [ ] **Task 3.3: Evaluation Tooling & Benchmarking** (`scripts/evaluate.py`)
  - Metrics: Precision, Recall, F1, FPR, ROC-AUC, PR-AUC, Confusion Matrix (FR-EVL-01, AT-08).
  - Time-aware / attack-type-aware cross-validation to prevent data leakage (FR-ML-05).
  - Evaluation on public datasets (CIC-IDS2017 / UNSW-NB15) vs lab traffic, reporting generalisation gap (FR-EVL-02).
  - Output reports in Markdown and JSON with threshold sweeps (FR-EVL-03, FR-EVL-05).

### Milestone 4: Live Mode, API, UI, C++ Parser & Hardening (v1.0.0)
**Goal:** Production packaging, live capture, local web dashboard, REST API, C++ parser acceleration, fuzz testing, and documentation.
- [ ] **Task 4.1: Live Capture** (`flowsentinel.capture.live`)
  - Multi-threaded capture with bounded queue (FR-CAP-05..07, NFR-PERF-03).
  - Interface enumeration (`flowsentinel capture --iface`) (FR-CAP-06, FR-CLI-02).
  - Graceful degradation on high load (packet drop counting) (FR-MON-01, NFR-SCL-01).
  - Clean shutdown on SIGINT/Ctrl+C within 5s (NFR-REL-02).
- [ ] **Task 4.2: C++ Parser Extension** (`src/flowsentinel/cparser`)
  - pybind11 C++17 frame parser achieving $\ge 5\times$ speedup (FR-PAR-11, NFR-PERF-02).
  - Transparent Python fallback if binary extension is not built (NFR-PRT-03).
- [ ] **Task 4.3: REST API** (`flowsentinel.api`)
  - FastAPI service with `/health`, `/alerts`, `/alerts/{id}`, `/flows/{id}`, `/stats` (FR-API-01).
  - Pagination, filtering, OpenAPI `/docs` (FR-API-02, FR-API-03).
  - Localhost binding default (127.0.0.1) and bearer token security (FR-API-04, FR-API-05).
  - Standardized error format without stack traces (FR-API-06).
- [ ] **Task 4.4: Web Dashboard** (`flowsentinel.dashboard`)
  - Single-page responsive HTML/JS interface (FR-UI-01..04).
  - Zero external CDN dependencies (works air-gapped) (FR-UI-05).
  - Real-time polling, alert filtering by severity, alert detail drawer with reasons and flow summaries.
- [ ] **Task 4.5: Monitoring & Drift** (`flowsentinel.monitoring`)
  - Runtime counters (read, dropped, active flows, alerts) (FR-MON-01).
  - Population Stability Index (PSI) drift calculation per 10-minute window (FR-MON-02, NFR-REL-01).
- [ ] **Task 4.6: Robustness Fuzzing & QA Verification**
  - Fuzz test suite: 10,000 mutated frames without crashes (NFR-REL-01, AT-10).
  - End-to-end acceptance tests AT-01 through AT-13.
  - Line coverage $\ge 80\%$ enforced in CI (FR-DEV-07).
  - Verification of installation within $\le 5$ commands (NFR-USE-01, AT-13).
