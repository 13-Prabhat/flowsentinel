# FlowSentinel Requirements Traceability Matrix (RTM)

This document tracks all 161 requirements defined in the **FlowSentinel Software Requirements Specification (SRS v1.0)**, establishing bidirectional traceability between requirements, source implementation files, and automated verification tests.

Status legend:
- **Implemented**: Fully implemented with accompanying passing automated tests.
- **Partially implemented**: Implementation or test scaffolding started but not complete.
- **Missing**: Not yet implemented.
- **Blocked**: Cannot proceed due to an external dependency or pending design decision.

---

## 1. Packet Acquisition (FR-CAP)

| ID | Description | Pri | Ver | Rel | Status | Target Path | Verification Test | Notes |
|---|---|---|---|---|---|---|---|---|
| FR-CAP-01 | Read packets from classic libpcap files (both byte orders, micro/nano resolution) | M | T | R1 | **Implemented** | `parser/pcap.py` | `tests/test_pcap.py` | Big/little endian, nanosecond |
| FR-CAP-02 | Reject non-classic pcap (including pcapng) with informative error | M | T | R1 | **Implemented** | `parser/pcap.py` | `tests/test_pcap.py` | Validated magic check |
| FR-CAP-03 | Accept only Ethernet link type (1) and report unsupported types | M | T | R1 | **Implemented** | `parser/pcap.py` | `tests/test_pcap.py` | Link type validation |
| FR-CAP-04 | Tolerate truncated final record with warning and return prior packets | M | T | R1 | **Implemented** | `parser/pcap.py` | `tests/test_pcap.py` | Graceful truncation |
| FR-CAP-05 | Capture packets live from selected network interface with capture filter | M | D | R4 | **Missing** | `capture/live.py` | `tests/test_capture.py` | Requires Scapy/Npcap |
| FR-CAP-06 | List capture interfaces available on host | S | D | R4 | **Missing** | `capture/live.py` | `tests/test_capture.py` | Interface listing |
| FR-CAP-07 | Pass packets to processing thread through bounded queue; count dropped | S | T | R4 | **Missing** | `capture/live.py` | `tests/test_capture.py` | Bounded queue drop counter |
| FR-CAP-08 | Read pcapng files directly | C | T | Later | **Missing** | `parser/pcapng.py` | `tests/test_pcapng.py` | Scheduled for post-1.0 |
| FR-CAP-09 | Reject record whose captured length exceeds 262,144 bytes without allocation | M | T | R4 | **Missing** | `parser/pcap.py` | `tests/test_pcap.py` | Memory hardening |

---

## 2. Packet Parsing (FR-PAR)

| ID | Description | Pri | Ver | Rel | Status | Target Path | Verification Test | Notes |
|---|---|---|---|---|---|---|---|---|
| FR-PAR-01 | Decode Ethernet II frames; skip one 802.1Q VLAN tag | M | T | R1 | **Implemented** | `parser/frames.py` | `tests/test_frames.py` | VLAN 0x8100 handled |
| FR-PAR-02 | Decode IPv4 header (version, IHL, options skipped, total length, TTL, proto, IPs) | M | T | R1 | **Implemented** | `parser/frames.py` | `tests/test_frames.py` | Validated against spec |
| FR-PAR-03 | Decode TCP (ports, seq, ack, window, flags, data offset, options skipped) | M | T | R1 | **Implemented** | `parser/frames.py` | `tests/test_frames.py` | TcpFlags bitmask |
| FR-PAR-04 | Decode UDP ports; compute ICMP payload length after 8-byte header | M | T | R1 | **Implemented** | `parser/frames.py` | `tests/test_frames.py` | UDP and ICMP tests |
| FR-PAR-05 | Payload length from IPv4 total length minus headers; never count Ethernet padding | M | T | R1 | **Implemented** | `parser/frames.py` | `tests/test_frames.py` | Verified padding exclusion |
| FR-PAR-06 | Use captured length when IPv4 total length is 0 (TSO offload) | M | T | R1 | **Implemented** | `parser/frames.py` | `tests/test_frames.py` | TSO support |
| FR-PAR-07 | Non-first IP fragments leave ports/TCP fields empty | M | T | R1 | **Implemented** | `parser/frames.py` | `tests/test_frames.py` | Fragment offset check |
| FR-PAR-08 | Skip non-IPv4 silently; malformed IPv4 raises ParseError and pcap logs warning | M | T | R1 | **Implemented** | `parser/frames.py` | `tests/test_frames.py` | Robust error handling |
| FR-PAR-09 | Deterministic parsing without side effects; Packet is immutable | M | T | R1 | **Implemented** | `parser/packet.py` | `tests/test_packet.py` | `slots=True, frozen=True` |
| FR-PAR-10 | Decode IPv6 headers and extension headers | S | T | Later | **Missing** | `parser/frames.py` | `tests/test_frames.py` | Post-1.0 |
| FR-PAR-11 | Optional C++ implementation of frame parser (pybind11) with Python fallback | S | T | R4 | **Missing** | `src/flowsentinel/cparser/` | `tests/test_cparser.py` | Performance booster |

---

## 3. Flow Assembly (FR-FLW)

| ID | Description | Pri | Ver | Rel | Status | Target Path | Verification Test | Notes |
|---|---|---|---|---|---|---|---|---|
| FR-FLW-01 | Group packets into bidirectional flows keyed by canonical 5-tuple | M | T | R1 | **Missing** | `flows/table.py` | `tests/test_flows.py` | Canonical order sorted endpoints |
| FR-FLW-02 | Record flow initiator (first packet) and label fwd/bwd directions | M | T | R1 | **Missing** | `flows/table.py` | `tests/test_flows.py` | Direction tagging |
| FR-FLW-03 | Close flow after idle timeout (default 60s) or active timeout (default 120s) | M | T | R1 | **Missing** | `flows/table.py` | `tests/test_flows.py` | Configurable timeouts |
| FR-FLW-04 | Close TCP flow on FIN in both directions or RST | M | T | R1 | **Missing** | `flows/table.py` | `tests/test_flows.py` | TCP connection teardown |
| FR-FLW-05 | Flush all open flows at end of input | M | T | R1 | **Missing** | `flows/table.py` | `tests/test_flows.py` | EOF emission |
| FR-FLW-06 | Bound flow table (default 100,000); evict LRU with reason 'evicted' | M | T | R2 | **Missing** | `flows/table.py` | `tests/test_flows.py` | Memory bounding |
| FR-FLW-07 | Deterministic flow identifier from key and start time | S | T | R1 | **Missing** | `flows/table.py` | `tests/test_flows.py` | Hash repeatability |
| FR-FLW-08 | Monotonic clock protection on out-of-order timestamps; count anomalies | S | T | R2 | **Missing** | `flows/table.py` | `tests/test_flows.py` | Clock skew defense |
| FR-FLW-09 | Support UDP and ICMP flows using timeouts only | M | T | R1 | **Missing** | `flows/table.py` | `tests/test_flows.py` | Connectionless flow support |

---

## 4. Feature Extraction (FR-FEA)

| ID | Description | Pri | Ver | Rel | Status | Target Path | Verification Test | Notes |
|---|---|---|---|---|---|---|---|---|
| FR-FEA-01 | Compute per-flow features (duration, counts, pps, bps, lengths, IATs) | M | T | R1 | **Missing** | `features/flow.py` | `tests/test_features.py` | Welford running stats |
| FR-FEA-02 | Compute per-flow TCP features (flag counts, initial windows, payload pkts) | M | T | R1 | **Missing** | `features/flow.py` | `tests/test_features.py` | Flags and windows |
| FR-FEA-03 | Compute per-source sliding-window features (ports, hosts, conn rate, entropy) | M | T | R2 | **Missing** | `features/window.py` | `tests/test_features.py` | Host window tracking |
| FR-FEA-04 | Deterministic features; undefined values take default 0, never NaN/inf | M | T | R1 | **Missing** | `features/flow.py` | `tests/test_features.py` | Robust arithmetic |
| FR-FEA-05 | Documented, versioned feature schema (stored with models) | M | I | R3 | **Missing** | `features/schema.py` | `tests/test_features.py` | Schema v1 |
| FR-FEA-06 | Export features as pandas DataFrame and CSV | S | T | R1 | **Missing** | `features/export.py` | `tests/test_features.py` | Pandas/CSV output |
| FR-FEA-07 | Bound sliding-window state by discarding entries older than window | M | T | R2 | **Missing** | `features/window.py` | `tests/test_features.py` | Memory bounding |

---

## 5. Rule-Based Detection (FR-DET)

| ID | Description | Pri | Ver | Rel | Status | Target Path | Verification Test | Notes |
|---|---|---|---|---|---|---|---|---|
| FR-DET-01 | Port-scan detector: >= N ports in W s and entropy >= H bits | M | T | R2 | **Missing** | `detectors/rules/port_scan.py` | `tests/test_detectors.py` | AT-03 |
| FR-DET-02 | SYN-flood detector: SYN rate > R/s and completion < 10% | M | T | R2 | **Missing** | `detectors/rules/syn_flood.py` | `tests/test_detectors.py` | AT-04 |
| FR-DET-03 | Brute-force detector: >= N connections to port 21/22/23/3389 in 60s | M | T | R2 | **Missing** | `detectors/rules/brute_force.py` | `tests/test_detectors.py` | AT-05 |
| FR-DET-04 | Host-sweep detector: >= N distinct hosts in window | S | T | R2 | **Missing** | `detectors/rules/host_sweep.py` | `tests/test_detectors.py` | Lateral movement detection |
| FR-DET-05 | Configurable thresholds with defaults; reject invalid values on startup | M | T | R2 | **Missing** | `detectors/base.py` | `tests/test_detectors.py` | Startup validation |
| FR-DET-06 | Individual detector enable/disable toggles | M | T | R2 | **Missing** | `detectors/base.py` | `tests/test_detectors.py` | Modular config |
| FR-DET-07 | Common detector interface for pluggability | S | I | R2 | **Missing** | `detectors/base.py` | `tests/test_detectors.py` | Extensibility |
| FR-DET-08 | Cooldown deduplication (default 60s) with suppression counter | M | T | R2 | **Missing** | `alerts/dedup.py` | `tests/test_alerts.py` | Alert fatigue reduction |

---

## 6. Machine-Learning Detection (FR-ML)

| ID | Description | Pri | Ver | Rel | Status | Target Path | Verification Test | Notes |
|---|---|---|---|---|---|---|---|---|
| FR-ML-01 | Train Isolation Forest on benign flows for anomaly detection | M | T | R3 | **Missing** | `detectors/ml/isolation_forest.py` | `tests/test_ml.py` | Unsupervised |
| FR-ML-02 | Train supervised classifier (Random Forest/XGBoost) on labelled flows | M | T | R3 | **Missing** | `detectors/ml/supervised.py` | `tests/test_ml.py` | Multi-class / binary |
| FR-ML-03 | Reproducible training (fixed seed, recorded versions, data hash) | M | T | R3 | **Missing** | `scripts/train.py` | `tests/test_ml.py` | Determinism |
| FR-ML-04 | Handle class imbalance with class weights or resampling | M | I | R3 | **Missing** | `detectors/ml/supervised.py` | `tests/test_ml.py` | Documented in sidecar |
| FR-ML-05 | Time-aware or attack-type-aware evaluation splits to avoid leakage | M | I | R3 | **Missing** | `scripts/evaluate.py` | `tests/test_ml.py` | Honest evaluation |
| FR-ML-06 | Saved model sidecar metadata (schema ver, data hash, metrics, model SHA256) | M | T | R3 | **Missing** | `detectors/ml/model.py` | `tests/test_ml.py` | Metadata sidecar |
| FR-ML-07 | Verify SHA-256 before loading pickle model; refuse on mismatch | M | T | R3 | **Missing** | `detectors/ml/model.py` | `tests/test_ml.py` | Anti-tamper security |
| FR-ML-08 | Tunable detection threshold on validation set for target FPR | M | T | R3 | **Missing** | `detectors/ml/model.py` | `tests/test_ml.py` | Operating point tuning |
| FR-ML-09 | Hybrid detection mode (rule OR ML score > threshold) with source attribution | M | T | R3 | **Missing** | `detectors/hybrid.py` | `tests/test_ml.py` | Rule + ML ensemble |
| FR-ML-10 | ML scores strictly from feature vector; never inspects payload bytes | M | I | R3 | **Missing** | `detectors/ml/model.py` | `tests/test_ml.py` | Zero-payload policy |

---

## 7. Explainability (FR-EXP)

| ID | Description | Pri | Ver | Rel | Status | Target Path | Verification Test | Notes |
|---|---|---|---|---|---|---|---|---|
| FR-EXP-01 | Every alert carries at least one human-readable reason | M | T | R2 | **Missing** | `explain/engine.py` | `tests/test_explain.py` | AT-07 |
| FR-EXP-02 | Rule alerts state measured value and threshold | M | T | R2 | **Missing** | `explain/rules.py` | `tests/test_explain.py` | Concrete metrics |
| FR-EXP-03 | ML alerts list top-k contributing features (SHAP) with direction & magnitude | M | T | R3 | **Missing** | `explain/shap.py` | `tests/test_explain.py` | Feature attribution |
| FR-EXP-04 | Template mapping from feature names to plain language without ML jargon | S | I | R3 | **Missing** | `explain/templates.py` | `tests/test_explain.py` | Human readable |
| FR-EXP-05 | Explanation computation adds <= 500ms per alert in live mode | S | T | R4 | **Missing** | `explain/engine.py` | `tests/test_explain.py` | Performance limit |
| FR-EXP-06 | Explanations stored together with alert record | M | T | R3 | **Missing** | `alerts/model.py` | `tests/test_alerts.py` | Stored in SQLite |

---

## 8. Alert Management and Storage (FR-ALR)

| ID | Description | Pri | Ver | Rel | Status | Target Path | Verification Test | Notes |
|---|---|---|---|---|---|---|---|---|
| FR-ALR-01 | Complete alert schema (id, ts, type, severity, score, IPs, port, reasons, count) | M | T | R2 | **Missing** | `alerts/model.py` | `tests/test_alerts.py` | Section 7.4 schema |
| FR-ALR-02 | Severity levels (low, medium, high, critical) mapped from rule/score | M | I | R2 | **Missing** | `alerts/model.py` | `tests/test_alerts.py` | Severity mapping |
| FR-ALR-03 | SQLite persistence with WAL mode and schema version surviving restart | M | T | R2 | **Missing** | `alerts/store.py` | `tests/test_alerts.py` | Atomic transactions |
| FR-ALR-04 | Export alerts as JSON Lines and CSV | M | T | R2 | **Missing** | `alerts/export.py` | `tests/test_alerts.py` | Export utility |
| FR-ALR-05 | Query alerts by time range, type, severity, source, destination | M | T | R2 | **Missing** | `alerts/store.py` | `tests/test_alerts.py` | Filterable queries |
| FR-ALR-06 | Purge alerts older than retention period (default 30 days) on startup | S | T | R2 | **Missing** | `alerts/store.py` | `tests/test_alerts.py` | Retention management |
| FR-ALR-07 | Export alert JSON mapping to Elastic Common Schema (ECS) | C | I | Later | **Missing** | `alerts/export.py` | `tests/test_alerts.py` | Post-1.0 |

---

## 9. Command-Line Interface (FR-CLI)

| ID | Description | Pri | Ver | Rel | Status | Target Path | Verification Test | Notes |
|---|---|---|---|---|---|---|---|---|
| FR-CLI-01 | `flowsentinel analyze <pcap>` runs pipeline; exit 0 ok, 1 err, 2 usage | M | D | R1 | **Missing** | `cli.py` | `tests/test_cli.py` | AT-01 |
| FR-CLI-02 | `flowsentinel capture --iface` runs live detection; clean Ctrl+C shutdown | M | D | R4 | **Missing** | `cli.py` | `tests/test_cli.py` | Live sniffer |
| FR-CLI-03 | `flowsentinel train` and `flowsentinel evaluate` commands | M | D | R3 | **Missing** | `cli.py` | `tests/test_cli.py` | ML commands |
| FR-CLI-04 | `flowsentinel serve` starts API and dashboard | M | D | R4 | **Missing** | `cli.py` | `tests/test_cli.py` | Server command |
| FR-CLI-05 | `flowsentinel config validate <file>` checks config syntax & ranges | S | D | R2 | **Missing** | `cli.py` | `tests/test_cli.py` | Validation tool |
| FR-CLI-06 | All commands support `--help`, `--version`, `--format`, `--log-level` | M | T | R1 | **Missing** | `cli.py` | `tests/test_cli.py` | Standard flags |
| FR-CLI-07 | Actionable stderr output; stack traces only with `--debug` | S | T | R1 | **Missing** | `cli.py` | `tests/test_cli.py` | Clean UX |

---

## 10. REST API & Dashboard (FR-API, FR-UI)

| ID | Description | Pri | Ver | Rel | Status | Target Path | Verification Test | Notes |
|---|---|---|---|---|---|---|---|---|
| FR-API-01 | FastAPI service: GET `/health`, `/alerts`, `/alerts/{id}`, `/flows/{id}`, `/stats` | M | T | R4 | **Missing** | `api/server.py` | `tests/test_api.py` | REST endpoints |
| FR-API-02 | List endpoints support pagination (limit/offset) and filters | M | T | R4 | **Missing** | `api/routes.py` | `tests/test_api.py` | Pagination & filtering |
| FR-API-03 | OpenAPI docs published at `/docs` | S | I | R4 | **Missing** | `api/server.py` | `tests/test_api.py` | Swagger UI |
| FR-API-04 | Bind to 127.0.0.1 by default; remote bind requires flag and token | M | T | R4 | **Missing** | `api/server.py` | `tests/test_api.py` | Security constraint |
| FR-API-05 | Bearer token auth compared in constant time | S | T | R4 | **Missing** | `api/auth.py` | `tests/test_api.py` | Timing attack protection |
| FR-API-06 | Standard JSON error format: `{error, field}`; no stack trace in 500 | M | T | R4 | **Missing** | `api/errors.py` | `tests/test_api.py` | Safe errors |
| FR-API-07 | PCAP upload endpoint for offline analysis | C | T | Later | **Missing** | `api/routes.py` | `tests/test_api.py` | Post-1.0 |
| FR-UI-01 | Live alert table with severity colors and filters | M | D | R4 | **Missing** | `dashboard/index.html` | `tests/test_ui.py` | Static web UI |
| FR-UI-02 | Alert charts over time and top talkers | S | D | R4 | **Missing** | `dashboard/app.js` | `tests/test_ui.py` | Visual analytics |
| FR-UI-03 | Alert detail panel showing reasons, key features, and flow summary | M | D | R4 | **Missing** | `dashboard/app.js` | `tests/test_ui.py` | Triaging view |
| FR-UI-04 | Auto-refresh every 5s; compatibility with Chrome/Firefox/Edge | S | D | R4 | **Missing** | `dashboard/app.js` | `tests/test_ui.py` | Polling UI |
| FR-UI-05 | Standalone zero-external-network requirement (no CDN assets) | S | I | R4 | **Missing** | `dashboard/index.html` | `tests/test_ui.py` | Offline airgap capable |

---

## 11. Configuration, Lab, Evaluation, Monitoring, Dev & Packaging

| ID | Description | Pri | Ver | Rel | Status | Target Path | Verification Test | Notes |
|---|---|---|---|---|---|---|---|---|
| FR-CFG-01 | YAML configuration with built-in defaults for every key | M | T | R2 | **Missing** | `config.py` | `tests/test_config.py` | Defaults in code |
| FR-CFG-02 | Precedence: CLI flags > Env vars (`FLOWSENTINEL_`) > File > Defaults | M | T | R2 | **Missing** | `config.py` | `tests/test_config.py` | Hierarchical config |
| FR-CFG-03 | Validate against schema; error names key and allowed range | M | T | R2 | **Missing** | `config.py` | `tests/test_config.py` | Range checks |
| FR-CFG-04 | Parse YAML using safe loader only (`yaml.safe_load`) | M | T | R2 | **Missing** | `config.py` | `tests/test_config.py` | Remote code execution prevention |
| FR-LAB-01 | Docker Compose isolated lab: victim (web/ssh), attacker (nmap/hydra), sniffer | M | D | R2 | **Missing** | `lab/docker-compose.yml` | `lab/run.sh` | Reproducible attacks |
| FR-LAB-02 | Scripts generate labelled captures (scan, syn flood, brute force, benign) | M | D | R2 | **Missing** | `lab/scripts/` | `lab/run.sh` | Test traffic generation |
| FR-LAB-03 | Lab network isolated from internet and host LAN | M | I | R2 | **Missing** | `lab/docker-compose.yml` | Inspection | Internal bridge only |
| FR-LAB-04 | Label CSV for each capture with attacker IP, attack type, time range | M | I | R2 | **Missing** | `lab/captures/*.csv` | Inspection | Ground truth |
| FR-LAB-05 | Lab starts and stops with one documented command | S | D | R2 | **Missing** | `lab/README.md` | Demonstration | Ease of use |
| FR-EVL-01 | Compute precision, recall, F1, FPR, ROC-AUC, PR-AUC, confusion matrix | M | T | R3 | **Missing** | `scripts/evaluate.py` | `tests/test_evaluate.py` | Statistical evaluation |
| FR-EVL-02 | Evaluation on public dataset and lab traffic; report generalisation gap | M | A | R3 | **Missing** | `scripts/evaluate.py` | Analysis | Bias measurement |
| FR-EVL-03 | Evaluation report as Markdown and JSON with seeds and library versions | S | I | R3 | **Missing** | `scripts/evaluate.py` | Inspection | Reproducibility |
| FR-EVL-04 | Benchmark packets/sec per stage and peak memory (Python & C++) | M | T | R4 | **Missing** | `scripts/benchmark.py` | `tests/test_benchmark.py` | Throughput testing |
| FR-EVL-05 | Save threshold sweep (PR curve data) as CSV and image | S | I | R3 | **Missing** | `scripts/evaluate.py` | Inspection | Operating curve |
| FR-MON-01 | Maintain metric counters (read, dropped, parse errors, flows, evictions, alerts) | M | T | R2 | **Missing** | `monitoring.py` | `tests/test_monitoring.py` | Telemetry |
| FR-MON-02 | Compute Population Stability Index (PSI) per 10min; warn if PSI > 0.25 | S | T | R4 | **Missing** | `monitoring.py` | `tests/test_monitoring.py` | Drift detection |
| FR-MON-03 | Structured logging (JSON option, log levels); never log payloads or tokens | M | I | R1 | **Missing** | `logging.py` | `tests/test_logging.py` | Secure logging |
| FR-DEV-01 | Public GitHub repo under MIT licence | M | I | R1 | **Implemented** | `LICENSE` | Inspection | MIT license in root |
| FR-DEV-02 | CI runs ruff lint, format check, and pytest on Python 3.10, 3.11, 3.12 | M | T | R1 | **Partially implemented** | `.github/workflows/ci.yml` | CI runs | In progress on `agent-dev` |
| FR-DEV-03 | Pre-commit hooks for whitespace, EOF, yaml, toml, keys, size, ruff | M | T | R1 | **Partially implemented** | `.pre-commit-config.yaml` | `pre-commit run` | Configured |
| FR-DEV-04 | Conventional Commits; rebase-and-merge PRs | S | I | R1 | **Partially implemented** | Git history | Inspection | Agent enforces format |
| FR-DEV-05 | Test captures anonymised, < 1 MB, verified by automated test | M | T | R1 | **Implemented** | `scripts/generate_sample_fixture.py` | `tests/test_fixture.py` | `sample_web.pcap` verified |
| FR-DEV-06 | Raw captures never committed; excluded by `.gitignore` and large file hook | M | I | R1 | **Implemented** | `.gitignore`, `.pre-commit-config.yaml` | Inspection | Configured |
| FR-DEV-07 | Line coverage >= 80% enforced in CI | M | T | R4 | **Missing** | `pyproject.toml`, `.github/workflows/ci.yml` | `pytest --cov` | Coverage enforcement |
| FR-DEV-08 | Dependabot alerts and `SECURITY.md` vulnerability reporting instructions | S | I | R2 | **Missing** | `SECURITY.md`, `.github/dependabot.yml` | Inspection | Security posture |
| FR-DEV-09 | Semantic Versioning with annotated tags and `CHANGELOG.md` | S | I | R1 | **Missing** | `CHANGELOG.md` | Inspection | Release management |
| FR-DEV-10 | Architecture Decision Records under `docs/adr/` | S | I | R1 | **Missing** | `docs/adr/` | Inspection | ADR tracking |
| FR-PKG-01 | Install via pip; provide `flowsentinel` entry point command | M | D | R4 | **Missing** | `pyproject.toml` | Demonstration | Packaging |
| FR-PKG-02 | Optional dependency groups: `capture`, `ml`, `api`, `dev` | S | I | R4 | **Missing** | `pyproject.toml` | Inspection | Clean core |
| FR-PKG-03 | PyPI publishing readiness | C | D | Later | **Missing** | Build artifacts | Demonstration | Post-1.0 |

---

## 12. Non-Functional Requirements (NFRs)

| ID | Description | Pri | Ver | Rel | Status | Notes |
|---|---|---|---|---|---|---|
| NFR-PERF-01 | Pure-Python pipeline sustains >= 20,000 pkts/s offline | M | T | R4 | **Missing** | Benchmark target |
| NFR-PERF-02 | C++ parser >= 5x faster than pure-Python | S | T | R4 | **Missing** | Pybind11 target |
| NFR-PERF-03 | Live rule alerts raised within 2s of evidence | M | T | R4 | **Missing** | Latency target |
| NFR-PERF-04 | Resident memory <= 512 MB at 100,000 active flows | M | T | R4 | **Missing** | Memory bounding |
| NFR-PERF-05 | ML stage scores >= 5,000 flows/s in batch mode | S | T | R3 | **Missing** | ML throughput |
| NFR-PERF-06 | Dashboard renders alert table within 2s with 10k alerts | S | T | R4 | **Missing** | UI latency |
| NFR-PERF-07 | `flowsentinel --help` prints within 2s | C | T | R4 | **Missing** | Startup latency |
| NFR-REL-01 | Robustness: 10,000 mutated frames handled without crash | M | T | R4 | **Missing** | Fuzz test |
| NFR-REL-02 | Clean shutdown on Ctrl+C: flush flows & persist alerts <= 5s | M | T | R4 | **Missing** | Signal handling |
| NFR-REL-03 | Atomic alert writes; crash does not corrupt SQLite | M | T | R2 | **Missing** | SQLite WAL |
| NFR-REL-04 | Deterministic alert output for same input and configuration | M | T | R2 | **Missing** | Reproducibility |
| NFR-REL-05 | API or dashboard failure does not stop capture or detection | S | T | R4 | **Missing** | Fault isolation |
| NFR-ACC-01 | Rule recall >= 0.95 on lab attack traffic | M | T | R2 | **Missing** | Accuracy target |
| NFR-ACC-02 | Benign false alert rate <= 0.1% on source-host windows | M | T | R2 | **Missing** | Low false alarm target |
| NFR-ACC-03 | Supervised ML detector macro F1 >= 0.85 on time-aware split | S | T | R3 | **Missing** | ML metric |
| NFR-ACC-04 | Every report includes confusion matrix, not accuracy alone | M | I | R3 | **Missing** | Evaluation standard |
| NFR-ACC-05 | Parser output matches Scapy reference on every field | M | T | R1 | **Implemented** | `tests/test_fixture_crosscheck.py` |
| NFR-SEC-01 | Safe parser for YAML and rule files | M | T | R2 | **Missing** | Safe loading |
| NFR-SEC-02 | Model files loaded from local path after SHA-256 verification | M | T | R3 | **Missing** | SHA-256 verification |
| NFR-SEC-03 | API binds to loopback default; remote requires token | M | T | R4 | **Missing** | Network isolation |
| NFR-SEC-04 | Input validation for capture files, API params, configs | M | T | R4 | **Missing** | Input boundaries |
| NFR-SEC-05 | Payload bytes never persisted by default | M | I | R2 | **Missing** | Privacy by design |
| NFR-SEC-06 | Logs do not contain payload, credentials, or tokens | M | I | R1 | **Missing** | Redaction in logger |
| NFR-SEC-07 | Fixtures contain no real personal network identifiers | M | T | R1 | **Implemented** | `tests/test_fixture.py` |
| NFR-SEC-08 | Offline analysis runs without elevated privileges | M | I | R4 | **Missing** | Principle of least privilege |
| NFR-ETH-01 | Documentation states tool is defensive | M | I | R1 | **Implemented** | Stated in README.md |
| NFR-ETH-02 | Attack tooling confined to isolated lab network | M | I | R2 | **Missing** | Docker bridge |
| NFR-ETH-03 | Public datasets cited with licences; not redistributed | M | I | R3 | **Missing** | Research ethics |
| NFR-ETH-04 | Review dependency licenses for MIT compatibility | M | I | R4 | **Missing** | License audit |
| NFR-ETH-05 | Scapy GPL-2.0 confined to optional extra; core is Scapy-free | S | I | R4 | **Missing** | Clean core |
| NFR-USE-01 | Install and analyze capture in <= 5 documented commands | M | D | R4 | **Missing** | Quickstart |
| NFR-USE-02 | Every command offers `--help` with examples and remediation | S | I | R1 | **Missing** | CLI help |
| NFR-USE-03 | Alert text understandable without ML knowledge | S | I | R3 | **Missing** | Plain language |
| NFR-USE-04 | Dashboard usable at >= 1024px and keyboard navigation | C | D | R4 | **Missing** | A11y / UI |
| NFR-MNT-01 | Type hints and docstrings on public API | S | I | R4 | **Partially implemented** | Parser is typed |
| NFR-MNT-02 | Zero ruff lint or format warnings | M | T | R1 | **Implemented** | Ruff passing |
| NFR-MNT-03 | One-direction module dependencies; no cycles | S | I | R2 | **Missing** | Architecture check |
| NFR-MNT-04 | Documentation includes architecture, limits, guides | M | I | R4 | **Partially implemented** | Architecture document started |
| NFR-PRT-01 | Support Python 3.10, 3.11, 3.12 | M | T | R1 | **Partially implemented** | In CI matrix |
| NFR-PRT-02 | Cross-platform offline analysis (Windows, Linux, macOS) | M | T | R4 | **Partially implemented** | Tested on Windows |
| NFR-PRT-03 | Automatic fallback to Python parser if C++ is absent | S | T | R4 | **Missing** | Dynamic fallback |
| NFR-PRT-04 | Captures written/read open in Wireshark | M | T | R1 | **Implemented** | Classic pcap |
| NFR-PRT-05 | Exported alerts are UTF-8 JSON Lines | S | T | R2 | **Missing** | JSON Lines format |
| NFR-SCL-01 | Bounded memory: flow table, host windows, queues | M | T | R2 | **Missing** | Memory bounding |
| NFR-SCL-02 | Documented single-node capacity limits | S | I | R4 | **Missing** | Docs |

---

## 13. Summary Statistics

| Classification | Count |
|---|---|
| **Total Requirements** | **161** |
| Must (M) | 114 |
| Should (S) | 41 |
| Could (C) | 6 |
| **Implemented** | **20** |
| **Partially implemented** | **8** |
| **Missing** | **133** |
| **Blocked** | **0** |
