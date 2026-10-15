# flowsentinel
Open-source, explainable network intrusion detection: flow-based attack detection with rules + ML (Python, optional C++).
# FlowSentinel

![CI](https://github.com/13-Prabhat/flowsentinel/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)
![Status](https://img.shields.io/badge/status-early%20development-orange.svg)

**Explainable network intrusion detection from flow metadata.**

Most network traffic is encrypted, so inspecting payloads no longer works well.
FlowSentinel detects attacks from *how* traffic behaves (packet sizes, timing,
direction, entropy) using transparent rules plus machine learning, and tells
the analyst **why** each alert was raised.

> Status: early development. Built in public, with regular commits.

## Planned features

- [ ] Packet parsing (Ethernet, IPv4, TCP, UDP, ICMP) from pcap files and live interfaces
- [ ] Bidirectional flow assembly with timeouts
- [ ] Flow and per-host sliding-window features (e.g. port entropy, SYN ratio)
- [ ] Rule detectors: port scan, SYN flood, SSH/FTP brute force
- [ ] ML detectors: Isolation Forest, Random Forest / XGBoost
- [ ] Explainable alerts (SHAP + human-readable reasons)
- [ ] REST API (FastAPI) and live dashboard
- [ ] Docker attack lab for reproducible, labelled traffic
- [ ] Honest evaluation on public datasets and own lab traffic

## Architecture (planned)

```
pcap / live interface -> parser -> flow assembler -> features
                                              |-> rule detectors --\
                                              |-> ML detectors ----+-> explainer -> alerts -> API / dashboard
```

## Roadmap

| Month | Goal | Release |
|---|---|---|
| 1 | Parsing, flows, features, CLI | v0.1.0 |
| 2 | Docker lab and rule-based detection | v0.2.0 |
| 3 | ML models and explainability | v0.3.0 |
| 4 | Live mode, API, dashboard, benchmarks | v1.0.0 |

## Development setup

```bash
git clone git@github.com:13-Prabhat/flowsentinel.git
cd flowsentinel
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest
ruff check .
```

## Ethics and responsible use

FlowSentinel is a **defensive** tool. Only capture or test on networks you own or
are explicitly authorised to monitor. Datasets used are public research datasets.

## License

MIT, see [LICENSE](LICENSE).