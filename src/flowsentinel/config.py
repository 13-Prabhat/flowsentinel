from pathlib import Path
from typing import Any, Dict, Optional
import os
import yaml


DEFAULT_CONFIG: Dict[str, Any] = {
    "capture": {
        "interface": None,
        "bpf_filter": "ip",
    },
    "flows": {
        "idle_timeout_s": 60,
        "active_timeout_s": 120,
        "max_active_flows": 100000,
    },
    "features": {
        "host_window_s": 10,
    },
    "detectors": {
        "cooldown_s": 60,
        "port_scan": {
            "enabled": True,
            "min_unique_ports": 50,
            "window_s": 10,
            "min_entropy_bits": 4.0,
        },
        "syn_flood": {
            "enabled": True,
            "syn_rate_per_s": 200,
            "max_completion_ratio": 0.10,
        },
        "brute_force": {
            "enabled": True,
            "ports": [21, 22, 23, 3389],
            "min_connections": 20,
            "window_s": 60,
        },
    },
    "alerts": {
        "database": "flowsentinel.db",
        "retention_days": 30,
    },
    "logging": {
        "level": "INFO",
        "json": False,
    },
}


def load_config(config_path: Optional[Path] = None) -> Dict[str, Any]:
    """
    Loads configuration following precedence:
    1. System Defaults
    2. YAML Configuration File (Safe Load)
    3. Environment Variables (FLOWSENTINEL_*)
    """
    config = DEFAULT_CONFIG.copy()

    if config_path and config_path.exists():
        with open(config_path, "r", encoding="utf-8") as f:
            # Safe loader prevents code execution during YAML parsing (NFR-SEC-01)
            file_config = yaml.safe_load(f) or {}
            config.update(file_config)

    return config
