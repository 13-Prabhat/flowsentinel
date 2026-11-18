from __future__ import annotations

import io
import json
import logging
from pathlib import Path

import pytest

from flowsentinel.cli import main
from flowsentinel.logging import JsonFormatter, setup_logging

SAMPLE_PCAP = Path(__file__).parent / "fixtures" / "sample_web.pcap"


def test_cli_version(capsys):
    """FR-CLI-06: --version displays version and exits cleanly."""
    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])
    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    assert "0.0.1" in captured.out or "0.0.1" in captured.err


def test_cli_help(capsys):
    """FR-CLI-06: --help displays usage and exits cleanly."""
    with pytest.raises(SystemExit) as exc_info:
        main(["--help"])
    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    assert "flowsentinel" in captured.out


def test_cli_no_args_exits_with_code_2(capsys):
    """FR-CLI-01: Invalid / missing command exits with code 2."""
    ret = main([])
    assert ret == 2


def test_cli_invalid_arg_exits_with_code_2():
    """FR-CLI-01: Unrecognized flag exits with code 2."""
    with pytest.raises(SystemExit) as exc_info:
        main(["--invalid-flag"])
    assert exc_info.value.code == 2


def test_cli_analyze_missing_file_exits_with_code_1(capsys):
    """FR-CLI-01: Runtime error on missing file exits with code 1."""
    ret = main(["analyze", "non_existent_file.pcap"])
    assert ret == 1
    captured = capsys.readouterr()
    assert "PCAP file not found" in captured.err


def test_at_01_acceptance_test_analyze_fixture(capsys):
    """AT-01: Run flowsentinel analyze on fixture; exit code 0; zero alerts."""
    ret = main(["analyze", str(SAMPLE_PCAP)])
    assert ret == 0
    captured = capsys.readouterr()
    out = captured.out

    assert "FlowSentinel Offline Analysis Summary" in out
    assert "Packets Read:" in out
    assert "Flows Assembled:" in out
    assert "Alerts Raised:    0" in out


def test_cli_analyze_json_format(capsys):
    """FR-CLI-06: Support JSON output format."""
    ret = main(["analyze", str(SAMPLE_PCAP), "--format", "json"])
    assert ret == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)

    assert data["packets_read"] > 0
    assert data["flows_assembled"] > 0
    assert data["alerts_raised"] == 0
    assert data["parse_errors"] == 0


def test_cli_analyze_csv_output(tmp_path):
    """FR-FEA-06 & FR-CLI-01: Export CSV from CLI analyze."""
    out_csv = tmp_path / "cli_features.csv"
    ret = main(["analyze", str(SAMPLE_PCAP), "-o", str(out_csv)])
    assert ret == 0
    assert out_csv.exists()
    assert out_csv.stat().st_size > 0


def test_structured_logging():
    """FR-MON-03: Structured logging configuration and JSON formatting."""
    buf = io.StringIO()
    logger = setup_logging(level="DEBUG", json_format=True, stream=buf)
    logger.info("Test message")

    output = buf.getvalue().strip()
    entry = json.loads(output)
    assert entry["level"] == "INFO"
    assert entry["message"] == "Test message"
    assert "timestamp" in entry

    # Text format
    buf_text = io.StringIO()
    logger_text = setup_logging(level="WARNING", json_format=False, stream=buf_text)
    logger_text.warning("Warning message")
    text_out = buf_text.getvalue().strip()
    assert "[WARNING]" in text_out
    assert "Warning message" in text_out


def test_json_formatter_with_exception():
    """FR-MON-03: JsonFormatter handles exception text cleanly."""
    formatter = JsonFormatter()
    record = logging.LogRecord(
        name="test",
        level=logging.ERROR,
        pathname="test.py",
        lineno=10,
        msg="Error occurred",
        args=(),
        exc_info=None,
    )
    record.exc_text = "Traceback (most recent call last): ..."
    formatted = formatter.format(record)
    entry = json.loads(formatted)
    assert entry["exception"] == "Traceback (most recent call last): ..."
