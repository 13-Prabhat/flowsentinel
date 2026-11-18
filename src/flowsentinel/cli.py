from __future__ import annotations

import argparse
import json
import sys
import traceback
from collections.abc import Sequence
from pathlib import Path

from flowsentinel.features import extract_flow_features
from flowsentinel.flows.table import FlowTable
from flowsentinel.logging import setup_logging
from flowsentinel.parser.pcap import read_pcap

VERSION = "0.0.1"


class ArgumentParserWithExitCode(argparse.ArgumentParser):
    """Custom ArgumentParser that exits with code 2 on argument errors (FR-CLI-01)."""

    def error(self, message: str) -> None:
        sys.stderr.write(f"Error: {message}\n")
        self.print_usage(sys.stderr)
        sys.exit(2)


def create_parser() -> argparse.ArgumentParser:
    """Build top-level argument parser and subcommands (FR-CLI-06)."""
    parser = ArgumentParserWithExitCode(
        prog="flowsentinel",
        description="FlowSentinel: Explainable network intrusion detection from flow metadata.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {VERSION}",
        help="Show program's version number and exit.",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Logging verbosity level (default: INFO).",
    )
    parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format: table or json (default: table).",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        default=False,
        help="Display full stack traces on error.",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # analyze subcommand (FR-CLI-01)
    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Run offline flow assembly and detection on a classic pcap capture.",
    )
    analyze_parser.add_argument(
        "pcap",
        help="Path to classic libpcap file (.pcap).",
    )
    analyze_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default=None,
        help="Override output format (table or json).",
    )
    analyze_parser.add_argument(
        "--output",
        "-o",
        type=str,
        default=None,
        help="Optional path to export extracted features to CSV.",
    )

    return parser


def run_analyze(
    pcap_path: str,
    output_format: str = "table",
    csv_output: str | None = None,
) -> int:
    """Execute offline analysis pipeline on a pcap file (FR-CLI-01, AT-01)."""
    path = Path(pcap_path)
    if not path.is_file():
        sys.stderr.write(f"Error: PCAP file not found: {pcap_path}\n")
        return 1

    table = FlowTable()
    packets_read = 0
    parse_errors = 0
    all_features = []

    try:
        reader = read_pcap(path)
        for pkt in reader:
            packets_read += 1
            for expired_flow in table.process_packet(pkt):
                feats = extract_flow_features(expired_flow)
                all_features.append(feats)

        # Flush any remaining active flows at EOF (FR-FLW-05)
        for flushed_flow in table.flush():
            feats = extract_flow_features(flushed_flow)
            all_features.append(feats)

    except Exception as exc:
        sys.stderr.write(f"Error processing PCAP '{pcap_path}': {exc}\n")
        return 1

    if csv_output:
        from flowsentinel.features import export_csv

        export_csv(all_features, csv_output)

    summary = {
        "pcap": str(path),
        "packets_read": packets_read,
        "flows_assembled": len(all_features),
        "parse_errors": parse_errors,
        "alerts_raised": 0,
    }

    if output_format == "json":
        print(json.dumps(summary, indent=2))
    else:
        print("FlowSentinel Offline Analysis Summary")
        print("=" * 40)
        print(f"Capture:          {summary['pcap']}")
        print(f"Packets Read:     {summary['packets_read']}")
        print(f"Flows Assembled:  {summary['flows_assembled']}")
        print(f"Parse Errors:     {summary['parse_errors']}")
        print(f"Alerts Raised:    {summary['alerts_raised']}")
        print("=" * 40)

    return 0


def main(args: Sequence[str] | None = None) -> int:
    """Main CLI entrypoint for flowsentinel."""
    parser = create_parser()
    parsed_args = parser.parse_args(args)

    if not parsed_args.command:
        parser.print_help(sys.stderr)
        return 2

    # Set up structured logging
    is_json_format = parsed_args.format == "json"
    setup_logging(level=parsed_args.log_level, json_format=is_json_format)

    try:
        if parsed_args.command == "analyze":
            output_format = parsed_args.format or "table"
            return run_analyze(
                pcap_path=parsed_args.pcap,
                output_format=output_format,
                csv_output=getattr(parsed_args, "output", None),
            )
        else:
            sys.stderr.write(f"Unknown command: {parsed_args.command}\n")
            return 2
    except Exception as exc:
        if parsed_args.debug:
            traceback.print_exc(file=sys.stderr)
        else:
            sys.stderr.write(f"Runtime error: {exc}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
