"""
HexHunter -- CLI Interface.

Command-line argument parsing and dispatch to the core engine.
"""

import argparse
import sys

from utils.logger import print_banner


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser with all flags."""
    parser = argparse.ArgumentParser(
        prog="hexhunter",
        description="HexHunter -- Modular Penetration Testing Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py -t example.com --full-scan
  python main.py -t example.com --recon --scan
  python main.py -t 192.168.1.0/24 --scan --threads 100
  python main.py -t example.com --vuln --resume
  python main.py -t example.com --recon --output reports/my_report
        """,
    )

    # Required
    parser.add_argument(
        "-t", "--target",
        required=True,
        help="Target domain, IP, CIDR, or URL",
    )

    # Phase selection
    phase_group = parser.add_argument_group("Scan Phases")
    phase_group.add_argument("--recon", action="store_true", help="Run reconnaissance phase")
    phase_group.add_argument("--scan", action="store_true", help="Run scanning phase")
    phase_group.add_argument("--fuzz", action="store_true", help="Run fuzzing phase")
    phase_group.add_argument("--vuln", action="store_true", help="Run vulnerability checks")
    phase_group.add_argument("--full-scan", action="store_true",
                             help="Run all phases (recon > scan > fuzz > vuln > report)")

    # Configuration
    config_group = parser.add_argument_group("Configuration")
    config_group.add_argument("--config", default="config/default.yaml",
                              help="Path to config file (default: config/default.yaml)")
    config_group.add_argument("--threads", type=int, default=None,
                              help="Number of concurrent threads (overrides config)")
    config_group.add_argument("--rate-limit", type=float, default=None,
                              help="Requests per second rate limit")
    config_group.add_argument("--timeout", type=int, default=None,
                              help="HTTP request timeout in seconds")

    # Output
    output_group = parser.add_argument_group("Output")
    output_group.add_argument("--output", "-o", default="reports/output",
                              help="Output directory for reports")
    output_group.add_argument("--format", choices=["json", "html", "both"], default="both",
                              help="Report format (default: both)")
    output_group.add_argument("--silent", action="store_true",
                              help="Suppress banner and non-essential output")

    # Advanced
    adv_group = parser.add_argument_group("Advanced")
    adv_group.add_argument("--resume", action="store_true",
                           help="Resume scan from database (skip completed phases)")
    adv_group.add_argument("--db", default="hexhunter.db",
                           help="SQLite database file path")
    adv_group.add_argument("--scope-file", default=None,
                           help="File containing in-scope targets (one per line)")
    adv_group.add_argument("--exclude-file", default=None,
                           help="File containing out-of-scope targets (one per line)")

    return parser


def parse_args(argv: list[str] | None = None) -> dict:
    """Parse CLI arguments and return configuration dict."""
    parser = build_parser()
    args = parser.parse_args(argv)

    # Determine phases
    phases = []
    if args.full_scan:
        phases = ["recon", "scan", "fuzz", "vuln", "report"]
    else:
        if args.recon:
            phases.append("recon")
        if args.scan:
            phases.append("scan")
        if args.fuzz:
            phases.append("fuzz")
        if args.vuln:
            phases.append("vuln")

    # Always generate report if phases were selected
    if phases and "report" not in phases:
        phases.append("report")

    if not phases:
        parser.error("No scan phase specified. Use --recon, --scan, --fuzz, --vuln, or --full-scan")

    return {
        "target": args.target,
        "phases": phases,
        "config_file": args.config,
        "threads": args.threads,
        "rate_limit": args.rate_limit,
        "timeout": args.timeout,
        "output_dir": args.output,
        "report_format": args.format,
        "silent": args.silent,
        "resume": args.resume,
        "db_path": args.db,
        "scope_file": args.scope_file,
        "exclude_file": args.exclude_file,
    }
