#!/usr/bin/env python3
"""
HexHunter -- Modular Penetration Testing Framework.

A semi-automated pentesting framework that automates recon, scanning,
fuzzing, and vulnerability detection for bug bounty and red team workflows.

Usage:
    python main.py -t target.com --full-scan
    python main.py -t target.com --recon --scan
    python main.py -t 192.168.1.0/24 --scan --threads 100

Author: HexHunter Team
License: MIT
"""

import os
os.environ.setdefault("PYTHONIOENCODING", "utf-8")

import asyncio
import sys
from pathlib import Path

import yaml

from cli.interface import parse_args
from core.engine import HexHunterEngine
from utils.logger import print_banner, HexHunterLogger, console

logger = HexHunterLogger.get_logger("main")


def load_config(config_path: str) -> dict:
    """Load configuration from YAML file with defaults fallback."""
    path = Path(config_path)
    if path.exists():
        with open(path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f) or {}
        logger.info(f"Config loaded: {config_path}")
        return config
    else:
        logger.warning(f"Config not found at {config_path}, using defaults")
        return {
            "general": {"threads": 50, "timeout": 10, "rate_limit": 10,
                         "user_agent": "HexHunter/1.0", "max_retries": 3},
            "database": {"path": "hexhunter.db"},
            "recon": {"subdomain_wordlist": "data/wordlists/common_subdomains.txt"},
            "scanning": {"dir_wordlist": "data/wordlists/common_dirs.txt",
                         "extensions": ["", ".php", ".html", ".js", ".json", ".txt"]},
            "fuzzing": {"param_wordlist": "data/wordlists/common_params.txt", "max_depth": 3},
            "reporting": {"format": ["json", "html"], "output_dir": "reports/output"},
        }


def apply_cli_overrides(config: dict, cli_args: dict) -> dict:
    """Apply CLI argument overrides to configuration."""
    if cli_args.get("threads"):
        config.setdefault("general", {})["threads"] = cli_args["threads"]
    if cli_args.get("rate_limit"):
        config.setdefault("general", {})["rate_limit"] = cli_args["rate_limit"]
    if cli_args.get("timeout"):
        config.setdefault("general", {})["timeout"] = cli_args["timeout"]
    if cli_args.get("db_path"):
        config.setdefault("database", {})["path"] = cli_args["db_path"]
    if cli_args.get("output_dir"):
        config.setdefault("reporting", {})["output_dir"] = cli_args["output_dir"]

    # Auth config
    auth_config = {}
    for key in ("cookie", "auth_token", "auth_header", "login_url", "login_user", "login_pass"):
        if cli_args.get(key):
            auth_config[key] = cli_args[key]
    if auth_config:
        config["auth"] = auth_config

    # OOB config
    if cli_args.get("oob"):
        config["oob"] = {
            "enabled": True,
            "server": cli_args.get("oob_server"),
            "token": cli_args.get("oob_token"),
            "poll_interval": cli_args.get("oob_poll", 5),
            "wait_timeout": cli_args.get("oob_wait", 30),
        }

    return config


async def run():
    """Main async entry point."""
    # Parse CLI arguments
    cli_args = parse_args()

    # Display banner
    if not cli_args.get("silent"):
        print_banner()

    # Load and override config
    config = load_config(cli_args["config_file"])
    config = apply_cli_overrides(config, cli_args)

    # Display scan info
    console.print(f"  [bold cyan]Target:[/bold cyan]  {cli_args['target']}")
    console.print(f"  [bold cyan]Phases:[/bold cyan]  {', '.join(cli_args['phases'])}")
    console.print(f"  [bold cyan]Resume:[/bold cyan]  {'Yes' if cli_args['resume'] else 'No'}")

    if config.get("auth"):
        auth_mode = "cookie" if config["auth"].get("cookie") else \
                    "bearer" if config["auth"].get("auth_token") else \
                    "header" if config["auth"].get("auth_header") else \
                    "auto-login" if config["auth"].get("login_url") else "none"
        console.print(f"  [bold cyan]Auth:[/bold cyan]    {auth_mode}")

    if config.get("oob", {}).get("enabled"):
        server = config["oob"].get("server") or "oast.pro"
        console.print(f"  [bold cyan]OOB:[/bold cyan]     enabled ({server})")

    console.print()

    # Create and run engine
    engine = HexHunterEngine(config)
    await engine.run(
        target=cli_args["target"],
        phases=cli_args["phases"],
        resume=cli_args["resume"],
    )


def main():
    """Synchronous entry point."""
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Scan interrupted by user[/bold yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"\n[bold red]Fatal error: {e}[/bold red]")
        sys.exit(1)


if __name__ == "__main__":
    main()
