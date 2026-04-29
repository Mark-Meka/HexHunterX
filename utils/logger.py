"""
HexHunterX -- Structured Logging System.

Provides color-coded, leveled logging with both console (Rich) and file output.
"""

import logging
import os
import sys
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme

# ──────────────────────────────────────────────
# Custom theme for HexHunterX console output
# ──────────────────────────────────────────────
HexHunterX_THEME = Theme({
    "info": "cyan",
    "warning": "yellow",
    "error": "bold red",
    "critical": "bold white on red",
    "success": "bold green",
    "module": "bold magenta",
    "target": "bold blue",
    "vuln": "bold red",
    "dim": "dim white",
})

console = Console(theme=HexHunterX_THEME)

# ──────────────────────────────────────────────
# Banner
# ──────────────────────────────────────────────
BANNER = r"""
[bold cyan]
    ██╗  ██╗███████╗██╗  ██╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ ██╗  ██╗
    ██║  ██║██╔════╝╚██╗██╔╝██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗╚██╗██╔╝
    ███████║█████╗   ╚███╔╝ ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝ ╚███╔╝
    ██╔══██║██╔══╝   ██╔██╗ ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗ ██╔██╗
    ██║  ██║███████╗██╔╝ ██╗██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║██╔╝ ██╗
    ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝
[/bold cyan]
[dim]    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/dim]
[bold white]    Modular Penetration Testing Framework[/bold white]                    [dim]v1.0.0[/dim]
[dim]    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/dim]
"""


def print_banner():
    """Display the HexHunterX banner."""
    console.print(BANNER)


class HexHunterXLogger:
    """
    Centralized logger for the HexHunterX framework.

    Features:
        - Rich console output with color-coded levels
        - File logging with rotation-friendly naming
        - Module-tagged messages for traceability
        - Phase tracking for workflow visibility
    """

    _instances: dict[str, "HexHunterXLogger"] = {}

    def __init__(self, module_name: str, log_dir: str = "logs"):
        self.module_name = module_name
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        # Configure Python logger
        self.logger = logging.getLogger(f"HexHunterX.{module_name}")
        self.logger.setLevel(logging.DEBUG)
        self.logger.propagate = False

        if not self.logger.handlers:
            self._setup_handlers()

    def _setup_handlers(self):
        """Configure console and file handlers."""
        # Rich console handler
        console_handler = RichHandler(
            console=console,
            show_path=False,
            show_time=True,
            rich_tracebacks=True,
            markup=True,
        )
        console_handler.setLevel(logging.INFO)
        console_format = logging.Formatter("%(message)s")
        console_handler.setFormatter(console_format)

        # File handler
        log_file = self.log_dir / f"HexHunterX_{datetime.now().strftime('%Y%m%d')}.log"
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_format = logging.Formatter(
            "%(asctime)s | %(name)s | %(levelname)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        file_handler.setFormatter(file_format)

        self.logger.addHandler(console_handler)
        self.logger.addHandler(file_handler)

    @classmethod
    def get_logger(cls, module_name: str) -> "HexHunterXLogger":
        """Get or create a logger instance for the given module."""
        if module_name not in cls._instances:
            cls._instances[module_name] = cls(module_name)
        return cls._instances[module_name]

    def info(self, message: str):
        self.logger.info(f"[module]\\[{self.module_name}][/module] {message}")

    def success(self, message: str):
        self.logger.info(f"[success]✓[/success] [module]\\[{self.module_name}][/module] {message}")

    def warning(self, message: str):
        self.logger.warning(f"[module]\\[{self.module_name}][/module] {message}")

    def error(self, message: str):
        self.logger.error(f"[module]\\[{self.module_name}][/module] {message}")

    def critical(self, message: str):
        self.logger.critical(f"[module]\\[{self.module_name}][/module] {message}")

    def debug(self, message: str):
        self.logger.debug(f"[{self.module_name}] {message}")

    def phase(self, phase_name: str):
        """Log a phase transition with visual separator."""
        console.print(f"\n[bold cyan]{'━' * 60}[/bold cyan]")
        console.print(f"[bold cyan]  ▶ PHASE: {phase_name.upper()}[/bold cyan]")
        console.print(f"[bold cyan]{'━' * 60}[/bold cyan]\n")
        self.logger.info(f"=== PHASE: {phase_name.upper()} ===")

    def finding(self, severity: str, vuln_type: str, target: str, detail: str = ""):
        """Log a vulnerability finding with severity coloring."""
        severity_colors = {
            "critical": "bold white on red",
            "high": "bold red",
            "medium": "bold yellow",
            "low": "bold blue",
            "info": "bold cyan",
        }
        color = severity_colors.get(severity.lower(), "white")
        console.print(
            f"  [{color}][{severity.upper()}][/{color}] "
            f"[vuln]{vuln_type}[/vuln] → [target]{target}[/target]"
        )
        if detail:
            console.print(f"    [dim]↳ {detail}[/dim]")
        self.logger.info(f"FINDING | {severity.upper()} | {vuln_type} | {target} | {detail}")

    def progress(self, current: int, total: int, description: str = ""):
        """Log progress inline."""
        pct = (current / total * 100) if total > 0 else 0
        bar_len = 30
        filled = int(bar_len * current / total) if total > 0 else 0
        bar = "█" * filled + "░" * (bar_len - filled)
        console.print(
            f"  [dim]{bar} {pct:5.1f}% ({current}/{total}) {description}[/dim]",
            end="\r" if current < total else "\n",
        )
