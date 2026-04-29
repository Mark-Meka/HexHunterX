"""
HexHunterX -- Base Tool Wrapper.

Abstract base class for wrapping external security tools.
"""

import asyncio
import json
import shutil
from abc import ABC, abstractmethod
from pathlib import Path

from utils.logger import HexHunterXLogger

logger = HexHunterXLogger.get_logger("integrations")


class ToolNotFoundError(Exception):
    """Raised when an external tool is not installed."""
    pass


class BaseToolWrapper(ABC):
    """
    Abstract base class for external tool integrations.

    Subclasses must implement:
        - tool_name: Name of the external tool binary
        - build_command: Build the CLI command
        - parse_output: Parse the tool's output
    """

    @property
    @abstractmethod
    def tool_name(self) -> str:
        """Name of the external tool binary."""
        pass

    def is_installed(self) -> bool:
        """Check if the tool is available on PATH."""
        return shutil.which(self.tool_name) is not None

    def require_installed(self):
        """Raise error if tool is not installed."""
        if not self.is_installed():
            raise ToolNotFoundError(
                f"'{self.tool_name}' is not installed or not on PATH. "
                f"Install it or use built-in alternatives."
            )

    async def execute(self, args: list[str], timeout: int = 300) -> tuple[str, str, int]:
        """
        Execute the tool with given arguments.

        Returns: (stdout, stderr, return_code)
        """
        self.require_installed()
        cmd = [self.tool_name] + args

        logger.debug(f"Executing: {' '.join(cmd)}")

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), timeout=timeout
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.communicate()
                logger.warning(f"{self.tool_name} timed out after {timeout}s")
                return "", "Timeout", -1

            return (
                stdout.decode("utf-8", errors="replace"),
                stderr.decode("utf-8", errors="replace"),
                process.returncode,
            )

        except Exception as e:
            logger.error(f"Error executing {self.tool_name}: {e}")
            return "", str(e), -1

    @abstractmethod
    def build_command(self, **kwargs) -> list[str]:
        """Build command-line arguments for the tool."""
        pass

    @abstractmethod
    def parse_output(self, stdout: str) -> list[dict]:
        """Parse the tool's stdout into structured data."""
        pass

    async def run(self, **kwargs) -> list[dict]:
        """Execute the tool and return parsed results."""
        if not self.is_installed():
            logger.warning(f"{self.tool_name} not installed, skipping")
            return []

        args = self.build_command(**kwargs)
        stdout, stderr, rc = await self.execute(args)

        if rc != 0 and rc != -1:
            logger.warning(f"{self.tool_name} exited with code {rc}")

        return self.parse_output(stdout)
