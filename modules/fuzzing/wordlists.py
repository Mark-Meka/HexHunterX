"""
HexHunterX -- Wordlist Management Module.

Load, merge, deduplicate, and manage wordlists for scanning/fuzzing.
"""

from pathlib import Path
from utils.logger import HexHunterXLogger
from utils.helpers import deduplicate

logger = HexHunterXLogger.get_logger("fuzzing.wordlists")


class WordlistManager:
    """
    Manage wordlists for various scanning operations.

    Features:
        - Load from files
        - Merge multiple wordlists
        - Deduplicate entries
        - Apply filters and transformations
    """

    def __init__(self, base_dir: str = "data/wordlists"):
        self.base_dir = Path(base_dir)
        self._cache: dict[str, list[str]] = {}

    def load(self, filename: str) -> list[str]:
        """Load a wordlist by filename from the base directory."""
        if filename in self._cache:
            return self._cache[filename]

        filepath = self.base_dir / filename
        if not filepath.exists():
            logger.warning(f"Wordlist not found: {filepath}")
            return []

        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            words = [line.strip() for line in f if line.strip() and not line.startswith("#")]

        self._cache[filename] = words
        logger.debug(f"Loaded {len(words)} words from {filename}")
        return words

    def load_multiple(self, filenames: list[str]) -> list[str]:
        """Load and merge multiple wordlists."""
        combined = []
        for filename in filenames:
            combined.extend(self.load(filename))
        return deduplicate(combined)

    def load_custom(self, filepath: str) -> list[str]:
        """Load a custom wordlist from any path."""
        path = Path(filepath)
        if not path.exists():
            logger.warning(f"Custom wordlist not found: {filepath}")
            return []

        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            words = [line.strip() for line in f if line.strip() and not line.startswith("#")]

        return words

    @staticmethod
    def filter_by_length(words: list[str], min_len: int = 1, max_len: int = 50) -> list[str]:
        """Filter words by length."""
        return [w for w in words if min_len <= len(w) <= max_len]

    @staticmethod
    def apply_prefix(words: list[str], prefix: str) -> list[str]:
        """Add a prefix to all words."""
        return [f"{prefix}{w}" for w in words]

    @staticmethod
    def apply_suffix(words: list[str], suffix: str) -> list[str]:
        """Add a suffix to all words."""
        return [f"{w}{suffix}" for w in words]

    def get_available(self) -> list[str]:
        """List available wordlists in the base directory."""
        if not self.base_dir.exists():
            return []
        return [f.name for f in self.base_dir.iterdir() if f.is_file() and f.suffix == ".txt"]
