"""
HexHunterX -- Task Scheduler.

Manages concurrent task execution with semaphores and phase tracking.
"""

import asyncio
from enum import Enum
from dataclasses import dataclass, field

from utils.logger import HexHunterXLogger

logger = HexHunterXLogger.get_logger("scheduler")


class PhaseStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    SKIPPED = "skipped"
    FAILED = "failed"


@dataclass
class PhaseResult:
    phase: str
    status: PhaseStatus
    items_processed: int = 0
    items_found: int = 0
    errors: int = 0
    duration_seconds: float = 0.0


class TaskScheduler:
    """
    Manages concurrent task execution for scan phases.

    Features:
        - Semaphore-based concurrency control
        - Phase tracking and completion status
        - Error collection and retry support
        - Progress callbacks
    """

    def __init__(self, max_concurrent: int = 50):
        self.max_concurrent = max_concurrent
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._phases: dict[str, PhaseStatus] = {}
        self._results: dict[str, PhaseResult] = {}
        self._errors: list[dict] = []

    def set_phase(self, phase: str, status: PhaseStatus):
        """Update phase status."""
        self._phases[phase] = status
        logger.debug(f"Phase '{phase}' → {status.value}")

    def get_phase_status(self, phase: str) -> PhaseStatus:
        return self._phases.get(phase, PhaseStatus.PENDING)

    def store_result(self, result: PhaseResult):
        self._results[result.phase] = result

    def get_results(self) -> dict[str, PhaseResult]:
        return self._results

    async def run_tasks(self, tasks: list, worker_func, description: str = "") -> list:
        """
        Execute tasks concurrently with semaphore control.

        Args:
            tasks: List of task inputs
            worker_func: Async function to process each task
            description: Description for logging

        Returns:
            List of results from worker_func
        """
        results = []
        total = len(tasks)
        completed = 0

        if not tasks:
            return results

        logger.info(f"Scheduling {total} tasks: {description}")

        async def _wrapped(task_input):
            nonlocal completed
            async with self._semaphore:
                try:
                    result = await worker_func(task_input)
                    completed += 1
                    if completed % max(1, total // 10) == 0:
                        logger.info(f"  Progress: {completed}/{total} ({completed*100//total}%)")
                    return result
                except Exception as e:
                    self._errors.append({
                        "task": str(task_input)[:200],
                        "error": str(e),
                    })
                    completed += 1
                    return None

        gathered = await asyncio.gather(*[_wrapped(t) for t in tasks], return_exceptions=False)
        results = [r for r in gathered if r is not None]

        logger.info(f"  Completed: {len(results)}/{total} successful, {len(self._errors)} errors")
        return results

    async def run_phase(self, phase_name: str, tasks: list, worker_func) -> PhaseResult:
        """
        Execute a full scan phase with tracking.

        Args:
            phase_name: Name of the phase
            tasks: List of task inputs
            worker_func: Async function to process each task

        Returns:
            PhaseResult with statistics
        """
        import time

        self.set_phase(phase_name, PhaseStatus.RUNNING)
        logger.phase(phase_name)

        start = time.monotonic()
        error_count_before = len(self._errors)

        try:
            results = await self.run_tasks(tasks, worker_func, description=phase_name)
            duration = time.monotonic() - start
            new_errors = len(self._errors) - error_count_before

            result = PhaseResult(
                phase=phase_name,
                status=PhaseStatus.COMPLETED,
                items_processed=len(tasks),
                items_found=len(results),
                errors=new_errors,
                duration_seconds=round(duration, 2),
            )
            self.set_phase(phase_name, PhaseStatus.COMPLETED)
            self.store_result(result)

            logger.success(
                f"Phase '{phase_name}' completed in {duration:.1f}s -- "
                f"{len(results)} results, {new_errors} errors"
            )
            return result

        except Exception as e:
            self.set_phase(phase_name, PhaseStatus.FAILED)
            logger.error(f"Phase '{phase_name}' failed: {e}")
            result = PhaseResult(phase=phase_name, status=PhaseStatus.FAILED)
            self.store_result(result)
            return result

    @property
    def summary(self) -> dict:
        return {
            phase: {
                "status": result.status.value,
                "processed": result.items_processed,
                "found": result.items_found,
                "errors": result.errors,
                "duration": f"{result.duration_seconds}s",
            }
            for phase, result in self._results.items()
        }
