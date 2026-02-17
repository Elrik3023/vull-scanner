"""Adaptive thread pool manager for dynamic scaling based on workload."""

import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed, Future
from typing import Callable, Any, Iterator, Iterable
from dataclasses import dataclass


@dataclass
class ThreadConfig:
    """Configuration for adaptive threading."""
    min_threads: int = 5
    max_threads: int = 50
    scale_interval: float = 30.0  # Seconds between scaling checks
    scale_factor: float = 2.0  # Multiply threads by this when scaling


class AdaptiveThreadPool:
    """Thread pool that automatically scales based on workload and elapsed time.

    Starts with min_threads and scales up to max_threads if tasks are taking
    too long to complete.
    """

    def __init__(self, config: ThreadConfig | None = None):
        """Initialize the adaptive thread pool.

        Args:
            config: Threading configuration. Uses defaults if not provided.
        """
        self.config = config or ThreadConfig()
        self.current_threads = self.config.min_threads
        self._executor: ThreadPoolExecutor | None = None
        self._start_time: float = 0
        self._last_scale_time: float = 0
        self._completed_count: int = 0
        self._total_tasks: int = 0
        self._lock = threading.Lock()
        self._stop_flag = threading.Event()

    def __enter__(self):
        """Context manager entry."""
        self._executor = ThreadPoolExecutor(max_workers=self.current_threads)
        self._start_time = time.time()
        self._last_scale_time = self._start_time
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        if self._executor:
            self._executor.shutdown(wait=True)
            self._executor = None

    def _maybe_scale_up(self) -> bool:
        """Check if we should scale up threads and do so if needed.

        Returns:
            True if scaled up, False otherwise.
        """
        now = time.time()
        elapsed_since_scale = now - self._last_scale_time

        # Check if enough time has passed since last scale
        if elapsed_since_scale < self.config.scale_interval:
            return False

        # Check if we can still scale up
        if self.current_threads >= self.config.max_threads:
            return False

        # Calculate progress rate
        with self._lock:
            if self._total_tasks == 0:
                return False

            completion_rate = self._completed_count / self._total_tasks
            elapsed_total = now - self._start_time

            # If less than 25% done after scale_interval, scale up
            expected_completion = elapsed_total / (self.config.scale_interval * 4)

            if completion_rate < expected_completion:
                # Scale up
                new_threads = min(
                    int(self.current_threads * self.config.scale_factor),
                    self.config.max_threads
                )

                if new_threads > self.current_threads:
                    old_threads = self.current_threads
                    self.current_threads = new_threads
                    self._last_scale_time = now
                    print(f"    [*] Scaling threads: {old_threads} -> {new_threads}")
                    return True

        return False

    def map_with_progress(
        self,
        fn: Callable[..., Any],
        items: Iterable[Any],
        progress_callback: Callable[[int, int], None] | None = None,
        total_count: int | None = None,
        expand_tuples: bool = False,
    ) -> Iterator[Any]:
        """Execute function on items with automatic scaling and progress tracking.

        Args:
            fn: Function to execute on each item.
            items: List of items to process.
            progress_callback: Optional callback(completed, total) for progress updates.

        Yields:
            Results from function execution.
        """
        if not self._executor:
            raise RuntimeError("ThreadPool must be used as context manager")

        if total_count is None:
            try:
                total_count = len(items)  # type: ignore[arg-type]
            except TypeError:
                total_count = 0

        self._total_tasks = total_count
        self._completed_count = 0

        iterator = iter(items)

        def submit_item(item: Any) -> Future:
            if expand_tuples and isinstance(item, tuple):
                return self._executor.submit(fn, *item)
            return self._executor.submit(fn, item)

        while True:
            if self._stop_flag.is_set():
                break

            futures: dict[Future, Any] = {}
            batch_size = max(self.current_threads * 2, 1)

            for _ in range(batch_size):
                if self._stop_flag.is_set():
                    break
                try:
                    item = next(iterator)
                except StopIteration:
                    break
                futures[submit_item(item)] = item

            if not futures:
                break

            for future in as_completed(futures):
                if self._stop_flag.is_set():
                    for pending in futures:
                        pending.cancel()
                    break

                with self._lock:
                    self._completed_count += 1
                    completed = self._completed_count

                if progress_callback and self._total_tasks:
                    progress_callback(completed, self._total_tasks)

                try:
                    yield future.result()
                except Exception:
                    # Yield None for failed tasks, let caller handle
                    yield None

            if self._stop_flag.is_set():
                break

            if self._maybe_scale_up():
                if self._executor:
                    self._executor.shutdown(wait=True)
                    self._executor = ThreadPoolExecutor(max_workers=self.current_threads)

    def submit(self, fn: Callable[..., Any], *args, **kwargs) -> Future:
        """Submit a single task to the pool.

        Args:
            fn: Function to execute.
            *args: Positional arguments for function.
            **kwargs: Keyword arguments for function.

        Returns:
            Future representing the pending result.
        """
        if not self._executor:
            raise RuntimeError("ThreadPool must be used as context manager")

        with self._lock:
            self._total_tasks += 1

        return self._executor.submit(fn, *args, **kwargs)

    def stop(self):
        """Signal the pool to stop accepting new work."""
        self._stop_flag.set()

    @property
    def is_stopped(self) -> bool:
        """Check if stop was requested."""
        return self._stop_flag.is_set()


def parallel_execute(
    fn: Callable[..., Any],
    items: list[Any],
    max_threads: int = 20,
    progress_interval: int = 10,
) -> list[Any]:
    """Simple parallel execution helper.

    Args:
        fn: Function to execute on each item.
        items: List of items (or tuples of args) to process.
        max_threads: Maximum number of threads.
        progress_interval: Print progress every N items.

    Returns:
        List of results (None for failed items).
    """
    results = []
    config = ThreadConfig(min_threads=max_threads, max_threads=max_threads)

    def progress_cb(completed: int, total: int):
        if completed % progress_interval == 0:
            print(f"    Processed {completed}/{total}...")

    with AdaptiveThreadPool(config) as pool:
        for result in pool.map_with_progress(fn, items, progress_cb):
            results.append(result)

    return results
