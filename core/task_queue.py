"""
AGENT ANONMUSK — Async Task Queue
================================
Phase 1: Lightweight asyncio-based local task runner.
Provides the same interface that a future Celery adapter would implement.
"""

from __future__ import annotations

import asyncio
import traceback
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Optional
from datetime import datetime, timezone

from rich.console import Console

console = Console()


class TaskState(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    RETRY = "retry"
    CANCELLED = "cancelled"


class TaskPriority(int, Enum):
    CRITICAL = 0
    HIGH = 1
    NORMAL = 2
    LOW = 3


@dataclass
class Task:
    """A unit of work in the queue."""
    id: str
    name: str
    func: Callable[..., Coroutine]
    args: tuple = ()
    kwargs: dict = field(default_factory=dict)
    priority: TaskPriority = TaskPriority.NORMAL
    state: TaskState = TaskState.PENDING
    result: Any = None
    error: Optional[str] = None
    retries: int = 0
    max_retries: int = 3
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    started_at: Optional[str] = None
    finished_at: Optional[str] = None

    def __lt__(self, other: "Task") -> bool:
        """Priority comparison for heapq."""
        return self.priority.value < other.priority.value


class AsyncTaskQueue:
    """
    Async task runner with priority queue and concurrency control.

    Usage:
        queue = AsyncTaskQueue(max_concurrent=5)

        async def my_scan(target):
            ...
            return results

        task_id = queue.submit("scan_target", my_scan, args=("example.com",))
        await queue.run_all()
        result = queue.get_result(task_id)
    """

    def __init__(self, max_concurrent: int = 10):
        self.max_concurrent = max_concurrent
        self._tasks: dict[str, Task] = {}
        self._queue: asyncio.PriorityQueue = asyncio.PriorityQueue()
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._counter = 0

    def submit(
        self,
        name: str,
        func: Callable[..., Coroutine],
        args: tuple = (),
        kwargs: Optional[dict] = None,
        priority: TaskPriority = TaskPriority.NORMAL,
        max_retries: int = 3,
    ) -> str:
        """Submit a task to the queue. Returns task ID."""
        self._counter += 1
        task_id = f"task_{self._counter:04d}"

        task = Task(
            id=task_id,
            name=name,
            func=func,
            args=args,
            kwargs=kwargs or {},
            priority=priority,
            max_retries=max_retries,
        )

        self._tasks[task_id] = task
        self._queue.put_nowait((priority.value, self._counter, task))
        return task_id

    async def _execute_task(self, task: Task):
        """Execute a single task with retry logic."""
        async with self._semaphore:
            task.state = TaskState.RUNNING
            task.started_at = datetime.now(timezone.utc).isoformat()

            try:
                task.result = await task.func(*task.args, **task.kwargs)
                task.state = TaskState.DONE
            except Exception as e:
                task.error = f"{type(e).__name__}: {e}\n{traceback.format_exc()}"
                task.retries += 1

                if task.retries < task.max_retries:
                    task.state = TaskState.RETRY
                    console.print(
                        f"[yellow]↻ Retrying[/] {task.name} "
                        f"({task.retries}/{task.max_retries})"
                    )
                    # Re-queue with backoff
                    await asyncio.sleep(2 ** task.retries)
                    self._queue.put_nowait(
                        (task.priority.value, self._counter, task)
                    )
                    self._counter += 1
                else:
                    task.state = TaskState.FAILED
                    console.print(
                        f"[bold red]✗ Failed[/] {task.name}: {e}"
                    )
            finally:
                task.finished_at = datetime.now(timezone.utc).isoformat()

    async def run_all(self) -> dict[str, Any]:
        """Run all queued tasks, returns dict of task_id → result."""
        workers = []

        while not self._queue.empty():
            _, _, task = await self._queue.get()
            if task.state in (TaskState.PENDING, TaskState.RETRY):
                workers.append(asyncio.create_task(self._execute_task(task)))

        if workers:
            await asyncio.gather(*workers, return_exceptions=True)

        # Handle any re-queued retry tasks
        if not self._queue.empty():
            await self.run_all()

        return {
            tid: t.result
            for tid, t in self._tasks.items()
            if t.state == TaskState.DONE
        }

    def get_result(self, task_id: str) -> Any:
        """Get the result of a completed task."""
        task = self._tasks.get(task_id)
        if not task:
            raise KeyError(f"Unknown task: {task_id}")
        if task.state == TaskState.DONE:
            return task.result
        if task.state == TaskState.FAILED:
            raise RuntimeError(f"Task failed: {task.error}")
        return None

    def get_status(self, task_id: str) -> TaskState:
        """Get the current state of a task."""
        task = self._tasks.get(task_id)
        return task.state if task else TaskState.PENDING

    @property
    def summary(self) -> dict[str, int]:
        """Count of tasks by state."""
        counts: dict[str, int] = {}
        for t in self._tasks.values():
            counts[t.state.value] = counts.get(t.state.value, 0) + 1
        return counts
