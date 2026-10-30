from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from threading import Event, Lock
from typing import Any
from uuid import uuid4

from .correlation import CorrelationSummary, correlate_results
from .core import RunResult, utc_now
from .api_scan import CancelledError, run_scan


@dataclass
class Job:
    id: str
    payload: dict[str, Any]
    status: str = "queued"
    progress: int = 0
    total: int = 0
    current_module: str | None = None
    created_at: str = field(default_factory=utc_now)
    started_at: str | None = None
    finished_at: str | None = None
    results: list[RunResult] = field(default_factory=list)
    correlation: CorrelationSummary = field(default_factory=CorrelationSummary)
    error: str | None = None
    cancel_event: Event = field(default_factory=Event, repr=False)
    future: Future[Any] | None = field(default=None, repr=False)

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "status": self.status, "progress": self.progress, "total": self.total, "current_module": self.current_module, "created_at": self.created_at, "started_at": self.started_at, "finished_at": self.finished_at, "results": [item.to_dict("both") for item in self.results], "correlation": self.correlation.to_dict(), "error": self.error}


class JobManager:
    def __init__(self, max_workers: int = 2) -> None:
        self._jobs: dict[str, Job] = {}
        self._lock = Lock()
        self._executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="amf-job")

    def create(self, payload: dict[str, Any]) -> Job:
        job = Job(uuid4().hex, payload)
        with self._lock:
            self._jobs[job.id] = job
        job.future = self._executor.submit(self._run, job)
        return job

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)

    def cancel(self, job_id: str) -> Job | None:
        job = self.get(job_id)
        if not job:
            return None
        job.cancel_event.set()
        if job.status == "queued":
            job.status = "cancelled"
        return job

    def _run(self, job: Job) -> None:
        job.status = "running"
        job.started_at = utc_now()
        try:
            total = len(_profile_names(job.payload))
            job.total = total
            def progress(index: int, total_count: int, module_name: str) -> None:
                job.progress = index
                job.total = total_count
                job.current_module = module_name
                if job.cancel_event.is_set():
                    raise JobCancelled()
            job.results = run_scan(job.payload, progress=progress, cancel_event=job.cancel_event)
            job.correlation = correlate_results(job.results)
            job.status = "completed"
            job.progress = job.total
        except (JobCancelled, CancelledError):
            job.status = "cancelled"
        except Exception as exc:
            job.status = "failed"
            job.error = str(exc)
        finally:
            job.current_module = None
            job.finished_at = utc_now()


class JobCancelled(Exception):
    pass


def _profile_names(payload: dict[str, Any]) -> list[str]:
    from .profiles import profile_modules
    return [module.name for module in profile_modules(payload.get("profile", "full"))]
