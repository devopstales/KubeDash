#!/usr/bin/env python3
"""Leader-only task framework for KubeDash cluster mode."""

import functools
import logging
import time
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

from flask import Flask

from .leader_election import LeaderElector
from lib.prometheus import (
    METRIC_LEADER_TASKS_EXECUTED,
    METRIC_LEADER_TASK_DURATION,
    METRIC_LEADER_TASKS_SKIPPED,
)

logger = logging.getLogger(__name__)


class LeaderTaskRegistry:
    """Registry for tracking leader-only tasks."""

    def __init__(self):
        self.tasks: Dict[str, Dict[str, Any]] = {}
        self._leader_elector: Optional[LeaderElector] = None

    def register_task(self, name: str, func: Callable, description: str = "") -> None:
        """Register a leader-only task."""
        self.tasks[name] = {
            'func': func,
            'description': description,
            'executions': 0,
            'skips': 0,
            'last_execution': None,
            'last_duration_seconds': None,
            'last_status': 'registered',
        }
        logger.debug("Registered leader-only task: %s", name)

    def unregister_task(self, name: str) -> None:
        """Unregister a leader-only task."""
        if name in self.tasks:
            del self.tasks[name]
            logger.debug("Unregistered leader-only task: %s", name)

    def get_registered_tasks(self) -> List[str]:
        """Get list of registered task names."""
        return list(self.tasks.keys())

    def list_tasks(self) -> List[Dict[str, Any]]:
        """Get detailed information about all registered tasks."""
        return [
            {
                'name': name,
                'description': info['description'],
                'scope': 'leader_only',
                'executions': info['executions'],
                'skips': info['skips'],
                'last_execution': info.get('last_execution'),
                'status': 'registered'
            }
            for name, info in self.tasks.items()
        ]

    def set_leader_elector(self, leader_elector: LeaderElector) -> None:
        """Set the leader elector instance."""
        self._leader_elector = leader_elector

    def is_leader(self) -> bool:
        """Check if current instance is the leader."""
        if self._leader_elector is None:
            # If no leader election, assume single replica mode (always leader)
            return True
        return self._leader_elector.is_leader

    def execute_task(self, name: str, *args, **kwargs) -> Any:
        """Execute a registered task if this instance is the leader."""
        if name not in self.tasks:
            raise ValueError(f"Task '{name}' not registered")

        task_info = self.tasks[name]

        if not self.is_leader():
            task_info['skips'] += 1
            METRIC_LEADER_TASKS_SKIPPED.labels(task_name=name).inc()
            logger.info("Skipping leader-only task '%s' (not leader)", name)
            return None

        start_time = time.time()
        try:
            result = task_info['func'](*args, **kwargs)
            duration = time.time() - start_time
            task_info['executions'] += 1
            task_info['last_execution'] = datetime.utcnow().isoformat()
            task_info['last_duration_seconds'] = duration
            task_info['last_status'] = 'success'
            METRIC_LEADER_TASKS_EXECUTED.labels(task_name=name).inc()
            METRIC_LEADER_TASK_DURATION.labels(task_name=name).observe(duration)
            logger.info("Executed leader-only task '%s' in %.2fs", name, duration)
            return result
        except Exception as exc:
            duration = time.time() - start_time
            task_info['last_duration_seconds'] = duration
            task_info['last_status'] = 'error'
            METRIC_LEADER_TASK_DURATION.labels(task_name=name).observe(duration)
            logger.error("Leader-only task '%s' failed after %.2fs: %s", name, duration, exc)
            raise

    def get_task_stats(self, name: str) -> Optional[Dict[str, Any]]:
        """Get execution statistics for a task."""
        return self.tasks.get(name)


# Global registry instance
_task_registry = LeaderTaskRegistry()


def leader_only(func: Callable) -> Callable:
    """
    Decorator to mark a function as leader-only.

    In cluster mode, the function will only execute on the leader replica.
    In single replica mode, it executes normally.
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        if not _task_registry.is_leader():
            logger.info("Skipping leader-only function '%s' (not leader)", func.__name__)
            return None
        return func(*args, **kwargs)
    return wrapper


def register_leader_task(name: str, description: str = "") -> Callable:
    """Decorator to register a function as a leader-only task."""
    def decorator(func: Callable) -> Callable:
        _task_registry.register_task(name, func, description)
        return leader_only(func)
    return decorator


def initialize_leader_tasks(app: Flask) -> None:
    """Initialize leader task framework."""
    global _task_registry

    # Get leader elector from app extensions if available
    leader_elector = app.extensions.get('leader_elector')
    if leader_elector:
        _task_registry.set_leader_elector(leader_elector)
        app.logger.info("Leader task framework initialized with leader election")
    else:
        app.logger.info("Leader task framework initialized (single replica mode)")

    # Register built-in leader-only tasks
    from .metrics import CullDatabase
    _task_registry.register_task(
        'cull_metrics_database',
        lambda app, db, window: CullDatabase(app, db, window),
        'Clean up old metrics data from database'
    )


def get_task_registry() -> LeaderTaskRegistry:
    """Get the global task registry."""
    return _task_registry