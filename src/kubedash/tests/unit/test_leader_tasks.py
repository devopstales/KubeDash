#!/usr/bin/env python3
"""Unit tests for leader task framework."""

import pytest
from unittest.mock import Mock, patch

from flask import Flask

from lib.leader_tasks import (
    LeaderTaskRegistry,
    leader_only,
    register_leader_task,
    initialize_leader_tasks,
    get_task_registry,
)


@pytest.fixture
def app():
    """Create test Flask app."""
    app = Flask(__name__)
    app.config['TESTING'] = True
    return app


@pytest.fixture
def registry():
    """Create fresh task registry for each test."""
    # Reset global registry
    import lib.leader_tasks
    lib.leader_tasks._task_registry = LeaderTaskRegistry()
    return lib.leader_tasks._task_registry


class TestLeaderTaskRegistry:
    """Test LeaderTaskRegistry functionality."""

    def test_register_and_unregister_task(self, registry):
        """Test task registration and unregistration."""
        def dummy_task():
            return "executed"

        # Register task
        registry.register_task("test_task", dummy_task, "Test task")
        assert "test_task" in registry.tasks
        assert registry.tasks["test_task"]["func"] == dummy_task
        assert registry.tasks["test_task"]["description"] == "Test task"

        # Unregister task
        registry.unregister_task("test_task")
        assert "test_task" not in registry.tasks

    def test_get_registered_tasks(self, registry):
        """Test getting list of registered tasks."""
        def task1():
            pass

        def task2():
            pass

        registry.register_task("task1", task1)
        registry.register_task("task2", task2)

        tasks = registry.get_registered_tasks()
        assert "task1" in tasks
        assert "task2" in tasks
        assert len(tasks) == 2

    def test_is_leader_without_elector(self, registry):
        """Test is_leader returns True when no leader elector is set."""
        assert registry.is_leader() is True

    def test_is_leader_with_elector(self, registry):
        """Test is_leader delegates to leader elector."""
        mock_elector = Mock()
        mock_elector.is_leader = True
        registry.set_leader_elector(mock_elector)

        assert registry.is_leader() is True

        mock_elector.is_leader = False
        assert registry.is_leader() is False

    def test_execute_task_when_leader(self, registry):
        """Test task execution when instance is leader."""
        def dummy_task(value):
            return f"result_{value}"

        registry.register_task("test_task", dummy_task)

        # Mock as leader
        mock_elector = Mock()
        mock_elector.is_leader = True
        registry.set_leader_elector(mock_elector)

        result = registry.execute_task("test_task", "test")
        assert result == "result_test"
        assert registry.tasks["test_task"]["executions"] == 1
        assert registry.tasks["test_task"]["skips"] == 0

    def test_execute_task_when_not_leader(self, registry):
        """Test task skipping when instance is not leader."""
        def dummy_task():
            return "should_not_execute"

        registry.register_task("test_task", dummy_task)

        # Mock as not leader
        mock_elector = Mock()
        mock_elector.is_leader = False
        registry.set_leader_elector(mock_elector)

        result = registry.execute_task("test_task")
        assert result is None
        assert registry.tasks["test_task"]["executions"] == 0
        assert registry.tasks["test_task"]["skips"] == 1

    def test_execute_task_not_registered(self, registry):
        """Test executing unregistered task raises ValueError."""
        with pytest.raises(ValueError, match="Task 'nonexistent' not registered"):
            registry.execute_task("nonexistent")

    def test_get_task_stats(self, registry):
        """Test getting task execution statistics."""
        def dummy_task():
            pass

        registry.register_task("test_task", dummy_task, "Test task")
        stats = registry.get_task_stats("test_task")

        assert stats is not None
        assert stats["description"] == "Test task"
        assert stats["executions"] == 0
        assert stats["skips"] == 0

        # Test nonexistent task
        assert registry.get_task_stats("nonexistent") is None


class TestDecorators:
    """Test decorator functionality."""

    def test_leader_only_decorator_when_leader(self, registry):
        """Test @leader_only decorator allows execution when leader."""
        @leader_only
        def test_func():
            return "executed"

        # Mock as leader
        mock_elector = Mock()
        mock_elector.is_leader = True
        registry.set_leader_elector(mock_elector)

        result = test_func()
        assert result == "executed"

    def test_leader_only_decorator_when_not_leader(self, registry):
        """Test @leader_only decorator skips execution when not leader."""
        @leader_only
        def test_func():
            return "should_not_execute"

        # Mock as not leader
        mock_elector = Mock()
        mock_elector.is_leader = False
        registry.set_leader_elector(mock_elector)

        result = test_func()
        assert result is None

    def test_register_leader_task_decorator(self, registry):
        """Test @register_leader_task decorator."""
        @register_leader_task("my_task", "My test task")
        def my_function():
            return "executed"

        # Check task is registered
        assert "my_task" in registry.tasks
        assert registry.tasks["my_task"]["description"] == "My test task"
        # The function should be wrapped by leader_only
        assert callable(registry.tasks["my_task"]["func"])

        # Check function still has leader_only behavior
        mock_elector = Mock()
        mock_elector.is_leader = True
        registry.set_leader_elector(mock_elector)

        result = my_function()
        assert result == "executed"


class TestInitialization:
    """Test initialization functionality."""

    def test_initialize_leader_tasks_with_elector(self, app, registry):
        """Test initialization with leader elector available."""
        mock_elector = Mock()
        app.extensions['leader_elector'] = mock_elector

        initialize_leader_tasks(app)

        # Check elector was set
        assert registry._leader_elector == mock_elector

    def test_initialize_leader_tasks_without_elector(self, app, registry):
        """Test initialization without leader elector."""
        initialize_leader_tasks(app)

        # Check no elector set
        assert registry._leader_elector is None

    def test_get_task_registry(self):
        """Test getting global task registry."""
        registry = get_task_registry()
        assert isinstance(registry, LeaderTaskRegistry)