"""Leader-gated background tasks (ADR-0007 RQ / ADR-0008 leader election).

Each module exposes an RQ-callable ``run()`` (or ``evaluate()`` for alerts);
``wsgi.py`` enqueues them on the ``kubedash`` queue only while this replica
leads, so every task executes exactly once fleet-wide.
"""
