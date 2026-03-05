#!/usr/bin/env python3
"""Workload cache background tasks initialization for KubeDash."""

from flask import Flask


def initialize_workloadcachers(app: Flask):
    """
    Initialize and start background tasks for caching various Kubernetes workload resources.

    This function sets up periodic tasks to fetch and cache information about pods,
    deployments, statefulsets, daemonsets, and replicasets from all namespaces in the
    Kubernetes cluster. Each task runs every 900 seconds (15 minutes).

    Args:
        app (Flask): The Flask application instance, used to provide context for
                     the caching operations.

    Returns:
        None

    Note:
        This function starts multiple ThreadedTicker instances, each responsible
        for caching a specific type of Kubernetes resource. These tickers run
        in the background and update the cache at regular intervals.
    """
    from lib.helper_functions import ThreadedTicker
    from lib.k8s.workload_cahers import (
        fetch_and_cache_pods_all_namespaces,
        fetch_and_cache_deployments_all_namespaces,
        fetch_and_cache_statefulsets_all_namespaces,
        fetch_and_cache_daemonsets_all_namespaces,
        fetch_and_cache_replicasets_all_namespaces,
    )

    pod_ticker = ThreadedTicker(
        interval_sec=900,
        func=fetch_and_cache_pods_all_namespaces(app)
    )
    pod_ticker.start()

    deployment_ticker = ThreadedTicker(
        interval_sec=900,
        func=fetch_and_cache_deployments_all_namespaces(app)
    )
    deployment_ticker.start()

    statefulset_ticker = ThreadedTicker(
        interval_sec=900,
        func=fetch_and_cache_statefulsets_all_namespaces(app)
    )
    statefulset_ticker.start()

    daemonset_ticker = ThreadedTicker(
        interval_sec=900,
        func=fetch_and_cache_daemonsets_all_namespaces(app)
    )
    daemonset_ticker.start()

    replicasets_ticker = ThreadedTicker(
        interval_sec=900,
        func=fetch_and_cache_replicasets_all_namespaces(app)
    )
    replicasets_ticker.start()
