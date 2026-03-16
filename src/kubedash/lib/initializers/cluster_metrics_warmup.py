#!/usr/bin/env python3
"""Cluster-metrics cache warm-up: background ticker that periodically calls k8sGetClusterMetric()."""

import os
from functools import partial

from flask import Flask

from lib.helper_functions import ThreadedTicker, bool_var_test


def _cluster_metrics_warmup_callback(app: Flask):
    """Callback for the cluster-metrics ticker: run k8sGetClusterMetric() inside app context."""
    try:
        with app.app_context():
            from lib.k8s.metrics import k8sGetClusterMetric
            k8sGetClusterMetric()
    except Exception as e:
        app.logger.warning(f"Cluster-metrics warmup ticker failed: {e}")


def initialize_cluster_metrics_warmup(app: Flask):
    """
    Start a ThreadedTicker that periodically warms the cluster-metrics cache
    by calling k8sGetClusterMetric(), when enabled and interval > 0.

    Config (ini [performance] or env):
      - cluster_metrics_warm_enabled (default true); env KUBEDASH_CLUSTER_METRICS_WARM_ENABLED
      - cluster_metrics_warm_interval_sec (default 300); env KUBEDASH_CLUSTER_METRICS_WARM_INTERVAL

    If enabled is false or interval is 0, no ticker is started.
    """
    ini = app.config.get("kubedash.ini")
    if not ini:
        return

    enabled_str = os.environ.get("KUBEDASH_CLUSTER_METRICS_WARM_ENABLED")
    if enabled_str is None:
        enabled_str = ini.get("performance", "cluster_metrics_warm_enabled", fallback="true")

    interval_str = os.environ.get("KUBEDASH_CLUSTER_METRICS_WARM_INTERVAL")
    if interval_str is None:
        interval_str = ini.get("performance", "cluster_metrics_warm_interval_sec", fallback="300")

    enabled = bool_var_test(enabled_str)
    try:
        interval = int(interval_str)
    except (ValueError, TypeError):
        interval = 300

    if not enabled or interval <= 0:
        app.logger.info("Cluster-metrics warmup ticker disabled (enabled=%s, interval=%s)", enabled, interval)
        return

    ticker = ThreadedTicker(
        interval_sec=interval,
        func=partial(_cluster_metrics_warmup_callback, app),
    )
    ticker.start()
    app.logger.info("Cluster-metrics warmup ticker started (interval=%ds)", interval)
