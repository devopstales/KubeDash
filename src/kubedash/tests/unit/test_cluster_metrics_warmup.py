"""Unit tests for cluster-metrics warmup initializer."""
import pytest
from unittest.mock import patch, MagicMock

from lib.initializers.cluster_metrics_warmup import (
    initialize_cluster_metrics_warmup,
    _cluster_metrics_warmup_callback,
)


@pytest.fixture
def app_with_ini():
    """Flask app with kubedash.ini config mock."""
    from flask import Flask
    app = Flask(__name__)
    app.config["kubedash.ini"] = MagicMock()
    return app


def test_initialize_cluster_metrics_warmup_disabled_by_enabled_flag(app_with_ini):
    """When cluster_metrics_warm_enabled is false, no ticker is started (3.2)."""
    app_with_ini.config["kubedash.ini"].get.side_effect = lambda sec, key, fallback=None: (
        "false" if key == "cluster_metrics_warm_enabled" else (fallback or "300")
    )
    with patch("lib.initializers.cluster_metrics_warmup.os.environ", {}):
        with patch("lib.initializers.cluster_metrics_warmup.ThreadedTicker") as mock_ticker_class:
            initialize_cluster_metrics_warmup(app_with_ini)
            mock_ticker_class.assert_not_called()


def test_initialize_cluster_metrics_warmup_disabled_by_interval_zero(app_with_ini):
    """When cluster_metrics_warm_interval_sec is 0, no ticker is started (3.2)."""
    app_with_ini.config["kubedash.ini"].get.side_effect = lambda sec, key, fallback=None: (
        "0" if key == "cluster_metrics_warm_interval_sec" else (fallback or "true")
    )
    with patch("lib.initializers.cluster_metrics_warmup.os.environ", {}):
        with patch("lib.initializers.cluster_metrics_warmup.ThreadedTicker") as mock_ticker_class:
            initialize_cluster_metrics_warmup(app_with_ini)
            mock_ticker_class.assert_not_called()


def test_initialize_cluster_metrics_warmup_starts_ticker_when_enabled(app_with_ini):
    """When enabled and interval > 0, ThreadedTicker is started (3.1 scenario)."""
    def ini_get(sec, key, fallback=None):
        if key == "cluster_metrics_warm_enabled":
            return "true"
        if key == "cluster_metrics_warm_interval_sec":
            return "300"
        return fallback if fallback is not None else "300"
    app_with_ini.config["kubedash.ini"].get.side_effect = ini_get
    with patch("lib.initializers.cluster_metrics_warmup.os.environ", {}):
        with patch("lib.initializers.cluster_metrics_warmup.ThreadedTicker") as mock_ticker_class:
            mock_ticker = MagicMock()
            mock_ticker_class.return_value = mock_ticker
            initialize_cluster_metrics_warmup(app_with_ini)
            mock_ticker_class.assert_called_once()
            assert mock_ticker_class.call_args[1]["interval_sec"] == 300
            mock_ticker.start.assert_called_once()


def test_cluster_metrics_warmup_callback_calls_k8s_get_cluster_metric(app_with_ini):
    """Ticker callback runs inside app context and calls k8sGetClusterMetric (3.1)."""
    with patch("lib.k8s.metrics.k8sGetClusterMetric", MagicMock()) as mock_metric:
        _cluster_metrics_warmup_callback(app_with_ini)
        mock_metric.assert_called_once()
