#!/usr/bin/env python3
"""Leader election support for KubeDash using Kubernetes Leases API."""

import os
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional

from flask import Flask
from kubernetes import client, config
from kubernetes.client.rest import ApiException

from lib.prometheus import (
    METRIC_LEADER_IS_LEADER,
    METRIC_LEADER_TRANSITIONS,
    METRIC_LEADER_RENEWALS,
)


DEFAULT_LEASE_NAME = 'kubedash-leader-election'


class LeaderElector:
    def __init__(
        self,
        app: Flask,
        on_started_leading: Optional[Callable[[], None]] = None,
        on_stopped_leading: Optional[Callable[[], None]] = None,
    ):
        self.app = app
        self.identity = self._get_identity()
        self.namespace = self._get_namespace()
        self.lease_name = app.config.get('LEADER_ELECTION_LEASE_NAME', DEFAULT_LEASE_NAME)
        self.lease_duration = int(app.config.get('LEADER_ELECTION_LEASE_DURATION', 30))
        self.renew_deadline = int(app.config.get('LEADER_ELECTION_RENEW_DEADLINE', 20))
        self.retry_period = int(app.config.get('LEADER_ELECTION_RETRY_PERIOD', 5))
        self.on_started_leading = on_started_leading
        self.on_stopped_leading = on_stopped_leading
        self.is_leader = False
        self.leader_holder_name = None  # Track current leader's identity
        self._stop_event = threading.Event()
        self._thread = threading.Thread(target=self.run, daemon=True)
        self._coordination_api = None

    def _get_identity(self) -> str:
        return (
            os.environ.get('POD_NAME')
            or self.app.config.get('POD_NAME')
            or os.environ.get('HOSTNAME')
            or os.uname().nodename
        )

    def _get_namespace(self) -> str:
        return (
            os.environ.get('POD_NAMESPACE')
            or self.app.config.get('POD_NAMESPACE')
            or 'default'
        )

    def _now(self) -> datetime:
        return datetime.now(timezone.utc)

    def _load_kube_config(self) -> None:
        if self._coordination_api is not None:
            return
        try:
            config.load_incluster_config()
            self.app.logger.info('Using in-cluster Kubernetes configuration for leader election')
        except Exception:
            try:
                config.load_kube_config()
                self.app.logger.info('Using local kubeconfig for leader election')
            except Exception as exc:
                self.app.logger.warning(
                    'Could not load Kubernetes configuration for leader election: %s',
                    exc,
                )
                self._coordination_api = None
                return
        self._coordination_api = client.CoordinationV1Api()

    def _build_lease_body(self) -> client.V1Lease:
        now = self._now()
        metadata = client.V1ObjectMeta(name=self.lease_name, namespace=self.namespace)
        spec = client.V1LeaseSpec(
            holder_identity=self.identity,
            lease_duration_seconds=self.lease_duration,
            renew_time=now,
            acquire_time=now,
            lease_transitions=0,
        )
        return client.V1Lease(metadata=metadata, spec=spec)

    def _lease_expired(self, lease: client.V1Lease) -> bool:
        if lease is None or lease.spec is None or lease.spec.renew_time is None:
            return True
        renew_time = lease.spec.renew_time
        if isinstance(renew_time, str):
            renew_time = datetime.fromisoformat(renew_time.replace('Z', '+00:00'))
        expiration = renew_time + timedelta(seconds=self.lease_duration)
        return expiration <= self._now()

    def _get_api(self) -> Optional[client.CoordinationV1Api]:
        self._load_kube_config()
        return self._coordination_api

    def _create_lease(self) -> bool:
        api = self._get_api()
        if api is None:
            return False

        body = self._build_lease_body()
        try:
            api.create_namespaced_lease(namespace=self.namespace, body=body)
            self.app.logger.info('Created new leader lease %s', self.lease_name)
            return True
        except ApiException as exc:
            if exc.status == 409:
                # Lease already exists - another replica created it first
                # This is expected in multi-replica scenarios
                self.app.logger.debug('Lease already exists, another replica created it first')
                return False
            self.app.logger.warning('Lease creation failed: %s', exc)
            return False
        except Exception as exc:
            self.app.logger.warning('Unexpected lease creation failure: %s', exc)
            return False

    def _renew_lease(self, lease: client.V1Lease) -> bool:
        api = self._get_api()
        if api is None:
            return False

        # Retry loop for handling 409 conflicts
        max_retries = 3
        for attempt in range(max_retries):
            try:
                # Always fetch the latest lease to get current resourceVersion
                latest_lease = api.read_namespaced_lease(name=self.lease_name, namespace=self.namespace)
                
                # Update the latest lease with our identity
                latest_lease.spec.renew_time = self._now()
                
                api.replace_namespaced_lease(name=self.lease_name, namespace=self.namespace, body=latest_lease)
                self.app.logger.debug('Renewed leader lease %s', self.lease_name)
                return True
            except ApiException as exc:
                if exc.status == 409 and attempt < max_retries - 1:
                    self.app.logger.debug('Lease renewal conflict (attempt %d/%d), retrying...', attempt + 1, max_retries)
                    time.sleep(0.5 * (2 ** attempt))  # Exponential backoff: 0.5s, 1s, 2s
                    continue
                self.app.logger.warning('Could not renew lease: %s', exc)
                return False
            except Exception as exc:
                self.app.logger.warning('Could not renew lease: %s', exc)
                return False
        
        return False

    def _try_takeover(self, lease: client.V1Lease) -> bool:
        api = self._get_api()
        if api is None:
            return False

        # Retry loop for handling 409 conflicts
        max_retries = 3
        for attempt in range(max_retries):
            try:
                # Always fetch the latest lease to get current resourceVersion
                latest_lease = api.read_namespaced_lease(name=self.lease_name, namespace=self.namespace)
                
                # Check if lease is still expired (another replica might have taken it)
                if not self._lease_expired(latest_lease):
                    self.app.logger.debug('Lease no longer expired, another replica may have taken it')
                    return False
                
                # Update the latest lease with our identity
                latest_lease.spec.holder_identity = self.identity
                latest_lease.spec.renew_time = self._now()
                latest_lease.spec.lease_transitions = (latest_lease.spec.lease_transitions or 0) + 1
                
                api.replace_namespaced_lease(name=self.lease_name, namespace=self.namespace, body=latest_lease)
                self.app.logger.info('Took over expired leader lease %s', self.lease_name)
                return True
            except ApiException as exc:
                if exc.status == 409 and attempt < max_retries - 1:
                    self.app.logger.debug('Lease takeover conflict (attempt %d/%d), retrying...', attempt + 1, max_retries)
                    time.sleep(0.5 * (2 ** attempt))  # Exponential backoff: 0.5s, 1s, 2s
                    continue
                self.app.logger.warning('Could not replace expired lease: %s', exc)
                return False
            except Exception as exc:
                self.app.logger.warning('Could not replace expired lease: %s', exc)
                return False
        
        return False

    def try_acquire(self) -> bool:
        api = self._get_api()
        if api is None:
            return False

        try:
            lease = api.read_namespaced_lease(name=self.lease_name, namespace=self.namespace)
        except ApiException as exc:
            if exc.status == 404:
                return self._create_lease()
            self.app.logger.warning('Lease read failed: %s', exc)
            return False
        except Exception as exc:
            self.app.logger.warning('Unexpected lease read failure: %s', exc)
            return False

        # Track the current leader holder name for status reporting
        if lease.spec.holder_identity:
            self.leader_holder_name = lease.spec.holder_identity

        if lease.spec.holder_identity == self.identity:
            return self._renew_lease(lease)

        if self._lease_expired(lease):
            return self._try_takeover(lease)

        return False

    def run(self) -> None:
        self.app.logger.info('Leader elector background loop starting')
        while not self._stop_event.is_set():
            acquired = self.try_acquire()
            if acquired and not self.is_leader:
                self.is_leader = True
                METRIC_LEADER_IS_LEADER.labels(pod_name=self.identity).set(1)
                METRIC_LEADER_TRANSITIONS.labels(pod_name=self.identity).inc()
                self.app.logger.info('Became leader: %s', self.identity)
                if self.on_started_leading:
                    self.on_started_leading()
            elif acquired and self.is_leader:
                # Successful renewal
                METRIC_LEADER_RENEWALS.labels(pod_name=self.identity).inc()
            elif not acquired and self.is_leader:
                self.is_leader = False
                METRIC_LEADER_IS_LEADER.labels(pod_name=self.identity).set(0)
                METRIC_LEADER_TRANSITIONS.labels(pod_name=self.identity).inc()
                self.app.logger.info('Lost leadership: %s', self.identity)
                if self.on_stopped_leading:
                    self.on_stopped_leading()
            time.sleep(self.retry_period)
        self.app.logger.info('Leader elector background loop stopped')

    def start(self) -> None:
        if not self._thread.is_alive():
            self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread.is_alive():
            self._thread.join(timeout=self.retry_period + 1)
        if self.is_leader:
            self.release_leadership()

    def release_leadership(self) -> bool:
        api = self._get_api()
        if api is None:
            return False

        # Retry loop for handling 409 conflicts
        max_retries = 3
        for attempt in range(max_retries):
            try:
                lease = api.read_namespaced_lease(name=self.lease_name, namespace=self.namespace)
                if lease.spec.holder_identity != self.identity:
                    self.app.logger.debug('Not the current leader, nothing to release')
                    return False
                
                lease.spec.holder_identity = ''
                lease.spec.renew_time = self._now()
                
                api.replace_namespaced_lease(name=self.lease_name, namespace=self.namespace, body=lease)
                self.app.logger.info('Released leadership for %s', self.identity)
                self.is_leader = False
                return True
            except ApiException as exc:
                if exc.status == 409 and attempt < max_retries - 1:
                    self.app.logger.debug('Lease release conflict (attempt %d/%d), retrying...', attempt + 1, max_retries)
                    time.sleep(0.5 * (2 ** attempt))  # Exponential backoff: 0.5s, 1s, 2s
                    continue
                self.app.logger.warning('Could not release leadership: %s', exc)
                return False
            except Exception as exc:
                self.app.logger.warning('Could not release leadership: %s', exc)
                return False
        
        return False

    def get_status(self) -> dict:
        """Get current leader election status."""
        try:
            api = self._get_api()
            if not api:
                return {
                    'enabled': False,
                    'error': 'Kubernetes API not available'
                }
            
            lease = api.read_namespaced_lease(name=self.lease_name, namespace=self.namespace)
            
            return {
                'enabled': True,
                'is_leader': self.is_leader,
                'identity': self.identity,
                'current_leader': lease.spec.holder_identity if lease.spec else None,
                'lease_duration_seconds': lease.spec.lease_duration_seconds if lease.spec else None,
                'renew_time': lease.spec.renew_time.isoformat() if lease.spec and lease.spec.renew_time else None,
                'acquire_time': lease.spec.acquire_time.isoformat() if lease.spec and lease.spec.acquire_time else None,
                'transitions': lease.spec.leader_transitions if lease.spec else 0
            }
        except Exception as e:
            return {
                'enabled': True,
                'error': f'Failed to get lease status: {e}'
            }

    def get_current_leader(self) -> Optional[str]:
        """Get the current leader identity."""
        try:
            api = self._get_api()
            if not api:
                return None
            
            lease = api.read_namespaced_lease(name=self.lease_name, namespace=self.namespace)
            return lease.spec.holder_identity if lease.spec else None
        except Exception:
            return None


def initialize_leader_election(app: Flask) -> Optional[LeaderElector]:
    """Initialize leader election for cluster replica mode."""
    env_enabled = os.environ.get('LEADER_ELECTION_ENABLED')
    if env_enabled is not None:
        enabled = env_enabled
    else:
        enabled = app.config.get('LEADER_ELECTION_ENABLED')
        if enabled is False:
            enabled = app.config.get('REPLICA_MODE') == 'cluster'
    enabled = str(enabled).strip().lower() in ('true', '1', 'yes')

    if not enabled:
        app.logger.info('Leader election disabled')
        return None

    elector = LeaderElector(app)
    app.extensions['leader_elector'] = elector
    elector.start()
    app.logger.info('Leader election initialized and background thread started')
    return elector


def get_leader_elector() -> Optional[LeaderElector]:
    """Get the current leader elector instance from Flask app context."""
    from flask import current_app
    return current_app.extensions.get('leader_elector')
