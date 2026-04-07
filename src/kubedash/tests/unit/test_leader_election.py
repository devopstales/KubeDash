import os
from lib.leader_election import LeaderElector


def test_leader_elector_detects_pod_identity_from_env(monkeypatch, app):
    monkeypatch.setenv('POD_NAME', 'pod-1')
    monkeypatch.setenv('POD_NAMESPACE', 'kube-system')
    elector = LeaderElector(app)

    assert elector.identity == 'pod-1'
    assert elector.namespace == 'kube-system'


def test_leader_elector_builds_lease_body(monkeypatch, app):
    monkeypatch.setenv('POD_NAME', 'pod-lease')
    monkeypatch.setenv('POD_NAMESPACE', 'default')
    elector = LeaderElector(app)
    lease = elector._build_lease_body()

    assert lease.metadata.name == elector.lease_name
    assert lease.metadata.namespace == elector.namespace
    assert lease.spec.holder_identity == elector.identity
