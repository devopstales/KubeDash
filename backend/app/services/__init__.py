"""Service layer — domain logic between the API layer and the adapters.

``k8s_client`` is the single seam that turns a stored ``Cluster`` row into a
live Kubernetes client (ADR-0010's informer cache will interpose HERE later,
without touching the APIs).
"""
