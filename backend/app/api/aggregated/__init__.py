"""Aggregated API server — per .skillgrid/artifacts/04-adr-0012-aggregated-api.md
(ADR-0012): second Flask app on port 8443, mTLS, read-only. The serving
app + APIService registration land with the aggregation change; the route
modules here (projects.py, sso_users.py, sso_groups.py) are stubs."""
