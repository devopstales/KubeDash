"""Kubeconfig renderer — per .skillgrid/ARCHITECTURE.md §5B "Self-service
kubeconfig" and ADR-0011.

Pure YAML emitter: builds the §5B dict and dumps it with ``yaml.safe_dump``
(``sort_keys=False`` — key order is stable and readable: clusters, contexts,
users, current-context). The load-bearing property (ADR-0011): EXACTLY ONE
shared ``users[]`` entry carrying an ``exec`` reference to the kubectl
credential plugin (``kubectl kubedash get-token --server=<plugin_server>``)
— NO ``token`` / ``tokenFile`` / ``oidc-*`` keys anywhere, the token is
always fresh (PKCE + keyring, ADR-0011). No Flask imports (services purity).
"""
import yaml

#: The shared user name every generated context points at.
KUBEDASH_USER = "kubedash"


def render_kubeconfig(
    clusters: list[dict[str, str]],
    contexts: list[dict[str, str]],
    plugin_server: str,
) -> str:
    """Render the §5B self-service kubeconfig.

    ``clusters``: one ``{"name", "server", "ca_data_b64"}`` per DISTINCT
    cluster (``ca_data_b64`` may be ``""`` — the CA field is then omitted).
    ``contexts``: one ``{"name", "namespace"}`` PER BINDING (a user bound to
    the same cluster in two namespaces gets two contexts; ``namespace``
    ``""`` = cluster scope → the ``namespace`` key is omitted).
    ``plugin_server``: the credential plugin's ``--server`` value (the caller
    guarantees it is non-empty — ``permission.generate_kubeconfig`` raises
    ``InternalError`` when ``KUBEDASH_PLUGIN_SERVER`` is unset).
    """
    cluster_entries: list[dict[str, object]] = []
    for c in clusters:
        cluster: dict[str, object] = {"server": c["server"]}
        # §5B: the CA is inlined base64; absent registry CA → key omitted.
        if c["ca_data_b64"]:
            cluster["certificate-authority-data"] = c["ca_data_b64"]
        cluster_entries.append({"name": c["name"], "cluster": cluster})

    context_entries: list[dict[str, object]] = []
    for ctx in contexts:
        context: dict[str, object] = {"cluster": ctx["name"], "user": KUBEDASH_USER}
        # Cluster-scoped bindings omit the key entirely (not "").
        if ctx["namespace"]:
            context["namespace"] = ctx["namespace"]
        context_entries.append({"name": ctx["name"], "context": context})

    doc: dict[str, object] = {
        "apiVersion": "v1",
        "kind": "Config",
        "clusters": cluster_entries,
        "contexts": context_entries,
        # ADR-0011: the ONE shared exec user — the plugin reads the cluster
        # from the active context's cluster.server (auto-detect), so no
        # --cluster-name; the token is minted fresh per exec, never embedded.
        "users": [
            {
                "name": KUBEDASH_USER,
                "user": {
                    "exec": {
                        "apiVersion": "client.authentication.k8s.io/v1",
                        "command": "kubectl",
                        "args": [
                            "kubedash",
                            "get-token",
                            f"--server={plugin_server}",
                        ],
                    }
                },
            }
        ],
        # §5B: current-context = the FIRST context name.
        "current-context": contexts[0]["name"],
    }
    # ponytail: safe_dump of an ordered dict with sort_keys=False is the
    # whole "renderer" — no template, no line splicing, valid YAML by
    # construction (the tests parse it back with safe_load).
    return yaml.safe_dump(doc, sort_keys=False)
