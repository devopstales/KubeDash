"""
FluxCD Dependency Graph Module

Builds a graph data structure representing the relationships between
Flux objects for visualization with Cytoscape.js or similar libraries.
"""

from logging import getLogger
from typing import Dict, List, Any, Optional

logger = getLogger(__name__)

##############################################################
# Node/Edge Color Schemes
##############################################################

NODE_COLORS = {
    # Sources
    "GitRepository": "#6f42c1",      # Purple
    "HelmRepository": "#0d6efd",     # Blue
    "OCIRepository": "#20c997",      # Teal
    "Bucket": "#fd7e14",             # Orange
    "HelmChart": "#0dcaf0",          # Cyan
    # Reconcilers
    "Kustomization": "#198754",      # Green
    "HelmRelease": "#dc3545",        # Red
    # Notifications
    "Alert": "#ffc107",              # Yellow
    "Provider": "#6c757d",           # Gray
    "Receiver": "#d63384",           # Pink
}

NODE_SHAPES = {
    # Sources - rounded rectangles
    "GitRepository": "round-rectangle",
    "HelmRepository": "round-rectangle",
    "OCIRepository": "round-rectangle",
    "Bucket": "round-rectangle",
    "HelmChart": "round-rectangle",
    # Reconcilers - hexagons
    "Kustomization": "hexagon",
    "HelmRelease": "hexagon",
    # Notifications - diamonds
    "Alert": "diamond",
    "Provider": "diamond",
    "Receiver": "diamond",
}


##############################################################
# Build Graph Data Structure
##############################################################

def build_flux_graph(flux_objects: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
    """
    Build a graph data structure from Flux objects for Cytoscape.js.
    
    Args:
        flux_objects: Dictionary mapping object types to lists of objects
            Example: {
                "GitRepositories": [...],
                "Kustomizations": [...],
                "HelmReleases": [...],
                ...
            }
    
    Returns:
        Dictionary with 'nodes' and 'edges' for Cytoscape.js:
        {
            "nodes": [
                {"data": {"id": "...", "label": "...", "kind": "...", ...}},
                ...
            ],
            "edges": [
                {"data": {"id": "...", "source": "...", "target": "...", "label": "..."}},
                ...
            ]
        }
    """
    nodes = []
    edges = []
    node_ids = set()
    
    # Mapping from plural form to kind
    plural_to_kind = {
        "GitRepositories": "GitRepository",
        "HelmRepositories": "HelmRepository",
        "OCIRepositories": "OCIRepository",
        "Buckets": "Bucket",
        "HelmCharts": "HelmChart",
        "Kustomizations": "Kustomization",
        "HelmReleases": "HelmRelease",
        "Alerts": "Alert",
        "Providers": "Provider",
        "Receivers": "Receiver",
    }
    
    # First pass: create all nodes
    for plural_name, objects in flux_objects.items():
        if not objects:
            continue
            
        kind = plural_to_kind.get(plural_name, plural_name.rstrip('s'))
        
        for obj in objects:
            if not isinstance(obj, dict):
                continue
                
            metadata = obj.get("metadata", {})
            name = metadata.get("name", "unknown")
            namespace = metadata.get("namespace", "default")
            
            node_id = _make_node_id(kind, name, namespace)
            
            if node_id in node_ids:
                continue
            node_ids.add(node_id)
            
            # Determine status
            status_info = _get_status_info(obj)
            
            # Get revision info
            revision = _get_revision(obj, kind)
            
            # Extract additional info based on kind
            extra_info = _get_extra_info(obj, kind)
            
            node = {
                "data": {
                    "id": node_id,
                    "label": name,
                    "kind": kind,
                    "namespace": namespace,
                    "fullName": f"{kind}/{name}",
                    "status": status_info["status"],
                    "statusColor": status_info["color"],
                    "message": status_info["message"],
                    "revision": revision,
                    "suspended": obj.get("spec", {}).get("suspend", False),
                    "color": NODE_COLORS.get(kind, "#6c757d"),
                    "shape": NODE_SHAPES.get(kind, "ellipse"),
                    "url": extra_info.get("url", ""),
                    "interval": extra_info.get("interval", ""),
                    "chart": extra_info.get("chart", ""),
                    "path": extra_info.get("path", ""),
                    "branch": extra_info.get("branch", ""),
                    "lastTransitionTime": extra_info.get("lastTransitionTime", ""),
                }
            }
            nodes.append(node)
    
    # Second pass: create edges based on relationships
    for plural_name, objects in flux_objects.items():
        if not objects:
            continue
            
        kind = plural_to_kind.get(plural_name, plural_name.rstrip('s'))
        
        for obj in objects:
            if not isinstance(obj, dict):
                continue
                
            metadata = obj.get("metadata", {})
            name = metadata.get("name", "unknown")
            namespace = metadata.get("namespace", "default")
            spec = obj.get("spec", {})
            
            source_node_id = _make_node_id(kind, name, namespace)
            
            # Extract relationships based on kind
            if kind == "Kustomization":
                # Kustomization -> sourceRef
                source_ref = spec.get("sourceRef", {})
                if source_ref:
                    edge = _create_source_ref_edge(
                        source_node_id, source_ref, namespace, node_ids
                    )
                    if edge:
                        edges.append(edge)
                        
                # Kustomization -> dependsOn
                depends_on = spec.get("dependsOn", [])
                for dep in depends_on:
                    dep_name = dep.get("name")
                    dep_ns = dep.get("namespace", namespace)
                    if dep_name:
                        target_id = _make_node_id("Kustomization", dep_name, dep_ns)
                        if target_id in node_ids:
                            edge_id = f"{source_node_id}-dependsOn-{target_id}"
                            edges.append({
                                "data": {
                                    "id": edge_id,
                                    "source": source_node_id,
                                    "target": target_id,
                                    "label": "dependsOn",
                                    "lineStyle": "dashed",
                                }
                            })
            
            elif kind == "HelmRelease":
                # HelmRelease -> chart.spec.sourceRef
                chart = spec.get("chart", {})
                chart_spec = chart.get("spec", {})
                source_ref = chart_spec.get("sourceRef", {})
                if source_ref:
                    edge = _create_source_ref_edge(
                        source_node_id, source_ref, namespace, node_ids
                    )
                    if edge:
                        edges.append(edge)
                
                # HelmRelease -> dependsOn
                depends_on = spec.get("dependsOn", [])
                for dep in depends_on:
                    dep_name = dep.get("name")
                    dep_ns = dep.get("namespace", namespace)
                    if dep_name:
                        target_id = _make_node_id("HelmRelease", dep_name, dep_ns)
                        if target_id in node_ids:
                            edge_id = f"{source_node_id}-dependsOn-{target_id}"
                            edges.append({
                                "data": {
                                    "id": edge_id,
                                    "source": source_node_id,
                                    "target": target_id,
                                    "label": "dependsOn",
                                    "lineStyle": "dashed",
                                }
                            })
            
            elif kind == "Alert":
                # Alert -> providerRef
                provider_ref = spec.get("providerRef", {})
                if provider_ref:
                    provider_name = provider_ref.get("name")
                    if provider_name:
                        target_id = _make_node_id("Provider", provider_name, namespace)
                        if target_id in node_ids:
                            edge_id = f"{source_node_id}-providerRef-{target_id}"
                            edges.append({
                                "data": {
                                    "id": edge_id,
                                    "source": source_node_id,
                                    "target": target_id,
                                    "label": "providerRef",
                                }
                            })
                
                # Alert -> eventSources
                event_sources = spec.get("eventSources", [])
                for event_src in event_sources:
                    src_kind = event_src.get("kind")
                    src_name = event_src.get("name", "*")
                    src_ns = event_src.get("namespace", namespace)
                    if src_kind and src_name != "*":
                        target_id = _make_node_id(src_kind, src_name, src_ns)
                        if target_id in node_ids:
                            edge_id = f"{source_node_id}-watches-{target_id}"
                            edges.append({
                                "data": {
                                    "id": edge_id,
                                    "source": source_node_id,
                                    "target": target_id,
                                    "label": "watches",
                                    "lineStyle": "dotted",
                                }
                            })
            
            elif kind == "Receiver":
                # Receiver -> resources
                resources = spec.get("resources", [])
                for resource in resources:
                    res_kind = resource.get("kind")
                    res_name = resource.get("name", "*")
                    res_ns = resource.get("namespace", namespace)
                    if res_kind and res_name != "*":
                        target_id = _make_node_id(res_kind, res_name, res_ns)
                        if target_id in node_ids:
                            edge_id = f"{source_node_id}-triggers-{target_id}"
                            edges.append({
                                "data": {
                                    "id": edge_id,
                                    "source": source_node_id,
                                    "target": target_id,
                                    "label": "triggers",
                                }
                            })
    
    return {
        "nodes": nodes,
        "edges": edges,
    }


##############################################################
# Helper Functions
##############################################################

def _make_node_id(kind: str, name: str, namespace: str) -> str:
    """Create a unique node ID from kind, name, and namespace."""
    return f"{namespace}/{kind}/{name}"


def _get_status_info(obj: Dict[str, Any]) -> Dict[str, str]:
    """Extract status information from a Flux object."""
    status = obj.get("status", {})
    conditions = status.get("conditions", [])
    
    # Check if suspended
    if obj.get("spec", {}).get("suspend", False):
        return {
            "status": "Suspended",
            "color": "#6c757d",  # Gray
            "message": "Object is suspended",
        }
    
    # Find Ready condition
    for cond in conditions:
        if cond.get("type") == "Ready":
            is_ready = cond.get("status") == "True"
            message = cond.get("message", "")
            reason = cond.get("reason", "")
            
            if is_ready:
                return {
                    "status": "Ready",
                    "color": "#198754",  # Green
                    "message": message or reason,
                }
            else:
                # Check for specific failure reasons
                if "Progressing" in reason:
                    return {
                        "status": "Progressing",
                        "color": "#0dcaf0",  # Cyan
                        "message": message or reason,
                    }
                return {
                    "status": "Not Ready",
                    "color": "#dc3545",  # Red
                    "message": message or reason,
                }
    
    return {
        "status": "Unknown",
        "color": "#ffc107",  # Yellow
        "message": "No status conditions found",
    }


def _get_extra_info(obj: Dict[str, Any], kind: str) -> Dict[str, str]:
    """Extract additional useful information from a Flux object based on its kind."""
    spec = obj.get("spec", {})
    status = obj.get("status", {})
    info = {}
    
    # Common: interval
    interval = spec.get("interval", "")
    if interval:
        info["interval"] = interval
    
    # Last transition time from Ready condition
    conditions = status.get("conditions", [])
    for cond in conditions:
        if cond.get("type") == "Ready":
            info["lastTransitionTime"] = cond.get("lastTransitionTime", "")
            break
    
    # Kind-specific info
    if kind == "GitRepository":
        info["url"] = spec.get("url", "")
        ref = spec.get("ref", {})
        info["branch"] = ref.get("branch", ref.get("tag", ref.get("commit", "")))
        
    elif kind == "HelmRepository":
        info["url"] = spec.get("url", "")
        
    elif kind == "OCIRepository":
        info["url"] = spec.get("url", "")
        ref = spec.get("ref", {})
        info["branch"] = ref.get("tag", ref.get("digest", ""))
        
    elif kind == "Bucket":
        info["url"] = f"{spec.get('provider', '')}/{spec.get('bucketName', '')}"
        info["path"] = spec.get("prefix", "")
        
    elif kind == "Kustomization":
        info["path"] = spec.get("path", "./")
        source_ref = spec.get("sourceRef", {})
        if source_ref:
            info["url"] = f"{source_ref.get('kind', '')}/{source_ref.get('name', '')}"
            
    elif kind == "HelmRelease":
        chart = spec.get("chart", {}).get("spec", {})
        info["chart"] = chart.get("chart", "")
        info["path"] = chart.get("version", "")  # Use path field for version
        source_ref = chart.get("sourceRef", {})
        if source_ref:
            info["url"] = f"{source_ref.get('kind', '')}/{source_ref.get('name', '')}"
            
    elif kind == "Alert":
        info["url"] = f"Events: {len(spec.get('eventSources', []))} sources"
        
    elif kind == "Provider":
        info["url"] = spec.get("type", "")
        
    elif kind == "Receiver":
        info["url"] = spec.get("type", "")
        info["path"] = f"{len(spec.get('resources', []))} resources"
    
    return info


def _get_revision(obj: Dict[str, Any], kind: str) -> str:
    """Extract revision information from a Flux object."""
    status = obj.get("status", {})
    
    # For sources: status.artifact.revision
    if kind in ["GitRepository", "HelmRepository", "OCIRepository", "Bucket", "HelmChart"]:
        artifact = status.get("artifact", {})
        revision = artifact.get("revision", "")
        if revision:
            return revision
    
    # For Kustomization/HelmRelease: status.lastAppliedRevision
    if kind in ["Kustomization", "HelmRelease"]:
        revision = status.get("lastAppliedRevision", "")
        if revision:
            return revision
        # Also check lastAttemptedRevision
        revision = status.get("lastAttemptedRevision", "")
        if revision:
            return revision
    
    return ""


def _create_source_ref_edge(
    source_node_id: str,
    source_ref: Dict[str, Any],
    default_namespace: str,
    node_ids: set
) -> Optional[Dict[str, Any]]:
    """Create an edge for a sourceRef relationship."""
    ref_kind = source_ref.get("kind")
    ref_name = source_ref.get("name")
    ref_namespace = source_ref.get("namespace", default_namespace)
    
    if not ref_kind or not ref_name:
        return None
    
    target_id = _make_node_id(ref_kind, ref_name, ref_namespace)
    
    # Only create edge if target node exists
    if target_id not in node_ids:
        return None
    
    edge_id = f"{source_node_id}-sourceRef-{target_id}"
    
    return {
        "data": {
            "id": edge_id,
            "source": source_node_id,
            "target": target_id,
            "label": "sourceRef",
        }
    }


##############################################################
# Graph Statistics
##############################################################

def get_graph_stats(graph_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Calculate statistics for the graph.
    
    Args:
        graph_data: The graph data from build_flux_graph()
        
    Returns:
        Dictionary with graph statistics
    """
    nodes = graph_data.get("nodes", [])
    edges = graph_data.get("edges", [])
    
    # Count by kind
    kind_counts = {}
    status_counts = {"Ready": 0, "Not Ready": 0, "Suspended": 0, "Unknown": 0, "Progressing": 0}
    
    for node in nodes:
        data = node.get("data", {})
        kind = data.get("kind", "Unknown")
        status = data.get("status", "Unknown")
        
        kind_counts[kind] = kind_counts.get(kind, 0) + 1
        
        if status in status_counts:
            status_counts[status] += 1
        else:
            status_counts["Unknown"] += 1
    
    return {
        "total_nodes": len(nodes),
        "total_edges": len(edges),
        "by_kind": kind_counts,
        "by_status": status_counts,
    }
