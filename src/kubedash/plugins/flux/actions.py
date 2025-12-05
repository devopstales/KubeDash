from datetime import datetime
from logging import getLogger

import kubernetes.client as k8s_client

from lib.k8s.server import k8sClientConfigGet
from lib.helper_functions import ErrorHandler, MessageHandler, WarningHandler

##############################################################
# Variables
##############################################################

logger = getLogger(__name__)

##############################################################
# ForceReconciliationAction ???
##############################################################
"""
patch https://github.com/headlamp-k8s/plugins/blob/main/flux/src/actions/index.tsx#L34

kubectl annotate helmrelease -n kyverno-system kyverno reconcile.fluxcd.io/requestedAt="$(date +%s)"
"""
##############################################################
# SuspendAction
##############################################################
"""
patch: https://github.com/headlamp-k8s/plugins/blob/main/flux/src/actions/index.tsx#L92

kubectl annotate helmrelease -n kyverno-system kyverno reconcile.fluxcd.io/requestedAt="$(date +%s)"

kubectl get helmrelease kyverno -n kyverno-system -o jsonpath='{.spec.suspend}'
# Should return "true"

kubectl patch helmrelease kyverno -n kyverno-system --type merge -p '{"spec":{"suspend":false}}'
"""

def SuspendAction(obj, username_role, user_token):
    """
    """
    k8sClientConfigGet(username_role, user_token)
    crd_api = k8s_client.CustomObjectsApi()

    kind = obj.get("kind")
    api_version = obj.get("apiVersion")
    metadata = obj.get("metadata", {})
    namespace = metadata.get("namespace")
    name = metadata.get("name")
    spec = obj.get("spec")
 
    # Accepted kinds and their apiVersions (all objects that support spec.suspend)
    VALID_OBJECTS = {
        "Kustomization": {
            "api_version": "kustomize.toolkit.fluxcd.io/v1",
            "group": "kustomize.toolkit.fluxcd.io",
            "version": "v1",
            "plural": "kustomizations"
        },
        "HelmRelease": {
            "api_version": "helm.toolkit.fluxcd.io/v2",
            "group": "helm.toolkit.fluxcd.io",
            "version": "v2",
            "plural": "helmreleases"
        },
        "GitRepository": {
            "api_version": "source.toolkit.fluxcd.io/v1",
            "group": "source.toolkit.fluxcd.io",
            "version": "v1",
            "plural": "gitrepositories"
        },
        "HelmRepository": {
            "api_version": "source.toolkit.fluxcd.io/v1",
            "group": "source.toolkit.fluxcd.io",
            "version": "v1",
            "plural": "helmrepositories"
        },
        "OCIRepository": {
            "api_version": "source.toolkit.fluxcd.io/v1beta2",
            "group": "source.toolkit.fluxcd.io",
            "version": "v1beta2",
            "plural": "ocirepositories"
        },
        "Bucket": {
            "api_version": "source.toolkit.fluxcd.io/v1",
            "group": "source.toolkit.fluxcd.io",
            "version": "v1",
            "plural": "buckets"
        },
        "HelmChart": {
            "api_version": "source.toolkit.fluxcd.io/v1",
            "group": "source.toolkit.fluxcd.io",
            "version": "v1",
            "plural": "helmcharts"
        },
        "Alert": {
            "api_version": "notification.toolkit.fluxcd.io/v1beta3",
            "group": "notification.toolkit.fluxcd.io",
            "version": "v1beta3",
            "plural": "alerts"
        },
        "Receiver": {
            "api_version": "notification.toolkit.fluxcd.io/v1",
            "group": "notification.toolkit.fluxcd.io",
            "version": "v1",
            "plural": "receivers"
        }
    }

    if not all([kind, api_version, namespace, name, spec]):
        msg = "Missing required fields in object: kind, apiVersion, metadata.name, metadata.namespace, or spec"
        logger.warning(msg)
        return True, msg, False

    if kind not in VALID_OBJECTS:
        msg = f"Unsupported kind: {kind}"
        logger.warning(msg)
        return True, msg, False

    expected_api_version = VALID_OBJECTS[kind]["api_version"]
    if api_version != expected_api_version:
        msg = f"Invalid apiVersion for {kind}: expected {expected_api_version}, got {api_version}"
        logger.warning(msg)
        return True, msg, False

    if spec.get("suspend") is True:
        msg = f"{kind} '{name}' is already suspended."
        logger.info(msg)
        return False, msg, False

    patch_body = {"spec": {"suspend": True}}
    crd_def = VALID_OBJECTS[kind]

    try:
        crd_api.patch_namespaced_custom_object(
            group=crd_def["group"],
            version=crd_def["version"],
            namespace=namespace,
            plural=crd_def["plural"],
            name=name,
            body=patch_body
        )
        msg = f"{kind} '{name}' suspended successfully in namespace '{namespace}'."
        logger.info(msg)
        return False, msg, True
    except Exception as e:
        msg = f"Failed to patch {kind} '{name}' in namespace '{namespace}': {e}"
        logger.error(msg)
        return True, msg, False

##############################################################
# ResumeAction
##############################################################
def ResumeAction(obj, username_role, user_token):
    """
    patch: https://github.com/headlamp-k8s/plugins/blob/main/flux/src/actions/index.tsx#L139
    """
    k8sClientConfigGet(username_role, user_token)
    crd_api = k8s_client.CustomObjectsApi()
    
    kind = obj.get("kind")
    api_version = obj.get("apiVersion")
    metadata = obj.get("metadata", {})
    namespace = metadata.get("namespace")
    name = metadata.get("name")
    spec = obj.get("spec")

    # All objects that support spec.suspend
    VALID_OBJECTS = {
        "Kustomization": {
            "api_version": "kustomize.toolkit.fluxcd.io/v1",
            "group": "kustomize.toolkit.fluxcd.io",
            "version": "v1",
            "plural": "kustomizations"
        },
        "HelmRelease": {
            "api_version": "helm.toolkit.fluxcd.io/v2",
            "group": "helm.toolkit.fluxcd.io",
            "version": "v2",
            "plural": "helmreleases"
        },
        "GitRepository": {
            "api_version": "source.toolkit.fluxcd.io/v1",
            "group": "source.toolkit.fluxcd.io",
            "version": "v1",
            "plural": "gitrepositories"
        },
        "HelmRepository": {
            "api_version": "source.toolkit.fluxcd.io/v1",
            "group": "source.toolkit.fluxcd.io",
            "version": "v1",
            "plural": "helmrepositories"
        },
        "OCIRepository": {
            "api_version": "source.toolkit.fluxcd.io/v1beta2",
            "group": "source.toolkit.fluxcd.io",
            "version": "v1beta2",
            "plural": "ocirepositories"
        },
        "Bucket": {
            "api_version": "source.toolkit.fluxcd.io/v1",
            "group": "source.toolkit.fluxcd.io",
            "version": "v1",
            "plural": "buckets"
        },
        "HelmChart": {
            "api_version": "source.toolkit.fluxcd.io/v1",
            "group": "source.toolkit.fluxcd.io",
            "version": "v1",
            "plural": "helmcharts"
        },
        "Alert": {
            "api_version": "notification.toolkit.fluxcd.io/v1beta3",
            "group": "notification.toolkit.fluxcd.io",
            "version": "v1beta3",
            "plural": "alerts"
        },
        "Receiver": {
            "api_version": "notification.toolkit.fluxcd.io/v1",
            "group": "notification.toolkit.fluxcd.io",
            "version": "v1",
            "plural": "receivers"
        }
    }
    
    if not all([kind, api_version, namespace, name, spec]):
        msg = "Missing required fields in object: kind, apiVersion, metadata.name, metadata.namespace, or spec"
        logger.warning(msg)
        return True, msg, False

    if kind not in VALID_OBJECTS:
        msg = f"Unsupported kind: {kind}"
        logger.warning(msg)
        return True, msg, False

    expected_api_version = VALID_OBJECTS[kind]["api_version"]
    if api_version != expected_api_version:
        msg = f"Invalid apiVersion for {kind}: expected {expected_api_version}, got {api_version}"
        logger.warning(msg)
        return True, msg, False

    if spec.get("suspend") is False:
        msg = f"{kind} '{name}' is already resumed (not suspended)."
        logger.info(msg)
        return False, msg, False

    patch_body = {"spec": {"suspend": False}}
    crd_def = VALID_OBJECTS[kind]

    try:
        crd_api.patch_namespaced_custom_object(
            group=crd_def["group"],
            version=crd_def["version"],
            namespace=namespace,
            plural=crd_def["plural"],
            name=name,
            body=patch_body
        )
        msg = f"{kind} '{name}' resumed successfully in namespace '{namespace}'."
        logger.info(msg)
        return False, msg, True
    except Exception as e:
        msg = f"Failed to patch {kind} '{name}' in namespace '{namespace}': {e}"
        logger.error(msg)
        return True, msg, False

##############################################################
# SyncAction
##############################################################
def SyncAction(obj, username_role, user_token):
    """
    patch: https://github.com/headlamp-k8s/plugins/blob/main/flux/src/actions/index.tsx#L176
    """
    k8sClientConfigGet(username_role, user_token)
    crd_api = k8s_client.CustomObjectsApi()
    
    kind = obj.get("kind")
    api_version = obj.get("apiVersion")
    metadata = obj.get("metadata", {})
    namespace = metadata.get("namespace")
    name = metadata.get("name")
    
    # All reconcilable Flux objects
    VALID_OBJECTS = {
        "Bucket": {
            "api_version": "source.toolkit.fluxcd.io/v1",
            "group": "source.toolkit.fluxcd.io",
            "version": "v1",
            "plural": "buckets"
        },
        "GitRepository": {
            "api_version": "source.toolkit.fluxcd.io/v1",
            "group": "source.toolkit.fluxcd.io",
            "version": "v1",
            "plural": "gitrepositories"
        },
        "OCIRepository": {
            "api_version": "source.toolkit.fluxcd.io/v1beta2",
            "group": "source.toolkit.fluxcd.io",
            "version": "v1beta2",
            "plural": "ocirepositories"
        },
        "HelmRepository": {
            "api_version": "source.toolkit.fluxcd.io/v1",
            "group": "source.toolkit.fluxcd.io",
            "version": "v1",
            "plural": "helmrepositories"
        },
        "HelmChart": {
            "api_version": "source.toolkit.fluxcd.io/v1",
            "group": "source.toolkit.fluxcd.io",
            "version": "v1",
            "plural": "helmcharts"
        },
        "Kustomization": {
            "api_version": "kustomize.toolkit.fluxcd.io/v1",
            "group": "kustomize.toolkit.fluxcd.io",
            "version": "v1",
            "plural": "kustomizations"
        },
        "HelmRelease": {
            "api_version": "helm.toolkit.fluxcd.io/v2",
            "group": "helm.toolkit.fluxcd.io",
            "version": "v2",
            "plural": "helmreleases"
        }
    }

    if not all([kind, api_version, namespace, name]):
        msg = "Missing required fields in object: kind, apiVersion, metadata.name, metadata.namespace"
        WarningHandler(logger, msg, "SyncAction")

    if kind not in VALID_OBJECTS:
        msg = f"Unsupported kind: {kind}"
        WarningHandler(logger, msg, "SyncAction")

    expected_api_version = VALID_OBJECTS[kind]["api_version"]
    if api_version != expected_api_version:
        msg = f"Invalid apiVersion for {kind}: expected {expected_api_version}, got {api_version}"
        WarningHandler(logger, msg, "SyncAction")

    # Create ISO8601 datetime string
    now_iso = datetime.utcnow().replace(microsecond=0).isoformat() + 'Z'

    patch_body = {
        "metadata": {
            "annotations": {
                "reconcile.fluxcd.io/requestedAt": now_iso
            }
        }
    }

    crd_def = VALID_OBJECTS[kind]

    try:
        crd_api.patch_namespaced_custom_object(
            group=crd_def["group"],
            version=crd_def["version"],
            namespace=namespace,
            plural=crd_def["plural"],
            name=name,
            body=patch_body
        )
        msg = f"{kind} '{name}' sync requested at {now_iso}"
        MessageHandler(logger, msg, "SyncAction")
    except Exception as error:
        msg = f"Failed to patch {kind} '{name}' in namespace '{namespace}': {error}"
        ErrorHandler(logger, error, "get %s" % msg)
