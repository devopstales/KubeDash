from flask import flash

from kubernetes import client as k8s_client
from kubernetes.client.rest import ApiException
from kubernetes import watch
from kubernetes.stream import stream

from lib.components import socketio

from lib.helper_functions import ErrorHandler, NoFlashErrorHandler, trimAnnotations

from. import logger
from .server import k8sClientConfigGet

##############################################################
## DaemonSets
##############################################################

def k8sDaemonSetsGet(username_role, user_token, ns):
    k8sClientConfigGet(username_role, user_token)
    DAEMONSET_LIST = list()
    try:
        daemonset_list = k8s_client.AppsV1Api().list_namespaced_daemon_set(ns, _request_timeout=5)
        for ds in daemonset_list.items:
            DAEMONSET_DATA = {
                "name": ds.metadata.name,
                "namespace": ns,
                # labels
                "annotations": list(),
                "labels": list(),
                "selectors": list(),
                # status
                "desired": "",
                "current": "",
                "ready": "",
                # Environment variables
                "environment_variables": [],
                # Security
                "security_context": ds.spec.template.spec.security_context.to_dict(),
                # Containers
                "containers": list(),
                "init_containers": list(),
                #  Related Resources
                "image_pull_secrets": list(),
                "service_account": list(),
                "pvc": list(),
                "cm": list(),
                "secrets": list(),
                "created": None,
            }
            DAEMONSET_DATA['created'] = ds.metadata.creation_timestamp.strftime('%Y-%m-%d %H:%M:%S')
            if ds.metadata.labels:
                DAEMONSET_DATA['labels'] = ds.metadata.labels
            if ds.metadata.annotations:
                DAEMONSET_DATA['annotations'] = trimAnnotations(ds.metadata.annotations)
            selectors = ds.spec.selector.to_dict()
            DAEMONSET_DATA['selectors'] = selectors['match_labels']
            if ds.status.desired_number_scheduled:
                DAEMONSET_DATA['desired'] = ds.status.desired_number_scheduled
            else:
                DAEMONSET_DATA['desired'] = 0
            if ds.status.current_number_scheduled:
                DAEMONSET_DATA['current'] = ds.status.current_number_scheduled
            else:
                DAEMONSET_DATA['current'] = 0
            if ds.status.number_ready:
                DAEMONSET_DATA['ready'] = ds.status.number_ready
            else:
                DAEMONSET_DATA['ready'] = 0
            if ds.spec.template.spec.image_pull_secrets:
                for ips in ds.spec.template.spec.image_pull_secrets:
                    DAEMONSET_DATA['image_pull_secrets'].append(ips.to_dict())
            if ds.spec.template.spec.service_account_name:
                DAEMONSET_DATA['service_account'] = ds.spec.template.spec.service_account_name
            if ds.spec.template.spec.volumes:
                for v in ds.spec.template.spec.volumes:
                    if v.persistent_volume_claim:
                        DAEMONSET_DATA['pvc'].append(v.persistent_volume_claim.claim_name)
                    if v.config_map:
                        DAEMONSET_DATA['cm'].append(v.config_map.name)
                    if v.secret:
                        DAEMONSET_DATA['secrets'].append(v.secret.secret_name)
            for c in ds.spec.template.spec.containers:
                if c.env:
                    for e in c.env:
                        ed = e.to_dict()
                        env_name = None
                        env_value = None
                        for name, val in ed.items():
                            if "value_from" in name and val is not None:
                                for key, value in val.items():
                                    if "secret_key_ref" in key and value:
                                        for n, v in value.items():
                                            if "name" in n:
                                                if v not in DAEMONSET_DATA['secrets']:
                                                    DAEMONSET_DATA['secrets'].append(v)
                            elif "name" in name and val is not None:
                                env_name = val
                            elif "value" in name and val is not None:
                                env_value = val

                        if env_name and env_value is not None:
                            DAEMONSET_DATA['environment_variables'].append({
                                env_name: env_value
                            })
                CONTAINERS = {
                    "name": c.name,
                    "image": c.image,
                }
                DAEMONSET_DATA['containers'].append(CONTAINERS)
            if ds.spec.template.spec.init_containers:
                for ic in ds.spec.template.spec.init_containers:
                    CONTAINERS = {
                        "name": ic.name,
                        "image": ic.image,
                    }
                    DAEMONSET_DATA['init_containers'].append(CONTAINERS)
            DAEMONSET_LIST.append(DAEMONSET_DATA)
        return DAEMONSET_LIST
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get daemonsets list - %s" % error.status)
        return DAEMONSET_LIST
    except Exception as error:
        ERROR = "k8sDaemonSetsGet: %s" % error
        ErrorHandler(logger, "error", ERROR)
        return DAEMONSET_LIST

def k8sDaemonsetPatch(username_role, user_token, ns, name, body):
    k8sClientConfigGet(username_role, user_token)
    try:
        api_response = k8s_client.AppsV1Api().patch_namespaced_daemon_set(
                name, ns, body, _request_timeout=5
            )
        flash("Daemonset: %s patched to replicas" % name, "success")
        logger.info("Deployment: %s patched to replicas" % name)
        return True
    except ApiException as error:
        ErrorHandler(logger, error, "ERROR: %s patch Daemonset Replica: %s" % (name, error))
        return False
    except Exception as error:
        ERROR = "k8sDaemonsetPatch: %s" % error
        ErrorHandler(logger, "error", ERROR)
        return False


##############################################################
## Deployments
##############################################################

def k8sDeploymentsGet(username_role, user_token, ns):
    k8sClientConfigGet(username_role, user_token)
    DEPLOYMENT_LIST = list()
    try:
        deployment_list = k8s_client.AppsV1Api().list_namespaced_deployment(ns, _request_timeout=5)
        for d in deployment_list.items:
            DEPLOYMENT_DATA = {
                "name": d.metadata.name,
                "annotations": list(),
                "namespace": ns,
                "labels": list(),
                "selectors": list(),
                "replicas": d.spec.replicas,
                # status
                "desired": "",
                "updated": "",
                "ready": "",
                # Environment variables
                "environment_variables": [],
                # Security
                "security_context": d.spec.template.spec.security_context.to_dict(),
                # Conditions
                "conditions": d.status.conditions,
                # Containers
                "containers": list(),
                "init_containers": list(),
                #  Related Resources
                "image_pull_secrets": list(),
                "service_account": list(),
                "pvc": list(),
                "cm": list(),
                "secrets": list(),
                "created": None,
            }
            DEPLOYMENT_DATA['created'] = d.metadata.creation_timestamp.strftime('%Y-%m-%d %H:%M:%S')
            if d.status.ready_replicas:
                DEPLOYMENT_DATA['ready']  = d.status.ready_replicas
            else:
                DEPLOYMENT_DATA['ready']  = 0
            if d.status.replicas:
                DEPLOYMENT_DATA['desired'] = d.status.replicas
            else:
                DEPLOYMENT_DATA['desired'] = 0
            if d.status.updated_replicas:
                DEPLOYMENT_DATA['updated'] = d.status.updated_replicas
            else:
                DEPLOYMENT_DATA['desired'] = 0
            if d.metadata.labels:
                DEPLOYMENT_DATA['labels'] = d.metadata.labels
            if d.metadata.annotations:
                DEPLOYMENT_DATA["annotations"] = trimAnnotations(d.metadata.annotations)
            selectors = d.spec.selector.to_dict()
            DEPLOYMENT_DATA['selectors'] = selectors['match_labels']
            if d.spec.template.spec.image_pull_secrets:
                for ips in d.spec.template.spec.image_pull_secrets:
                    DEPLOYMENT_DATA['image_pull_secrets'].append(ips.to_dict())
            if d.spec.template.spec.service_account_name:
                DEPLOYMENT_DATA['service_account'] = d.spec.template.spec.service_account_name
            if d.spec.template.spec.volumes:
                for v in d.spec.template.spec.volumes:
                    if v.persistent_volume_claim:
                        DEPLOYMENT_DATA['pvc'].append(v.persistent_volume_claim.claim_name)
                    if v.config_map:
                        DEPLOYMENT_DATA['cm'].append(v.config_map.name)
                    if v.secret:
                        DEPLOYMENT_DATA['secrets'].append(v.secret.secret_name)
            for c in d.spec.template.spec.containers:
                if c.env:
                    for e in c.env:
                        ed = e.to_dict()
                        env_name = None
                        env_value = None
                        for name, val in ed.items():
                            if "value_from" in name and val is not None:
                                for key, value in val.items():
                                    if "secret_key_ref" in key and value:
                                        for n, v in value.items():
                                            if "name" in n:
                                                if v not in DEPLOYMENT_DATA['secrets']:
                                                    DEPLOYMENT_DATA['secrets'].append(v)
                            elif "name" in name and val is not None:
                                env_name = val
                            elif "value" in name and val is not None:
                                env_value = val

                        if env_name and env_value is not None:
                            DEPLOYMENT_DATA['environment_variables'].append({
                                env_name: env_value
                            })
                CONTAINERS = {
                    "name": c.name,
                    "image": c.image,
                }
                DEPLOYMENT_DATA['containers'].append(CONTAINERS)
            if d.spec.template.spec.init_containers:
                for ic in d.spec.template.spec.init_containers:
                    CONTAINERS = {
                        "name": ic.name,
                        "image": ic.image,
                    }
                    DEPLOYMENT_DATA['init_containers'].append(CONTAINERS)

            DEPLOYMENT_LIST.append(DEPLOYMENT_DATA)
        return DEPLOYMENT_LIST
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get deployments list - %s" % error.status)
        return DEPLOYMENT_LIST
    except Exception as error:
        ERROR = "k8sDeploymentsGet: %s" % error
        ErrorHandler(logger, "error", ERROR)
        return DEPLOYMENT_LIST
    
def k8sDeploymentsPatchReplica(username_role, user_token, ns, name, replicas):
    k8sClientConfigGet(username_role, user_token)
    try:
        body = [
            {
                'op': 'replace', 
                'path': '/spec/replicas', 
                'value': int(replicas)
            }
        ]
        api_response = k8s_client.AppsV1Api().patch_namespaced_deployment_scale(
                name, ns, body, _request_timeout=5
            )
        flash("Deployment: %s patched to replicas %s" % (name, replicas), "success")
        logger.info("Deployment: %s patched to replicas %s" % (name, replicas))
        return True
    except ApiException as error:
        ErrorHandler(logger, error, "ERROR: %s patch Deployments Replica: %s" % (name, error))
        return False
    except Exception as error:
        ERROR = "k8sDeploymentsPatchReplica: %s" % error
        ErrorHandler(logger, "error", ERROR)
        return False
    
def k8sDeploymentsPatchAnnotation(username_role, user_token, ns, name, replicas):
    k8sClientConfigGet(username_role, user_token)
    try:
        body = [
            {
                'op': 'add', 
                'path': '/metadata/annotations/kubedash.devopstales.io~1original-replicas', 
                "value": str(replicas)
            }
        ]
        api_response = k8s_client.AppsV1Api().patch_namespaced_deployment(
                name, ns, body, _request_timeout=5
            )
        flash("Deployment: %s Annotation patched" % name, "success")
        logger.info("Deployment: %s Annotation patched" % name)
        return True
    except ApiException as error:
        ErrorHandler(logger, error, "ERROR: %s patch Deployments Annotation: %s" % (name, error))
        return False
    except Exception as error:
        ERROR = "k8sDeploymentsPatchAnnotation: %s" % error
        ErrorHandler(logger, "error", ERROR)
        return False

##############################################################
## Pods
##############################################################

def k8sPodListGet(username_role, user_token, ns):
    k8sClientConfigGet(username_role, user_token)
    POD_LIST = list()
    try:
        pod_list = k8s_client.CoreV1Api().list_namespaced_pod(ns, _request_timeout=5)
        for pod in pod_list.items:
            POD_SUM = {
                "name": pod.metadata.name,
                "status": pod.status.phase,
                "owner": "",
                "pod_ip": pod.status.pod_ip,
            }
            if pod.metadata.owner_references:
                for owner in pod.metadata.owner_references:
                    POD_SUM['owner'] = "%ss/%s" % (owner.kind.lower(), owner.name)
            POD_LIST.append(POD_SUM)
        return POD_LIST
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get pod list - %s" % error.status)
        return POD_LIST

def k8sPodGet(username_role, user_token, ns, po):
    k8sClientConfigGet(username_role, user_token)
    POD_DATA = {}
    try: 
        pod_data = k8s_client.CoreV1Api().read_namespaced_pod(po, ns, _request_timeout=5)
        POD_DATA = {
            # main
            "name": po,
            "namespace": ns,
            "status": pod_data.status.phase,
            "restarts": pod_data.status.container_statuses[0].restart_count,
            "annotations": list(),
            "labels": list(),
            "owner": "",
            "node": pod_data.spec.node_name,
            "priority": pod_data.spec.priority,
            "priority_class_name": pod_data.spec.priority_class_name,
            "runtime_class_name": pod_data.spec.runtime_class_name,
            # Environment variables
            "environment_variables": [],
            # Containers
            "containers": list(),
            "init_containers": list(),
            #  Related Resources
            "image_pull_secrets": [],
            "service_account": pod_data.spec.service_account_name,
            "pvc": list(),
            "cm": list(),
            "secrets": list(),
            # Security
            "security_context": pod_data.spec.security_context.to_dict(),
            # Conditions
            "conditions": list(),
            "created": None,
        }
        POD_DATA['created'] = pod_data.metadata.creation_timestamp.strftime('%Y-%m-%d %H:%M:%S')
        if pod_data.metadata.labels:
            POD_DATA['labels'] = pod_data.metadata.labels
        if pod_data.metadata.annotations:
            POD_DATA['annotations'] = trimAnnotations(pod_data.metadata.annotations)
        if pod_data.metadata.owner_references:
            for owner in pod_data.metadata.owner_references:
                POD_DATA['owner'] = "%ss/%s" % (owner.kind.lower(), owner.name)
        for c in  pod_data.spec.containers:
            if c.env:
                for e in c.env:
                    ed = e.to_dict()
                    env_name = None
                    env_value = None
                    for name, val in ed.items():
                        if "value_from" in name and val is not None:
                            for key, value in val.items():
                                if "secret_key_ref" in key and value:
                                    for n, v in value.items():
                                        if "name" in n:
                                            if v not in POD_DATA['secrets']:
                                                POD_DATA['secrets'].append(v)
                        elif "name" in name and val is not None:
                            env_name = val
                        elif "value" in name and val is not None:
                            env_value = val

                    if env_name and env_value is not None:
                        POD_DATA['environment_variables'].append({
                            env_name: env_value
                        })
            CONTAINERS = {}
            for cs in pod_data.status.container_statuses:
                if cs.name == c.name:
                    if cs.ready:
                        CONTAINERS = {
                            "name": c.name,
                            "image": c.image,
                            "ready": "Running",
                            "restarts": cs.restart_count,
                        }
                    else:
                        CONTAINERS = {
                            "name": c.name,
                            "image": c.image,
                            "ready": cs.state.waiting.reason,
                            "restarts": cs.restart_count,
                        }
                    POD_DATA['containers'].append(CONTAINERS)
        if pod_data.spec.init_containers:
            for ic in pod_data.spec.init_containers:
                for ics in pod_data.status.init_container_statuses:
                    if ics.name == ic.name:
                        if ics.ready:
                            CONTAINERS = {
                                "name": ic.name,
                                "image": ic.image,
                                "ready": ics.state.terminated.reason,
                                "restarts": ics.restart_count,
                            }
                        else:
                            CONTAINERS = {
                                "name": ic.name,
                                "image": ic.image,
                                "ready": ics.state.waiting.reason,
                                "restarts": ics.restart_count,
                            }
                        POD_DATA['init_containers'].append(CONTAINERS)
        if pod_data.spec.image_pull_secrets:
            for ips in pod_data.spec.image_pull_secrets:
                POD_DATA['image_pull_secrets'].append(ips.to_dict())
        for v in pod_data.spec.volumes:
            # secret
            if v.persistent_volume_claim:
                POD_DATA['pvc'].append(v.persistent_volume_claim.claim_name)
            if v.config_map:
                POD_DATA['cm'].append(v.config_map.name)
            if v.secret:
                POD_DATA['secrets'].append(v.secret.secret_name)
        for c in pod_data.status.conditions:
            CONDITION = {
                c.type: c.status
            }
            POD_DATA['conditions'].append(CONDITION)
        return POD_DATA
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get pods in this namespace - %s" % error.status)
        return POD_DATA
    except Exception as error:
        ERROR = "k8sPodGet: %s" % error
        ErrorHandler(logger, "error", ERROR)
        return POD_DATA

def k8sPodGetContainers(username_role, user_token, namespace, pod_name):
    k8sClientConfigGet(username_role, user_token)
    POD_CONTAINER_LIST = list()
    POD_INIT_CONTAINER_LIST = list()
    try:
        pod_data = k8s_client.CoreV1Api().read_namespaced_pod(pod_name, namespace, _request_timeout=5)
        for c in  pod_data.spec.containers:
            for cs in pod_data.status.container_statuses:
                if cs.name == c.name:
                    if cs.ready:
                        POD_CONTAINER_LIST.append(c.name)
        if pod_data.spec.init_containers:
            for ic in pod_data.spec.init_containers:
                for ics in pod_data.status.init_container_statuses:
                    if ics.name == ic.name:
                        if ics.ready:
                            POD_INIT_CONTAINER_LIST.append(ic.name)

        return POD_CONTAINER_LIST, POD_INIT_CONTAINER_LIST
    except ApiException as error:
        ErrorHandler(logger, error, "get pod - %s" % error.status)
        return POD_CONTAINER_LIST, POD_INIT_CONTAINER_LIST
    except Exception as error:
        ERROR = "k8sPodGetContainers: %s" % error
        ErrorHandler(logger, "error", ERROR)
        return POD_CONTAINER_LIST, POD_INIT_CONTAINER_LIST


##############################################################
## Pod Logs
##############################################################

def k8sPodLogsStream(username_role, user_token, namespace, pod_name, container):
    k8sClientConfigGet(username_role, user_token)
    try:
        w = watch.Watch()
        for line in w.stream(
                k8s_client.CoreV1Api().read_namespaced_pod_log, 
                name=pod_name, 
                namespace=namespace,
                container=container,
                tail_lines=100,
                _request_timeout=5
            ):
            socketio.emit('response',
                                {'data': str(line)}, namespace="/log")
    except ApiException as error:
            NoFlashErrorHandler(logger, error, "get logStream - %s" % error.status)
    except Exception as error:
        ERROR = "k8sPodLogsStream: %s" % error
        NoFlashErrorHandler(logger, "error", ERROR)

##############################################################
## Pod Exec
##############################################################

def k8sPodExecSocket(username_role, user_token, namespace, pod_name, container):
    k8sClientConfigGet(username_role, user_token)
    try:
        wsclient = stream(k8s_client.CoreV1Api().connect_get_namespaced_pod_exec,
                pod_name,
                namespace,
                container=container,
                command=['/bin/sh'],
                stderr=True, stdin=True,
                stdout=True, tty=True,
                _preload_content=False,
                _request_timeout=5
                )
        return wsclient
    except Exception as error:
        ERROR = "k8sPodExecSocket: %s" % error
        NoFlashErrorHandler(logger, "error", ERROR)
        return None
    
"""
    def terminal_start(self, namespace, pod_name, container):
        command = [
            "/bin/sh",
            "-c",
            'TERM=xterm-256color; export TERM; [ -x /bin/bash ] '
            '&& ([ -x /usr/bin/script ] '
            '&& /usr/bin/script -q -c "/bin/bash" /dev/null || exec /bin/bash) '
            '|| exec /bin/sh']
        client_v1 = self.get_client()
        container_stream = stream(
            client_v1.connect_get_namespaced_pod_exec,
            name=pod_name,
            namespace=namespace,
            container=container,
            command=command,
            stderr=True, stdin=True,
            stdout=True, tty=True,
            _preload_content=False
        )

        return container_stream
"""

def k8sPodExecStream(wsclient, username_role, user_token, namespace, pod_name, container):
    while True:
        socketio.sleep(0.01)
        try:
            wsclient.update(timeout=5)

            """Read from wsclient"""
            output = wsclient.read_all()
            if output:
                """write back to socket"""
                socketio.emit(
                    "response", {"output": output}, namespace="/exec")
        #except:
        #    try:
        #        print("Failed to read")
        #        wsclient = k8sPodExecSocket(username_role, user_token, namespace, pod_name, container)
        #
        #        """Read from wsclient"""
        #        output = wsclient.read_all()
        #        if output:
        #            """write back to socket"""
        #            socketio.emit(
        #                "response", {"output": output}, namespace="/exec")
        #            
        #    except Exception as error:
        #        # Show disconnected status on the UI
        #        logger.error("k8sPodExecStream: %s" % error)

        except Exception as error:
            # Show disconnected status on the UI
            logger.error("k8sPodExecStream: %s" % error)

##############################################################
## ReplicaSets
##############################################################

def k8sReplicaSetsGet(username_role, user_token, ns):
    k8sClientConfigGet(username_role, user_token)
    REPLICASET_LIST = list()
    try:
        replicaset_list = k8s_client.AppsV1Api().list_namespaced_replica_set(ns, _request_timeout=5)
        for rs in replicaset_list.items:
            REPLICASET_DATA = {
                "name": rs.metadata.name,
                "owner": "",
                "desired": "",
                "current": "",
                "ready": "",
            }
            if rs.status.fully_labeled_replicas:
                REPLICASET_DATA['desired'] = rs.status.fully_labeled_replicas
            else:
                REPLICASET_DATA['desired'] = 0
            if rs.status.available_replicas:
                REPLICASET_DATA['current'] = rs.status.available_replicas
            else:
                REPLICASET_DATA['current'] = 0
            if rs.status.ready_replicas:
                REPLICASET_DATA['ready'] = rs.status.ready_replicas
            else:
                REPLICASET_DATA['ready'] = 0
            if rs.metadata.owner_references:
                for owner in rs.metadata.owner_references:
                    REPLICASET_DATA['owner'] = "%ss/%s" % (owner.kind.lower(), owner.name)
            REPLICASET_LIST.append(REPLICASET_DATA)
        return REPLICASET_LIST
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get replicasets list - %s" % error.status)
        return REPLICASET_LIST
    except Exception as error:
        ERROR = "k8sReplicaSetsGet: %s" % error
        ErrorHandler(logger, "error", ERROR)
        return REPLICASET_LIST


##############################################################
## StatefulSets
##############################################################

def k8sStatefulSetsGet(username_role, user_token, ns):
    k8sClientConfigGet(username_role, user_token)
    STATEFULSET_LIST = list()
    try:
        statefulset_list = k8s_client.AppsV1Api().list_namespaced_stateful_set(ns, _request_timeout=5)
        for sfs in statefulset_list.items:
            STATEFULSET_DATA = {
                "name": sfs.metadata.name,
                "namespace": ns,
                "annotations": list(),
                "labels": list(),
                "selectors": list(),
                # status
                "replicas": sfs.spec.replicas,
                "desired": "",
                "current": "",
                "ready": "",
                # Environment variables
                "environment_variables": [],
                # Security
                "security_context": sfs.spec.template.spec.security_context.to_dict(),
                # Containers
                "containers": list(),
                "init_containers": list(),
                #  Related Resources
                "image_pull_secrets": list(),
                "service_account": "",
                "pvc": list(),
                "cm": list(),
                "secrets": list(),
                "created": None,
            }
            STATEFULSET_DATA['created'] = sfs.metadata.creation_timestamp.strftime('%Y-%m-%d %H:%M:%S')
            if sfs.status.replicas:
                STATEFULSET_DATA['desired'] = sfs.status.replicas
            else:
                STATEFULSET_DATA['desired'] = 0
            if sfs.status.current_replicas:
                STATEFULSET_DATA['current'] = sfs.status.current_replicas
            else:
                STATEFULSET_DATA['current'] = 0
            if sfs.status.ready_replicas:
                STATEFULSET_DATA['ready'] = sfs.status.ready_replicas
            else:
                STATEFULSET_DATA['ready'] = 0
            if sfs.metadata.annotations:
                STATEFULSET_DATA['annotations'] = trimAnnotations(sfs.metadata.labels)
            if sfs.metadata.labels:
                STATEFULSET_DATA['labels'] = sfs.metadata.labels
            selectors = sfs.spec.selector.to_dict()
            STATEFULSET_DATA['selectors'] = selectors['match_labels']
            if sfs.spec.template.spec.image_pull_secrets:
                for ips in sfs.spec.template.spec.image_pull_secrets:
                    STATEFULSET_DATA['image_pull_secrets'].append(ips.to_dict())
            if sfs.spec.template.spec.service_account_name:
                STATEFULSET_DATA['service_account'] = sfs.spec.template.spec.service_account_name
            if sfs.spec.template.spec.volumes:
                for v in sfs.spec.template.spec.volumes:
                    if v.persistent_volume_claim:
                        STATEFULSET_DATA['pvc'].append(v.persistent_volume_claim.claim_name)
                    if v.config_map:
                        STATEFULSET_DATA['cm'].append(v.config_map.name)
                    if v.secret:
                        STATEFULSET_DATA['secrets'].append(v.secret.secret_name)
            for c in sfs.spec.template.spec.containers:
                if c.env:
                    for e in c.env:
                        ed = e.to_dict()
                        env_name = None
                        env_value = None
                        for name, val in ed.items():
                            if "value_from" in name and val is not None:
                                for key, value in val.items():
                                    if "secret_key_ref" in key and value:
                                        for n, v in value.items():
                                            if "name" in n:
                                                if v not in STATEFULSET_DATA['secrets']:
                                                    STATEFULSET_DATA['secrets'].append(v)
                            elif "name" in name and val is not None:
                                env_name = val
                            elif "value" in name and val is not None:
                                env_value = val

                        if env_name and env_value is not None:
                            STATEFULSET_DATA['environment_variables'].append({
                                env_name: env_value
                            })
                CONTAINERS = {
                    "name": c.name,
                    "image": c.image,
                }
                STATEFULSET_DATA['containers'].append(CONTAINERS)
            if sfs.spec.template.spec.init_containers:
                for ic in sfs.spec.template.spec.init_containers:
                    CONTAINERS = {
                        "name": ic.name,
                        "image": ic.image,
                    }
                    STATEFULSET_DATA['init_containers'].append(CONTAINERS)

            STATEFULSET_LIST.append(STATEFULSET_DATA)
        return STATEFULSET_LIST
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get statefullsets list - %s" % error.status)
        return STATEFULSET_LIST
    except Exception as error:
        ERROR = "k8sStatefulSetsGet: %s" % error
        ErrorHandler(logger, "error", ERROR)
        return STATEFULSET_LIST

def k8sStatefulSetPatchReplica(username_role, user_token, ns, name, replicas):
    k8sClientConfigGet(username_role, user_token)
    try:
        body = [
            {
                'op': 'replace', 
                'path': '/spec/replicas', 
                'value': int(replicas)
            }
        ]
        api_response = k8s_client.AppsV1Api().patch_namespaced_stateful_set_scale(
                name, ns, body, _request_timeout=5
            )
        flash("StatefulSet: %s patched to replicas %s" % (name, replicas), "success")
        logger.info("StatefulSet: %s patched to replicas %s" % (name, replicas))
        return True
    except ApiException as error:
        ErrorHandler(logger, error, "ERROR: %s patch StatefulSet Replica: %s" % (name, error))
        return False
    except Exception as error:
        ERROR = "k8sStatefulSetPatchReplica: %s" % error
        ErrorHandler(logger, "error", ERROR)
        return False

def k8sStatefulSetPatchAnnotation(username_role, user_token, ns, name, replicas):
    k8sClientConfigGet(username_role, user_token)
    try:
        body = [
            {
                'op': 'add', 
                'path': '/metadata/annotations/kubedash.devopstales.io~1original-replicas', 
                "value": str(replicas)
            }
        ]
        api_response = k8s_client.AppsV1Api().patch_namespaced_stateful_set(
                name, ns, body, _request_timeout=5
            )
        flash("StatefulSet: %s Annotation patched" % name, "success")
        logger.info("StatefulSet: %s Annotation patched" % name)
        return True
    except ApiException as error:
        ErrorHandler(logger, error, "ERROR: %s patch StatefulSet Annotation: %s" % (name, error))
        return False
    except Exception as error:
        ERROR = "k8sStatefulSetPatchAnnotation: %s" % error
        ErrorHandler(logger, "error", ERROR)
        return False


def k8sWorkloadList(username_role, user_token, namespace):
    WORKLOAD_LIST = []
    
    deployments_list = k8sDeploymentsGet(username_role, user_token, namespace)   
    for deploy in deployments_list:
        original_replicas = 0
        for annotation in deploy["annotations"]:
            ANNOTATIONS = annotation.split("=")
            if ANNOTATIONS[0] == "kubedash.devopstales.io/original-replicas":
                original_replicas = ANNOTATIONS[1]
        WORKLOAD = {
            "type": "deployment",
            "name": deploy["name"],
            "namespace": deploy["namespace"],
            "replicas": deploy["desired"],
            "original-replicas": original_replicas,
        }
        WORKLOAD_LIST.append(WORKLOAD)

    statefulset_list = k8sStatefulSetsGet(username_role, user_token, namespace)
    for statefulset in statefulset_list:
        original_replicas = 0
        for annotation in statefulset["annotations"]:
            ANNOTATIONS = annotation.split("=")
            if ANNOTATIONS[0] == "kubedash.devopstales.io/original-replicas":
                original_replicas = ANNOTATIONS[1]
        WORKLOAD = {
            "type": "statefulset",
            "name": statefulset["name"],
            "namespace": statefulset["namespace"],
            "replicas": statefulset["desired"],
            "original-replicas": original_replicas,
        }
        WORKLOAD_LIST.append(WORKLOAD)

    daemonset_list = k8sDaemonSetsGet(username_role, user_token, namespace)
    for daemonset in daemonset_list:
        WORKLOAD = {
            "type": "daemonset",
            "name": daemonset["name"],
            "namespace": daemonset["namespace"],
            "replicas": daemonset["desired"],
        }
        WORKLOAD_LIST.append(WORKLOAD)

    return WORKLOAD_LIST