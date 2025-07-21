import os, base64
from datetime import datetime, timedelta

from flask import Flask, request, jsonify

from kubernetes import client, config
from kubernetes.client.rest import ApiException

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

######################################################################
# Variables
######################################################################
app = Flask(__name__)

core_v1 = client.CoreV1Api()
authz_v1 = client.AuthorizationV1Api()

USERS = {}
GROUPS = {}
PROJECTS = {}
PROJECTS_CACHE = {}
######################################################################
# Base Functions
######################################################################

def load_kube_config():
    """
    Load Kubernetes configuration from the default location.
    """
    try:
        # Load in-cluster config
        if os.getenv("KUBERNETES_SERVICE_HOST"):
            config.load_incluster_config()
        else:
            config.load_kube_config()
    except config.ConfigException as e:
        print(f"Error loading kube config: {e}")
        raise

def gen_tls_cert(service_name: str, namespace: str):
    core_v1 = client.CoreV1Api()

    # === Generate CA Key and Cert ===
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"KubeDash CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow() - timedelta(days=1))
        .not_valid_after(datetime.utcnow() + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256(), default_backend())
    )

    # === Generate Server Key and Cert ===
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, f"{service_name}.{namespace}.svc"),
    ])
    alt_names = [
        f"{service_name}",
        f"{service_name}.{namespace}",
        f"{service_name}.{namespace}.svc",
        f"{service_name}.{namespace}.svc.cluster.local"
    ]
    san = x509.SubjectAlternativeName([x509.DNSName(name) for name in alt_names])

    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_subject)
        .issuer_name(ca_cert.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow() - timedelta(days=1))
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(san, critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256(), default_backend())
    )

    # === PEM encode all components ===
    cert_pem = server_cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = server_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()
    ca_cert_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode()
    ca_key_pem = ca_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()

    # === Store TLS Secret ===
    tls_secret_data = {
        "tls.crt": base64.b64encode(cert_pem.encode()).decode(),
        "tls.key": base64.b64encode(key_pem.encode()).decode(),
    }
    tls_secret = client.V1Secret(
        metadata=client.V1ObjectMeta(name="kubedash-api-cert", namespace=namespace),
        type="kubernetes.io/tls",
        data=tls_secret_data
    )
    try:
        core_v1.create_namespaced_secret(namespace=namespace, body=tls_secret)
    except ApiException as e:
        if e.status == 409:
            core_v1.replace_namespaced_secret("kubedash-api-cert", namespace, tls_secret)
        else:
            raise

    # === Store CA Secret ===
    ca_secret_data = {
        "ca.crt": base64.b64encode(ca_cert_pem.encode()).decode(),
        "ca.key": base64.b64encode(ca_key_pem.encode()).decode(),
    }
    ca_secret = client.V1Secret(
        metadata=client.V1ObjectMeta(name="kubedash-api-ca-cert", namespace=namespace),
        type="Opaque",
        data=ca_secret_data
    )
    try:
        core_v1.create_namespaced_secret(namespace=namespace, body=ca_secret)
    except ApiException as e:
        if e.status == 409:
            core_v1.replace_namespaced_secret("kubedash-api-ca-cert", namespace, ca_secret)
        else:
            raise

    return cert_pem, key_pem, ca_cert_pem, ca_key_pem

def register_api_service(ca_cert_pem: str, service_name: str, namespace: str):
    api_service_name = "v1.kubedash.devopstales.io"
    service_ref = client.V1ServiceReference(
        name=service_name,
        namespace=namespace,
        port=8443
    )

    metadata = client.V1ObjectMeta(name=api_service_name)

    # Base64 encode the cert
    ca_bundle = base64.b64encode(ca_cert_pem.encode()).decode()

    spec = client.V1APIServiceSpec(
        group="kubedash.devopstales.io",
        version="v1",
        service=service_ref,
        group_priority_minimum=1000,
        version_priority=15,
        ca_bundle=ca_bundle
    )

    api_service = client.V1APIService(
        api_version="apiregistration.k8s.io/v1",
        kind="APIService",
        metadata=metadata,
        spec=spec
    )

    api_registration = client.ApiregistrationV1Api()

    try:
        api_registration.create_api_service(api_service)
    except ApiException as e:
        if e.status == 409:
            # Already exists: replace it
            api_registration.replace_api_service(name=api_service_name, body=api_service)
        else:
            raise

##############################################################################
# Api Endpoint
##############################################################################

@app.route("/apis/kubedash.devopstales.io/v1/users", methods=["GET"])
def get_users():
    return jsonify(list(USERS.values()))

@app.route("/apis/kubedash.devopstales.io/v1/groups", methods=["GET"])
def get_groups():
    return jsonify(list(GROUPS.values()))

@app.route("/apis/kubedash.devopstales.io/v1/projects", methods=["GET"])
def get_projects():
    user = request.headers.get("Impersonate-User")
    groups = request.headers.get("Impersonate-Group")
    if not user:
        return jsonify({"error": "Missing Impersonate-User header"}), 403
    
    try:
        ns_list = core_v1.list_namespace().items
    except ApiException as e:
        return jsonify({"error": str(e)}), 500

    visible_namespaces = []
    
    for ns in ns_list:
        namespace = ns.metadata.name
        sar = client.V1SubjectAccessReview(
            spec=client.V1SubjectAccessReviewSpec(
                resource_attributes=client.V1ResourceAttributes(
                    namespace=namespace,
                    verb="get",
                    group="",
                    resource="namespaces"
                ),
                user=user,
                groups=[groups] if groups else None
            )
        )

        try:
            resp = authz_v1.create_subject_access_review(body=sar)
            if resp.status.allowed:
                visible_namespaces.append(create_project_obj(name=namespace, namespace=namespace))
        except ApiException as e:
            continue

    return jsonify({
        "apiVersion": "kubedash.devopstales.io/v1",
        "kind": "ProjectList",
        "items": visible_namespaces
    })

def start_api_service(cert_pem, key_pem):
    # Write certs to temporary files
    cert_path = "/tmp/tls.crt"
    key_path = "/tmp/tls.key"

    with open(cert_path, "w") as f:
        f.write(cert_pem)
    with open(key_path, "w") as f:
        f.write(key_pem)
    
    app.run(host="0.0.0.0", port=8443, ssl_context=(cert_path, key_path))

##############################################################################
# Operator logic
##############################################################################
import kopf
import logging

@kopf.on.startup()
def configure(settings: kopf.OperatorSettings, **_):
    service_name = "kubedash-api"
    namespace = "default"
    
    print("Starting operator")
    settings.posting.level = logging.INFO
    # Generate TLS certificates
    print("Generating TLS certificates...")
    cert_pem, key_pem, ca_cert_pem, ca_key_pem = gen_tls_cert(service_name, namespace)
    # Load Kubernetes configuration
    load_kube_config()
    # Register the APIService
    print("Registering APIService...")
    register_api_service(ca_cert_pem, service_name, namespace)
    # Start the HTTP server
    print("Starting HTTP server...")
    start_api_service(cert_pem, key_pem)


@kopf.on.create('kubedash.devopstales.io', 'v1', 'users')
def create_user(spec, name, logger, **_):
    USERS[name] = {"name": name, "fullName": spec.get("fullName"), "identities": spec.get("identities", [])}
    logger.info(f"User created: {name}")

@kopf.on.create('kubedash.devopstales.io', 'v1', 'groups')
def create_group(spec, name, logger, **_):
    GROUPS[name] = {"name": name, "users": spec.get("users", [])}
    logger.info(f"Group created: {name}")

"""Project -> Namespace"""
@kopf.on.create('kubedash.devopstales.io', 'v1', 'projects')
def on_project_create(spec, name, logger, **kwargs):
    logger.info(f"🆕 Project created: {name} — creating matching namespace")

    ns_body = client.V1Namespace(metadata=client.V1ObjectMeta(name=name))

    try:
        core_v1.create_namespace(ns_body)
        logger.info(f"✅ Namespace '{name}' created for project")
    except ApiException as e:
        if e.status == 409:
            logger.info(f"⚠️ Namespace '{name}' already exists")
        else:
            raise
        
@kopf.on.delete('kubedash.devopstales.io', 'v1', 'projects')
def on_project_delete(name, logger, **kwargs):
    logger.info(f"🗑 Project deleted: {name} — deleting namespace")
    try:
        core_v1.delete_namespace(name)
        logger.info(f"✅ Namespace '{name}' deleted")
    except ApiException as e:
        if e.status == 404:
            logger.info(f"⚠️ Namespace '{name}' not found")
        else:
            raise

"""Namespace -> Project"""
@kopf.on.create('', 'v1', 'namespaces')
def on_namespace_create(meta, spec, name, logger, **kwargs):
    logger.info(f"🆕 Namespace created: {name}")

    custom_api = client.CustomObjectsApi()

    project_name = name  # Match namespace name
    try:
        custom_api.create_cluster_custom_object(
            group="kubedash.devopstales.io",
            version="v1",
            plural="projects",
            body={
                "apiVersion": "kubedash.devopstales.io/v1",
                "kind": "Project",
                "metadata": {
                    "name": project_name,
                },
                "spec": {
                    "owner": "system:namespace-controller"
                }
            }
        )
        logger.info(f"✅ Project object created for namespace {name}")
    except client.rest.ApiException as e:
        if e.status == 409:
            logger.info(f"⚠️ Project for namespace {name} already exists.")
        else:
            raise

@kopf.on.delete('', 'v1', 'namespaces')
def on_namespace_delete(meta, name, logger, **kwargs):
    logger.info(f"🗑 Namespace deleted: {name}")
    custom_api = client.CustomObjectsApi()

    try:
        custom_api.delete_cluster_custom_object(
            group="kubedash.devopstales.io",
            version="v1",
            plural="projects",
            name=name
        )
        logger.info(f"✅ Project object '{name}' deleted.")
    except client.rest.ApiException as e:
        if e.status == 404:
            logger.info(f"⚠️ Project '{name}' not found (already deleted).")
        else:
            raise

##############################################################################
# Entry Point
##############################################################################

#if __name__ == "__main__":
#    service_name = "kubedash-api"
#    namespace = "default"
#    
#    cert_pem, key_pem, ca_cert_pem, ca_key_pem = gen_tls_cert(service_name, namespace)
#    
#    load_kube_config()
#    
#    # Create the APIService in Kubernetes
#    register_api_service(ca_cert_pem, service_name, namespace)
#    
#    start_api_service(cert_pem, key_pem)