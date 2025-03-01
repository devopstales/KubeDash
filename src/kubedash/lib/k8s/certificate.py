import base64

from datetime import datetime, timezone
from OpenSSL import crypto

from kubernetes import client as k8s_client
from kubernetes.client.rest import ApiException

from lib.helper_functions import email_check

from . import logger
from .server import k8sClientConfigGet

##############################################################
## Kubernetes User
##############################################################

def k8sCreateUserCSR(username_role, user_token, username, user_csr_base64):
    k8sClientConfigGet(username_role, user_token)
    with k8s_client.ApiClient() as api_client:
        api_instance = k8s_client.CertificatesV1Api(api_client)
        body = k8s_client.V1CertificateSigningRequest(
            api_version = "certificates.k8s.io/v1",
            kind = "CertificateSigningRequest",
            metadata = k8s_client.V1ObjectMeta(
                name = "kubedash-user-"+username,
            ),
            spec = k8s_client.V1CertificateSigningRequestSpec(
                groups = ["system:authenticated"],
                request = user_csr_base64,
                usages = [
                    "digital signature",
                    "key encipherment",
                    "client auth",
                ],
                signer_name = "kubernetes.io/kubedash-apiserver-client",
                expiration_seconds = 315360000, # 10 years
            ),
        )
    pretty = "true"
    field_manager = 'KubeDash'
    try:
        api_response = api_instance.create_certificate_signing_request(body, pretty=pretty, field_manager=field_manager, _request_timeout=5)
        return True, None
    except ApiException as e:
        logger.error("Exception when calling CertificatesV1Api->create_certificate_signing_request: %s\n" % e)
        return False, e

def k8sApproveUserCSR(username_role, user_token, username):
    k8sClientConfigGet(username_role, user_token)
    certs_api = k8s_client.CertificatesV1Api()
    csr_name = "kubedash-user-"+username
    body = certs_api.read_certificate_signing_request_status(csr_name)
    approval_condition = k8s_client.V1CertificateSigningRequestCondition(
        last_update_time=datetime.now(timezone.utc).astimezone(),
        message='This certificate was approved by KubeDash',
        reason='KubeDash',
        type='Approved',
        status='True',
    )
    body.status.conditions = [approval_condition]
    response = certs_api.replace_certificate_signing_request_approval(csr_name, body) 

def k8sReadUserCSR(username_role, user_token, username):
    k8sClientConfigGet(username_role, user_token)
    with k8s_client.ApiClient() as api_client:
        api_instance = k8s_client.CertificatesV1Api(api_client)
        pretty = "true"
        name = "kubedash-user-"+username
    try:
        api_response = api_instance.read_certificate_signing_request(name, pretty=pretty, _request_timeout=5)
        user_certificate_base64 = api_response.status.certificate
        return user_certificate_base64
    except ApiException as e:
        logger.error("Exception when calling CertificatesV1Api->read_certificate_signing_request: %s\n" % e)

def k8sDeleteUserCSR(username_role, user_token, username):
    k8sClientConfigGet(username_role, user_token)
    with k8s_client.ApiClient() as api_client:
        api_instance = k8s_client.CertificatesV1Api(api_client)
        pretty = "true"
        name = "kubedash-user-"+username
    try:
        api_response = api_instance.delete_certificate_signing_request(name, pretty=pretty, _request_timeout=5)
    except ApiException as e:
        logger.error("Exception when calling CertificatesV1Api->delete_certificate_signing_request: %s\n" % e)

def k8sCreateUser(username, username_role='Admin', user_token=None):
    if email_check(username):
        user = username.split("@")[0]
    else:
        user = username
    pkey = crypto.PKey()
    pkey.generate_key(crypto.TYPE_RSA, 2048)

    # private key
    private_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey)
    private_key_base64 = base64.b64encode(private_key).decode('ascii')

    # Certificate Signing Request
    req = crypto.X509Req()
    req.get_subject().CN = user
    req.set_pubkey(pkey)
    req.sign(pkey, 'sha256')
    user_csr = crypto.dump_certificate_request(crypto.FILETYPE_PEM, req)
    user_csr_base64 = base64.b64encode(user_csr).decode('ascii')

    k8sCreateUserCSR(username_role, user_token, user, user_csr_base64)
    k8sApproveUserCSR(username_role, user_token, user)
    user_certificate_base64 = k8sReadUserCSR(username_role, user_token, user)
    k8sDeleteUserCSR(username_role, user_token, user)

    return private_key_base64, user_certificate_base64
