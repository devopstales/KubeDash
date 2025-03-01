import requests
from logging import getLogger

from .registry_server import RegistrySererGet

from lib.helper_functions import ErrorHandler

logger = getLogger(__name__)

#############################################################
## Helper Functions
##############################################################

def get_base_url(registry_server_url: str) -> str:
    """Generate URL for registry server
    
    Args:
        registry_server_url (str): The URL of the registry server.
        
    Returns:
        registry_base_url (str): The base URL for the registry server
    """
    registry = RegistrySererGet(registry_server_url)
    if registry:
        registry_url = registry.registry_server_url
        registry_port = str(registry.registry_server_port)
        if registry.registry_server_tls:
            registry_prefix = 'https://'
        else:
            registry_prefix = 'http://'
        registry_base_url = registry_prefix + registry_url + ':' + registry_port
        return registry_base_url
    else:
        return None

def get_request_options(registry_server_url: str):
    """Get verify and headers for registry server request
    
    Args:
        registry_server_url (str): The URL of the registry server.

    Returns:
        verify (bool): Verify SSL certificate for the registry server.
        headers (dict): Headers for the registry server request.
    """
    registry = RegistrySererGet(registry_server_url)
    verify = True
    headers = {
        "Cache-Control": "no-cache",
        "User-Agent": "KubeDash",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    if registry:
        if registry.insecure_tls:
            verify = False
            import urllib3
            urllib3.disable_warnings()

        if registry.registry_server_auth:
            headers["Authorization"]="Basic "+str(registry.registry_server_auth_token)

    return verify, headers

def registry_request(registry_server_url: str, url_path, header=None, method='GET', data=None):
    """Make a request to the registry server
    
    Args:
        registry_server_url (str): The URL of the registry server.
        url_path (str): The URL path to the resource.
        header (str): Header for the request.
        method (str): The HTTP method like GET or POST
        data (dict): Data for the POST request.
    
    Returns:
        response (requests.Response): The response from the registry server.
        next_url (str): The URL for the next page of results.
    """
    registry_base_url = get_base_url(registry_server_url)
    api_url = registry_base_url + '/v2/' + url_path
    logger.debug("%s %s" % (method, api_url)) # DEBUG
    verify, headers = get_request_options(registry_server_url)
    if header:
        header_name = header.split(':',1)[0]
        header_value = header.split(':',1)[-1]
        headers[header_name] = header_value
    else:
        headers["Accept"] = "application/vnd.oci.image.manifest.v1+json"

    # Debugging
    #proxies = {
    #'http': 'http://127.0.0.1:8080',
    #'https': 'http://127.0.0.1:8080',
    #}

    try:
        r = requests.request(url=api_url, method=method, headers=headers, verify=verify, data=data) # proxies=proxies
        if r.status_code == 401:
            ErrorHandler(logger, "Registry Error", 'Return Code was 401, Authentication required / not successful!')
            raise Exception()
        else:
            if r.links:
                return r, r.links['next']['url']
            else:
                return r, None
    except requests.RequestException as error:
        ErrorHandler(logger, "Registry Error", 'Problem during docker registry connection: %s' % error)
        return None, None
    
def get_image_sbom_vulns(registry_server_url, image, tag) -> list:
    """Get the SBOM vulnerabilities for an image and tag
    
    Args:
        registry_server_url (str): The URL of the registry server.
        image (str): The name of the image.
        tag (str): The tag of the image.

    Returns:
        vulnerabilities (list): List of vulnerabilities in dict found for the image and tag.
    """
    vulnerabilities = None
    rd, links = registry_request(registry_server_url, f"{image}/manifests/{tag}")
    if rd.status_code == 200:
        digest = rd.json()["layers"][0]['digest']
        rb, links = registry_request(registry_server_url, f"{image}/blobs/{digest}")
        jb = rb.json()
        sbom_vulnerabilities = jb["scanner"]["result"]["Results"][0]["Vulnerabilities"]
        if sbom_vulnerabilities:
            vulnerabilities = list()
            for sbom in sbom_vulnerabilities:
                vulnerability = {
                    "vulnerabilityID": sbom["VulnerabilityID"],
                    "severity": sbom["Severity"],
                    "score": sbom["CVSS"]["redhat"]["V3Score"],
                    "resource": sbom["PkgName"],
                    "installedVersion": sbom["InstalledVersion"],
                    "publishedDate": sbom["PublishedDate"],
                }
                if "fixedVersion" in sbom:
                    vulnerability["fixedVersion"] = sbom["FixedVersion"]
                vulnerabilities.append(vulnerability)
        return vulnerabilities