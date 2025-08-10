from logging import getLogger

import requests

from kubedash.lib.helper_functions import ErrorHandler

from .registry_server import RegistrySererGet

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
                # Initialize score as None in case CVSS information isn't available
                score = None
                if "CVSS" in sbom and "redhat" in sbom["CVSS"] and "V3Score" in sbom["CVSS"]["redhat"]:
                    score = sbom["CVSS"]["redhat"]["V3Score"]
                    
                fixed_version = None
                if "FixedVersion" in sbom and sbom["FixedVersion"] is not None:
                    fixed_version = sbom["FixedVersion"]
                
                vulnerability = {
                    "vulnerabilityID": sbom["VulnerabilityID"],
                    "severity": sbom["Severity"],
                    "score": score,
                    "resource": sbom["PkgName"],
                    "installedVersion": sbom["InstalledVersion"],
                    "publishedDate": sbom["PublishedDate"],
                    "fixedVersion": fixed_version,  # Initialize fixedVersion as None
                }

                vulnerabilities.append(vulnerability)
        return vulnerabilities

def process_image_labels(config_data):
    """
    Extracts standardized labels from Docker image config and maps them to a structured format.
    Follows OpenContainers Image Spec (https://specs.opencontainers.org/image-spec/annotations/)
    and Label Schema (http://label-schema.org/rc1/) standards.
    """
    manifest = {}
    created_label = None
    
    if "config" in config_data and "Labels" in config_data["config"]:
        labels = config_data["config"]["Labels"]
        manifest["labels"] = labels
        
        # OpenContainers Standard Annotations
        label_mappings = {
            # Core OpenContainers labels
            "org.opencontainers.image.created": ("created", None),
            "org.opencontainers.image.url": ("url", None),
            "org.opencontainers.image.source": ("source_code", None),
            "org.opencontainers.image.version": ("version", None),
            "org.opencontainers.image.revision": ("revision", None),
            "org.opencontainers.image.licenses": ("licenses", None),
            "org.opencontainers.image.documentation": ("documentation", None),
            
            # Label Schema (legacy) mappings
            "org.label-schema.build-date": ("build_date", None),
            "org.label-schema.vcs-url": ("vcs_url", None),
            "org.label-schema.vcs-ref": ("vcs_ref", None),
            "org.label-schema.version": ("version", None),
            "org.label-schema.license": ("license", None),
            
            # Common vendor-specific mappings
            "com.example.maintainer": ("maintainer", None),
            "com.example.release-notes": ("release_notes", None)
        }
        
        # Process all labels
        for label_key, label_value in labels.items():
            # Standardized label processing
            if label_key in label_mappings:
                manifest_key, transform_fn = label_mappings[label_key]
                manifest[manifest_key] = transform_fn(label_value) if transform_fn else label_value
            
            # Special handling for created date
            if label_key == "org.opencontainers.image.created":
                created_label = label_value
                
        # Set default fields if not found
        if "created" not in manifest and created_label:
            manifest["created"] = created_label
            
    return manifest