import json, hashlib
from datetime import datetime
from logging import getLogger

from lib.helper_functions import ErrorHandler, ResponseHandler

from .helpers import registry_request, get_base_url, get_image_sbom_vulns

logger = getLogger(__name__)

##############################################################
# OCI Registry Functions
##############################################################

def RegistryGetRepositories(registry_server_url: str) -> list:
    """Get all repositories from the registry server
    
    Args:
        registry_server_url (str): The URL of the registry server.
    
    Returns:
        repositories (list): List of repositories from the registry server.
    """
    repositories = list()
    r, links = registry_request(registry_server_url, '_catalog?n=100')
    if r:
        j = r.json()
        repositories.extend(j['repositories'])
        while links:
            r, links = registry_request(registry_server_url, links.split("/", 2)[-1])
            if r:
                j = r.json()
                repositories.extend(j['repositories'])
    return repositories

def RegistryGetTags(registry_server_url: str, image: str) -> dict:
    """Get all tags for an image from the registry server
    
    Args:
        registry_server_url (str): The URL of the registry server.
        image (str): The name of the image.

    Returns:
        tags (dict): Dictionary containing the image name and a list of tags.
    """
    # TODO: Implement caching for tags to improve performance and reduce API calls.
    #       Store the tags in a database and update them periodically.
    tags = {}
    registry_base_url = get_base_url(registry_server_url)
    r, links = registry_request(registry_server_url, f"{image}/tags/list")
    if r:
        j = r.json()
        tags = {
            'registry': registry_base_url,
            'image': image,
            'tags': j['tags'],
        }
    return tags

def RegistryGetManifest(registry_server_url, image, tag) -> list[dict]:
    """Get the manifest for an image and tag
    
    Args:
        registry_server_url (str): The URL of the registry server.
        image (str): The name of the image.
        tag (str): The tag of the image.

    Returns:
        manifest (dict): Dictionary containing the image name, tag, and manifest details.
    """
    # TODO: Implement caching for manifests to improve performance and reduce API calls.
    #       Store the manifests in a database and update them periodically.
    manifest = list()
    registry_base_url = get_base_url(registry_server_url)
    r, links = registry_request(registry_server_url, f"{image}/manifests/{tag}")
    if r:
        j = r.json()
        #print(json.dumps(j, indent=2))

        manifest = {
            'registry': registry_base_url,
            'image': image,
            'tag': tag,
        }
        created_label = None
        manifest['signed'] = False

        rh, links = registry_request(registry_server_url, f"{image}/manifests/{tag}", "Accept:application/vnd.docker.distribution.manifest.v2+json")
        if 'Docker-Content-Digest' in rh.headers:
            image_digest = rh.headers['Docker-Content-Digest']
            image_tags = RegistryGetTags(registry_server_url, image)

            for tag in image_tags["tags"]:
                if tag == image_digest.replace(":", "-")+".sig":
                    manifest['signed'] = True
                if tag == image_digest.replace(":", "-")+".sbom":
                    sbom_vulnerabilities = get_image_sbom_vulns(registry_server_url, image, tag)
                    if sbom_vulnerabilities:
                        manifest["vulnerabilities"] = sbom_vulnerabilities
            manifest['digest'] = image_digest
        

        if j['schemaVersion'] == 1:
            manifest["layers"] = len(j['fsLayers'])
            manifest["architecture"] = j['architecture']
            manifest["format"] = "Docker"
            for layer in j["history"]:
                json_history = json.loads(layer["v1Compatibility"])
                if "created" in json_history:
                    manifest["created"] = json_history["created"]
                if "author" in json_history:
                    manifest["author"] = json_history["author"]
                if "os" in json_history:
                    manifest["os"] = json_history["os"]
                if "docker_version" in json_history:
                    manifest["docker_version"] = json_history["docker_version"]
                if "config" in json_history:
                    if "ExposedPorts" in json_history["config"]:
                        manifest["exposed_ports"] = json_history["config"]["ExposedPorts"]
                    if "Env" in json_history["config"]:
                        manifest["env"] = json_history["config"]["Env"]
                    if "Volumes" in json_history["config"]:
                        manifest["volumes"] = json_history["config"]["Volumes"]
                    if "WorkingDir" in json_history["config"]:
                        manifest["working_dir"] = json_history["config"]["WorkingDir"]
                    if "Cmd" in json_history["config"]:
                        manifest["cmd"] = json_history["config"]["Cmd"]
                    if "Entrypoint" in json_history["config"]:
                        manifest["entrypoint"] = json_history["config"]["Entrypoint"]
                    if "Labels" in json_history["config"] and json_history["config"]["Labels"]:
                        manifest["labels"] = json_history["config"]["Labels"]
                        for l_key, l_value in json_history["config"]["Labels"].items():
                            if l_key == "maintainer":
                                manifest["maintainer"] = l_value
                            elif l_key == "org.label-schema.vendor":
                                manifest["maintainer"] = l_value
                            elif l_key == "org.label-schema.build-date":
                                created_label = l_value
                            elif l_key == "org.label-schema.url":
                                manifest["url"] = l_value
                            elif l_key == "org.label-schema.usage":
                                manifest["usage"] = l_value
                            elif l_key == "org.label-schema.vcs-url":
                                manifest["source_code"] = l_value
                            elif l_key == "org.label-schema.vcs-ref":
                                manifest["source_code_version"] = l_value
                            elif l_key == "org.opencontainers.image.vendor":
                                manifest["maintainer"] = l_value
                            elif l_key == "org.opencontainers.image.authors":
                                manifest["authors"] = l_value
                            elif l_key == "org.opencontainers.image.created":
                                created_label = l_value
                            elif l_key == "org.opencontainers.image.url":
                                manifest["url"] = l_value
                            elif l_key == "org.opencontainers.image.source":
                                manifest["source_code"] = l_value
                            elif l_key == "org.opencontainers.image.revision":
                                manifest["source_code_version"] = l_value
                            elif l_key == "org.opencontainers.image.licenses":
                                manifest["licenses"] = l_value
                            elif l_key == "org.opencontainers.image.documentation":
                                manifest["documentation"] = l_value

        elif j['schemaVersion'] == 2:
            media_type = j["config"]["mediaType"]

            manifest["layers"] = len(j['layers'])
            manifest["format"] = "OCI"
            manifest["media_type"] = media_type

            for layer in j['layers']:
                if media_type == "application/vnd.oci.image.config.v1+json":
                        # Cosign Signature
                        if layer["mediaType"] == "application/vnd.dev.cosign.simplesigning.v1+json":
                            manifest["cosign_signature"] = layer["annotations"]["dev.cosignproject.cosign/signature"]
                            json_object = json.loads(layer["annotations"]["dev.sigstore.cosign/bundle"])
                            manifest["cosign_bundle"] = json.dumps(json_object, indent=2)
                            manifest["cosign_certificate"] = layer["annotations"]["dev.sigstore.cosign/certificate"]
                            manifest["cosign_chain"] = layer["annotations"]["dev.sigstore.cosign/chain"]

                if media_type == "application/vnd.aquasec.trivy.config.v1+json":
                    # Trivy DB
                    manifest["trivy_db"] = layer["annotations"]["org.opencontainers.image.title"]

                # Helm Chart
                if media_type == "application/vnd.cncf.helm.config.v1+json":
                    digest = j["config"]["digest"]
                    r2, links = registry_request(registry_server_url, f"{image}/blobs/{digest}")
                    if r2:
                        j2 = r2.json()
                        if "name" in j2:
                            manifest["helm_name"] = j2["name"]
                        if "home" in j2:
                            manifest["url"] = j2["home"]
                        if "source" in j2:
                            manifest["source_code"] = j2["source"]
                        if "version" in j2:
                            manifest["helm_version"] = j2["version"]
                        if "description" in j2:
                            manifest["helm_description"] = j2["description"]
                        if "appVersion" in j2:
                            manifest["helm_app_version"] = j2["appVersion"]
                        if "apiVersion" in j2:
                            manifest["helm_api_version"] = j2["apiVersion"]
                        if "annotations" in j2 and "licenses" in j2["annotations"]:
                            manifest["licenses"] = j2["annotations"]["licenses"]
                        if "maintainers" in j2:
                            manifest["maintainer"] = j2["maintainers"][0]["name"]

        else:
            manifest["format"] = "Unknown"
        if created_label:
            manifest["created"] = created_label

        #print(json.dumps(manifest, indent=2))
    return manifest

def RegistryDeleteTag(registry_server_url: str, image: str, tag: str):
    """ Delete a specific tag from a Docker registry.

    Args:
        registry_server_url (str): The URL of the Docker registry server.
        image (str): The name of the image.
        tag (str): The name of the tag to delete.
    """
    dummy_hash = "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
    r, links = registry_request(registry_server_url, f"{image}/manifests/{tag}", None, "DELETE")
    if r and r.status_code == 200:
        ResponseHandler(f"Tag {tag} deleted successfully", "success")
    elif r and r.status_code == 400:
        r2, links = registry_request(registry_server_url, f"{image}/blobs/uploads/?mount={dummy_hash}", None, "POST")
        LOCATION = r2.headers["Location"].split("/")[-1]
        if r2 and r2.status_code == 202:
            dummy_json = "{}"
            r3, links = registry_request(registry_server_url, f"{image}/blobs/uploads/{LOCATION}&digest={dummy_hash}", "Content-Type:application/octet-stream", "PUT", dummy_json)
            if r3 and r3.status_code == 201:
                manifest_json = {
                    "created": datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%f"),
                    "architecture": "amd64",
                    "os": "linux",
                    "config":{
                        "Labels":{
                            "delete-date": datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%f"),
                            "delete-tag": tag,
                        }
                    },
                    "rootfs": {
                        "type":"layers",
                        "diff_ids":["sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"],
                    },
                    "history": [
                        {
                            "created": datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%f"),
                            "created_by":"# regclient",
                            "comment":"scratch blob",
                        }
                    ],
                }
                formatted_manifest_json = json.dumps(manifest_json, sort_keys = True).encode("utf-8")
                manifest_json_hash = hashlib.sha256(formatted_manifest_json).hexdigest().lower()
                r4, links = registry_request(registry_server_url, f"{image}/blobs/uploads/?mount=sha256:{manifest_json_hash}", None, "POST")
                if r4 and r4.status_code == 202:
                    LOCATION2 = r4.headers["Location"].split("/")[-1]
                    r5, links = registry_request(registry_server_url, f"{image}/blobs/uploads/{LOCATION2}&digest=sha256:{manifest_json_hash}", "Content-Type:application/octet-stream", "PUT", formatted_manifest_json)
                    if r5 and r5.status_code == 201:
                        manifest_json2 = {
                            "schemaVersion":2,
                            "mediaType":"application/vnd.docker.distribution.manifest.v2+json",
                            "config":{
                                "mediaType":"application/vnd.docker.container.image.v1+json",
                                "size":418,
                                "digest": f"sha256:{manifest_json_hash}",
                                "layers":[
                                    {
                                        "mediaType":"application/vnd.docker.image.rootfs.diff.tar.gzip",
                                        "size":2,
                                        "digest":"sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
                                    }
                                ],
                            },
                        }
                        formatted_manifest_json2 = json.dumps(manifest_json2, sort_keys = True).encode("utf-8")
                        r6, links = registry_request(registry_server_url, f"{image}/manifests/{tag}", "Content-Type:application/vnd.docker.distribution.manifest.v2+json", "PUT", formatted_manifest_json2)
                        if r6 and r6.status_code == 201:
                            image_digest = r6.headers['Docker-Content-Digest']
                            r7, links = registry_request(registry_server_url, f"{image}/manifests/{image_digest}", None, "DELETE")
                            if r7 and r7.status_code == 202:
                                ResponseHandler(f"Tag {tag} deleted successfully", "info")
                            else:
                                ErrorHandler(logger, "Cannot Delete Tag", "Cannot Delete Tag: (r7) %s" % r7.json()["errors"][0]["message"])
                                logger.debug("r7: %s %s" % (r7.status_code, r7.reason)) # DEBUG
                        else:
                            ErrorHandler(logger, "Cannot Delete Tag", "Cannot Delete Tag: (r6) %s" % r6.json()["errors"][0]["message"])
                            logger.debug("r6: %s %s" % (r6.status_code, r6.reason)) # DEBUG
                    else:
                        ErrorHandler(logger, "Cannot Delete Tag", "Cannot Delete Tag: (r5) %s" % r5.json()["errors"][0]["message"])
                        logger.debug("r5: %s %s" % (r5.status_code, r5.reason)) # DEBUG
                else:
                    ErrorHandler(logger, "Cannot Delete Tag", "Cannot Delete Tag: (r4) %s" % r4.json()["errors"][0]["message"])
                    logger.debug("r4: %s %s" % (r4.status_code, r4.reason)) # DEBUG
            else:
                ErrorHandler(logger, "Cannot Delete Tag", "Cannot Delete Tag: (r3) %s" % r3.json()["errors"][0]["message"])
                logger.debug("r3: %s %s" % (r3.status_code, r3.reason)) # DEBUG
        else:
            ErrorHandler(logger, "Cannot Delete Tag", "Cannot Delete Tag: (r2) %s" % r2.json()["errors"][0]["message"])
            logger.debug("r2: %s %s" % (r2.status_code, r2.reason)) # DEBUG
    else:
        if r:
            ErrorHandler(logger, "Cannot Delete Tag", "Cannot Delete Tag: (r1) %s" % r.json()["errors"][0]["message"])
            logger.debug("r1: %s %s" % (r.status_code, r.reason)) # DEBUG
        else:
            ErrorHandler(logger, "Cannot Delete Tag", "Cannot Delete Tag: (r1) %s" % "Response is missing")
