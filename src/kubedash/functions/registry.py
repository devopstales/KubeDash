#!/usr/bin/env python3

import  requests, json, hashlib
from itsdangerous import base64_encode, base64_decode
from functions.components import db
from functions.helper_functions import get_logger, ErrorHandler, ResponseHandler, find_values_in_json
from flask_login import UserMixin
from sqlalchemy import inspect
from datetime import datetime

##############################################################
## Helper Functions
##############################################################

logger = get_logger(__name__)

##############################################################

def get_base_url(registry_server_url):
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

def get_request_options(registry_server_url):
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

def registry_request(registry_server_url, url_path, header=None, method='GET', data=None):
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
    except requests.RequestException:
        ErrorHandler(logger, "Registry Error", 'Problem during docker registry connection')
    
def get_image_sbom_vulns(registry_server_url, image, tag):
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


##############################################################
## Registry Data Functions
##############################################################
def RegistryGetRepositories(registry_server_url):
    repositories = list()
    r, links = registry_request(registry_server_url, '_catalog?n=100')
    j = r.json()
    repositories.extend(j['repositories'])
    while links:
        r, links = registry_request(registry_server_url, links.split("/", 2)[-1])
        j = r.json()
        repositories.extend(j['repositories'])
    return repositories

def RegistryGetTags(registry_server_url, image):
    registry_base_url = get_base_url(registry_server_url)
    r, links = registry_request(registry_server_url, f"{image}/tags/list")
    j = r.json()
    tags = {
        'registry': registry_base_url,
        'image': image,
        'tags': j['tags'],
    }
    return tags

def RegistryGetManifest(registry_server_url, image, tag):
    registry_base_url = get_base_url(registry_server_url)
    r, links = registry_request(registry_server_url, f"{image}/manifests/{tag}")
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

def RegistryDeleteTag(registry_server_url, image, tag):
    dummy_hash = "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
    r, links = registry_request(registry_server_url, f"{image}/manifests/{tag}", None, "DELETE")
    if r.status_code == 200:
        ResponseHandler(f"Tag {tag} deleted successfully", "success")
    elif r.status_code == 400:
        r2, links = registry_request(registry_server_url, f"{image}/blobs/uploads/?mount={dummy_hash}", None, "POST")
        LOCATION = r2.headers["Location"].split("/")[-1]
        if r2.status_code == 202:
            dummy_json = "{}"
            r3, links = registry_request(registry_server_url, f"{image}/blobs/uploads/{LOCATION}&digest={dummy_hash}", "Content-Type:application/octet-stream", "PUT", dummy_json)
            if r3.status_code == 201:
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
                if r4.status_code == 202:
                    LOCATION2 = r4.headers["Location"].split("/")[-1]
                    r5, links = registry_request(registry_server_url, f"{image}/blobs/uploads/{LOCATION2}&digest=sha256:{manifest_json_hash}", "Content-Type:application/octet-stream", "PUT", formatted_manifest_json)
                    if r5.status_code == 201:
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
                        if r6.status_code == 201:
                            image_digest = r6.headers['Docker-Content-Digest']
                            r7, links = registry_request(registry_server_url, f"{image}/manifests/{image_digest}", None, "DELETE")
                            if r7.status_code == 202:
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
        ErrorHandler(logger, "Cannot Delete Tag", "Cannot Delete Tag: (r1) %s" % r.json()["errors"][0]["message"])
        logger.debug("r1: %s %s" % (r.status_code, r.reason)) # DEBUG

##############################################################
## Database Models
##############################################################
class Registry(UserMixin, db.Model):
    __tablename__ = 'registry'
    id = db.Column(db.Integer, primary_key=True)
    registry_server_url = db.Column(db.Text, unique=True, nullable=False)
    registry_server_port = db.Column(db.Text, nullable=False)
    registry_server_auth = db.Column(db.Boolean, nullable=False)
    registry_server_tls = db.Column(db.Boolean, nullable=False)
    insecure_tls = db.Column(db.Boolean, nullable=False)
    registry_server_auth_token = db.Column(db.String(80), nullable=True)

    def __repr__(self):
        return_data = {
            "registry_server_url": self.registry_server_url,
            "registry_server_port": self.registry_server_port,
            "registry_server_auth": self.registry_server_auth,
            "registry_server_tls": self.registry_server_tls,
            "insecure_tls": self.insecure_tls,
            "registry_server_auth_token": self.registry_server_auth_token,
        }
        return str(return_data)
    
class RegistryEvents(UserMixin, db.Model):
    __tablename__ = 'registry_events'
    id = db.Column(db.Integer, unique=True, primary_key=True)
    action = db.Column(db.String(4), unique=False, nullable=False)
    repository = db.Column(db.String(100), unique=False, nullable=False)
    tag = db.Column(db.String(100), unique=False, nullable=True)
    digest = db.Column(db.String(100), unique=False, nullable=False)
    ip = db.Column(db.String(15), unique=False, nullable=False)
    user = db.Column(db.String(50), unique=False, nullable=True)
    created = db.Column(db.DateTime, unique=False, nullable=False)

    def __repr__(self):
        return_data = {
            "action": self.action,
            "repository": self.repository,
            "tag": self.tag,
            "ip": self.ip,
            "user": self.user,
            "created": self.created,
        }
        return str(return_data)

##############################################################
## Registry Server
##############################################################

def RegistryServerCreate(registry_server_url, registry_server_port, registry_server_auth=False, 
                        registry_server_tls=False, insecure_tls=False, registry_server_auth_user=None, 
                        registry_server_auth_pass=None):
    registry = Registry.query.filter_by(registry_server_url=registry_server_url).first()
    if registry is None:
        registry = Registry(
            registry_server_url = registry_server_url,
            registry_server_port = registry_server_port,
            registry_server_auth = registry_server_auth,
            registry_server_tls = registry_server_tls,
            insecure_tls = insecure_tls,
        )
        if registry_server_auth:
            usrPass = registry_server_auth_user + ":" + registry_server_auth_pass
            registry.registry_server_auth_token = str(base64_encode(usrPass), "UTF-8")
        db.session.add(registry)
        db.session.commit()

def RegistryServerUpdate(registry_server_url, registry_server_url_old, registry_server_port, registry_server_auth=False, 
                         registry_server_tls=False, insecure_tls=False, registry_server_auth_user=None, 
                        registry_server_auth_pass=None):
    registry = Registry.query.filter_by(registry_server_url=registry_server_url_old).first()
    if registry:
        registry.registry_server_url = registry_server_url
        registry.registry_server_port = registry_server_port
        registry.registry_server_auth = registry_server_auth
        registry.registry_server_tls = registry_server_tls
        registry.insecure_tls = insecure_tls
        if registry_server_auth:
            usrPass = registry_server_auth_user + ":" + registry_server_auth_pass
            registry.registry_server_auth_token = str(base64_encode(usrPass), "UTF-8")
        db.session.commit()

def RegistryServerListGet():
    registrys = Registry.query.all()
    if registrys:
        return registrys
    else:
        return list()

def RegistrySererGet(registry_server_url):
    registry = Registry.query.filter_by(registry_server_url=registry_server_url).first()
    if registry:
        return registry
    else:
        return None

def RegistryServerDelete(registry_server_url):
    registry = Registry.query.filter_by(registry_server_url=registry_server_url).first()
    if registry:
        db.session.delete(registry)
        db.session.commit()

def RegistryEventCreate(event_action, event_repository, 
                        event_tag, event_digest, event_ip, event_user, event_created):
    inspector = inspect(db.engine)
    if inspector.has_table("registry_events"):
        registry_event = RegistryEvents(
            action = event_action,
            repository = event_repository,
            tag = event_tag,
            digest = event_digest,
            ip = event_ip,
            user = event_user,
            created = event_created,
        )
        db.session.add(registry_event)
        db.session.commit()

def RegistryGetEvent(repository, tag):
    registry_events = None
    inspector = inspect(db.engine)
    if inspector.has_table("registry_events"):
        registry_events = RegistryEvents.query.filter_by(repository=repository, tag=tag).all()
    return registry_events