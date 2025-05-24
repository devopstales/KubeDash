from itsdangerous import base64_decode, base64_encode
from sqlalchemy import inspect

from lib.components import db

from .model import Registry, RegistryEvents

##############################################################
## Registry Server
##############################################################

def RegistryServerCreate(registry_server_url, registry_server_port, registry_server_auth=False, 
                        registry_server_tls=False, insecure_tls=False, registry_server_auth_user=None, 
                        registry_server_auth_pass=None):
    """Create a new registry server object in database
    
    Args:
        registry_server_url (str):  Url of the registry server
        registry_server_port (str): Port of the registry server
        registry_server_auth (bool): Enable or disable aithentication for registry server
        registry_server_tls (bool): Use http or https in url
        insecure_tls (bool): Disable SSL certificate validation
        registry_server_auth_user (str): User to use for authentication
        registry_server_auth_pass (str): Password for authentication
    """
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
    """Update registry server object in database
    
    Args:
        registry_server_url (str):  Url of the registry server
        registry_server_port (str): Port of the registry server
        registry_server_auth (bool): Enable or disable aithentication for registry server
        registry_server_tls (bool): Use http or https in url
        insecure_tls (bool): Disable SSL certificate validation
        registry_server_auth_user (str): User to use for authentication
        registry_server_auth_pass (str): Password for authentication
    """
    registry = Registry.query.filter_by(registry_server_url=registry_server_url_old).first()
    if registry:
        registry.registry_server_url = registry_server_url
        registry.registry_server_port = registry_server_port
        registry.registry_server_tls = registry_server_tls
        registry.insecure_tls = insecure_tls
        if registry_server_auth:
            registry.registry_server_auth = registry_server_auth
            usrPass = registry_server_auth_user + ":" + registry_server_auth_pass
            registry.registry_server_auth_token = str(base64_encode(usrPass), "UTF-8")
        print(registry.insecure_tls)
        db.session.commit()

def RegistryServerListGet() -> list:
    """Get all registry servers from database
    
    Returns:
        registrys (list): list of Registry objects
    """
    registrys = Registry.query.all()
    if registrys:
        return registrys
    else:
        return list()

def RegistrySererGet(registry_server_url):
    """Get registry server object from database
    
    Args:
        registry_server_url (str):  Url of the registry server

    Returns:
        registry (Registry): Registry object or None if not found
    """
    registry = Registry.query.filter_by(registry_server_url=registry_server_url).first()
    if registry:
        return registry
    else:
        return None

def RegistryServerDelete(registry_server_url):
    """Delete registry server object from database
    
    Args:
        registry_server_url (str):  Url of the registry server
    """
    registry = Registry.query.filter_by(registry_server_url=registry_server_url).first()
    if registry:
        db.session.delete(registry)
        db.session.commit()

def RegistryEventCreate(event_action, event_repository, 
                        event_tag, event_digest, event_ip, event_user, event_created):
    """Create event object forregistry in database
    
    Args:
        event_action (str): Action of the event
        event_repository (str): Repository of the event
        event_tag (str): Inage tag
        event_digest (str): Digest of the image
        event_ip (str): Source IP address of the event
        event_user (str): User who initiated the event
        event_created (datetime): Time when the event occurred
    """
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
    """Get all events for a given repository and tag
    
    Args:
        repository (str): Repository of the event
        tag (str): Inage tag

    Returns:
        registry_events (list): List of RegistryEvents objects
    """
    registry_events = None
    inspector = inspect(db.engine)
    if inspector.has_table("registry_events"):
        registry_events = RegistryEvents.query.filter_by(repository=repository, tag=tag).all()
    return registry_events
