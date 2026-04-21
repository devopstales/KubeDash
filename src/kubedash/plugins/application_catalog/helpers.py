"""
Helper functions for application catalog initialization and security policy updates.
"""

from urllib.parse import urlparse

from lib.helper_functions import get_logger, ErrorHandler
from lib.k8s.server import (
    K8S_DEFAULT_REQUEST_TIMEOUT as _K8S_DISCOVERY_TIMEOUT,
    is_k8s_unreachable_exception as _k8s_unreachable_error,
)
from .model import ApplicationCatalog
from .application import ApplicationCreate, ApplicationUpdate

logger = get_logger()


def application_links_init(app_config):
    """
    Initialize application catalog from kubedash.ini configuration.
    Reads [application_list] section and syncs with database.
    
    Args:
        app_config: Configuration object from kubedash.ini
    """
    try:
        if not hasattr(app_config, "has_section") or not app_config.has_section("application_list"):
            logger.info("No [application_list] section found in config")
            return
        
        section = app_config["application_list"]
        import re
        
        # Parse all application entries
        app_map = {}
        for key, value in section.items():
            match = re.match(r"app_(\d+)_(name|url|icon|embed|enable|enabled)$", key)
            if not match:
                continue
            index, field = match.groups()
            # Normalize 'enabled' to 'enable'
            if field == 'enabled':
                field = 'enable'
            app_map.setdefault(index, {})[field] = value
        
        # Sync with database
        from lib.components import db
        from sqlalchemy.exc import IntegrityError
        
        for index, data in app_map.items():
            app_name = data.get("name")
            app_url = data.get("url")
            
            if not app_name or not app_url:
                continue
            
            app_enabled = section.getboolean(f"app_{index}_enable", fallback=True)
            app_embedded = section.getboolean(f"app_{index}_embed", fallback=False)
            app_icon = data.get("icon", "")
            
            # Use no_autoflush to prevent premature flush during query
            with db.session.no_autoflush:
                # Priority: URL has unique constraint, so check URL first
                existing_by_url = ApplicationCatalog.query.filter_by(
                    application_url=app_url
                ).first()
                
                if existing_by_url:
                    # URL exists - update this application (config points to this URL)
                    # Check if name would conflict before updating
                    existing_by_name = ApplicationCatalog.query.filter_by(
                        application_name=app_name
                    ).first()
                    
                    if existing_by_name and existing_by_name.id != existing_by_url.id:
                        # Name already exists on different application - don't update name, just other fields
                        if app_icon:
                            existing_by_url.application_icon = app_icon
                        existing_by_url.application_enabled = app_enabled
                        existing_by_url.application_embedded = app_embedded
                        logger.debug(f"Updated existing application (URL: {app_url}, kept existing name '{existing_by_url.application_name}' due to conflict)")
                    else:
                        # No name conflict - update all fields including name
                        existing_by_url.application_name = app_name
                        if app_icon:
                            existing_by_url.application_icon = app_icon
                        existing_by_url.application_enabled = app_enabled
                        existing_by_url.application_embedded = app_embedded
                        logger.debug(f"Updated existing application (URL: {app_url}) to name '{app_name}'")
                else:
                    # URL doesn't exist, check if name exists
                    existing_by_name = ApplicationCatalog.query.filter_by(
                        application_name=app_name
                    ).first()
                    
                    if existing_by_name:
                        # Name exists but URL is different - update from config
                        existing_by_name.application_url = app_url
                        if app_icon:
                            existing_by_name.application_icon = app_icon
                        existing_by_name.application_enabled = app_enabled
                        existing_by_name.application_embedded = app_embedded
                        logger.debug(f"Updated existing application '{app_name}' (changed URL to {app_url})")
                    else:
                        # Create new application
                        new_app = ApplicationCatalog(
                            application_name=app_name,
                            application_url=app_url,
                            application_icon=app_icon if app_icon else None,
                            application_enabled=app_enabled,
                            application_embedded=app_embedded
                        )
                        db.session.add(new_app)
                        logger.debug(f"Created new application '{app_name}' with URL {app_url}")
            
            # Commit each application individually to handle race conditions
            try:
                db.session.commit()
            except IntegrityError as e:
                # Handle race condition: another request might have inserted the same app
                db.session.rollback()
                # Check again after rollback - prioritize URL
                existing_by_url = ApplicationCatalog.query.filter_by(
                    application_url=app_url
                ).first()
                
                if existing_by_url:
                    # URL exists - always update this application (config points to this URL)
                    # Check if name would conflict
                    existing_by_name = ApplicationCatalog.query.filter_by(
                        application_name=app_name
                    ).first()
                    
                    if existing_by_name and existing_by_name.id != existing_by_url.id:
                        # Name conflict - don't update name, just other fields
                        if app_icon:
                            existing_by_url.application_icon = app_icon
                        existing_by_url.application_enabled = app_enabled
                        existing_by_url.application_embedded = app_embedded
                    else:
                        # No conflict - update all fields
                        existing_by_url.application_name = app_name
                        if app_icon:
                            existing_by_url.application_icon = app_icon
                        existing_by_url.application_enabled = app_enabled
                        existing_by_url.application_embedded = app_embedded
                    db.session.commit()
                else:
                    # Check by name only if URL doesn't exist
                    existing_by_name = ApplicationCatalog.query.filter_by(
                        application_name=app_name
                    ).first()
                    if existing_by_name:
                        # Name exists and URL doesn't - safe to update URL
                        existing_by_name.application_url = app_url
                        if app_icon:
                            existing_by_name.application_icon = app_icon
                        existing_by_name.application_enabled = app_enabled
                        existing_by_name.application_embedded = app_embedded
                        db.session.commit()
                    else:
                        logger.warning(f"Failed to create or update application '{app_name}': {e}")
                        # Re-raise if it's not a duplicate key error
                        if "duplicate key" not in str(e).lower() and "unique constraint" not in str(e).lower():
                            raise
        
        logger.info(f"Initialized {len(app_map)} applications from config")
    except Exception as error:
        ErrorHandler(logger, error, f"Error initializing application links: {error}")


def update_security_policies(app, applications):
    """
    Update Content Security Policy (CSP) to allow embedding applications.
    
    Args:
        app: Flask application object
        applications: List of application dictionaries with 'url' and 'embed' keys
    """
    try:
        if not hasattr(app, 'talisman'):
            logger.warning("Talisman not initialized, cannot update CSP")
            return
        
        # Get embedded applications
        embedded_apps = [app_data for app_data in applications if app_data.get('embed', False)]
        
        if not embedded_apps:
            logger.info("No embedded applications found, CSP not updated")
            return
        
        # Extract domains from embedded application URLs
        domains = set()
        for app_data in embedded_apps:
            url = app_data.get('url', '')
            if url:
                try:
                    parsed = urlparse(url)
                    if parsed.scheme and parsed.netloc:
                        # Add the full origin (scheme + netloc)
                        domains.add(f"{parsed.scheme}://{parsed.netloc}")
                except Exception as e:
                    logger.warning(f"Failed to parse URL {url}: {e}")
        
        # Update CSP
        csp = app.talisman.content_security_policy.copy() if app.talisman.content_security_policy else {}
        
        # Initialize frame-src if not present
        if 'frame-src' not in csp:
            csp['frame-src'] = ["'self'"]
        elif isinstance(csp['frame-src'], str):
            csp['frame-src'] = [csp['frame-src']]
        
        # Add domains to frame-src
        if domains:
            # Ensure 'self' is included
            if "'self'" not in csp['frame-src']:
                csp['frame-src'].insert(0, "'self'")
            # Add application domains
            for domain in sorted(domains):
                if domain not in csp['frame-src']:
                    csp['frame-src'].append(domain)
        
        app.talisman.content_security_policy = csp
        logger.info(f"Updated CSP frame-src with {len(domains)} application domains")
        
    except Exception as error:
        ErrorHandler(logger, error, f"Error updating security policies: {error}")


def discover_ingress_applications():
    """
    Discover ingresses from all namespaces that have the application-catalog annotation
    and register them as applications in the database.
    
    Looks for ingresses with annotation: metadata.k8s.io/application-catalog = "true"
    """
    try:
        from kubernetes import client as k8s_client
        from kubernetes.client.rest import ApiException
        from lib.k8s.server import k8sClientConfigGet
        from lib.components import db
        from sqlalchemy.exc import IntegrityError
        
        # Use Admin role to access Kubernetes API
        k8sClientConfigGet("Admin", None)
        
        # List all ingresses across all namespaces
        networking_api = k8s_client.NetworkingV1Api()
        ingress_list = networking_api.list_ingress_for_all_namespaces(
            _request_timeout=_K8S_DISCOVERY_TIMEOUT
        )
        
        discovered_count = 0
        registered_count = 0
        
        for ingress in ingress_list.items:
            # Check for the application-catalog annotation
            annotations = ingress.metadata.annotations or {}
            app_catalog_annotation = annotations.get("metadata.k8s.io/application-catalog", "").lower()
            
            if app_catalog_annotation != "true":
                continue
            
            discovered_count += 1
            
            # Extract application name from annotation (required)
            app_name = annotations.get("metadata.k8s.io/application-catalog-name")
            if not app_name:
                logger.warning(f"Ingress {ingress.metadata.namespace}/{ingress.metadata.name} has application-catalog annotation but missing metadata.k8s.io/application-catalog-name, skipping")
                continue
            
            # Construct URL from ingress
            app_url = _extract_url_from_ingress(ingress)
            if not app_url:
                logger.warning(f"Could not extract URL from ingress {ingress.metadata.namespace}/{ingress.metadata.name}, skipping")
                continue
            
            # Extract optional fields from annotations
            # Default: enabled=true, embedded=false
            app_icon = annotations.get("metadata.k8s.io/application-catalog-icon")
            app_enabled_str = annotations.get("metadata.k8s.io/application-catalog-enabled", "true").lower()
            app_enabled = app_enabled_str in ("true", "1", "yes")
            app_embedded_str = annotations.get("metadata.k8s.io/application-catalog-embedded", "false").lower()
            app_embedded = app_embedded_str in ("true", "1", "yes")
            
            # Register in database
            try:
                with db.session.no_autoflush:
                    # Priority: URL is unique and ingress points to this URL, so URL is source of truth
                    # Check if URL already exists
                    existing_by_url = ApplicationCatalog.query.filter_by(
                        application_url=app_url
                    ).first()
                    
                    if existing_by_url:
                        # URL exists - always update this application from ingress (ingress points to this URL)
                        # Check if name would conflict before updating
                        existing_by_name = ApplicationCatalog.query.filter_by(
                            application_name=app_name
                        ).first()
                        
                        if existing_by_name and existing_by_name.id != existing_by_url.id:
                            # Name already exists on different application - don't update name, just other fields
                            if app_icon:
                                existing_by_url.application_icon = app_icon
                            existing_by_url.application_enabled = app_enabled
                            existing_by_url.application_embedded = app_embedded
                            logger.debug(f"Updated existing application (URL: {app_url}, kept existing name due to conflict) from ingress {ingress.metadata.namespace}/{ingress.metadata.name}")
                        else:
                            # No name conflict - update all fields including name
                            existing_by_url.application_name = app_name
                            if app_icon:
                                existing_by_url.application_icon = app_icon
                            existing_by_url.application_enabled = app_enabled
                            existing_by_url.application_embedded = app_embedded
                            logger.debug(f"Updated existing application (URL: {app_url}) from ingress {ingress.metadata.namespace}/{ingress.metadata.name}")
                    else:
                        # URL doesn't exist, check if name exists
                        existing_by_name = ApplicationCatalog.query.filter_by(
                            application_name=app_name
                        ).first()
                        
                        if existing_by_name:
                            # Name exists but URL is different and not used - update from ingress
                            existing_by_name.application_url = app_url
                            if app_icon:
                                existing_by_name.application_icon = app_icon
                            existing_by_name.application_enabled = app_enabled
                            existing_by_name.application_embedded = app_embedded
                            logger.debug(f"Updated existing application '{app_name}' (changed URL to {app_url}) from ingress {ingress.metadata.namespace}/{ingress.metadata.name}")
                        else:
                            # Create new application from ingress
                            new_app = ApplicationCatalog(
                                application_name=app_name,
                                application_url=app_url,
                                application_icon=app_icon if app_icon else None,
                                application_enabled=app_enabled,
                                application_embedded=app_embedded
                            )
                            db.session.add(new_app)
                            logger.debug(f"Created new application '{app_name}' from ingress {ingress.metadata.namespace}/{ingress.metadata.name}")
                
                # Commit each application individually to handle race conditions
                try:
                    db.session.commit()
                    registered_count += 1
                except IntegrityError as e:
                    # Handle race condition or constraint violation
                    db.session.rollback()
                    # Check again after rollback - prioritize URL
                    existing_by_url = ApplicationCatalog.query.filter_by(
                        application_url=app_url
                    ).first()
                    
                    if existing_by_url:
                        # URL exists - always update this application (ingress points to this URL)
                        # Check if name would conflict
                        existing_by_name = ApplicationCatalog.query.filter_by(
                            application_name=app_name
                        ).first()
                        
                        if existing_by_name and existing_by_name.id != existing_by_url.id:
                            # Name conflict - don't update name, just other fields
                            if app_icon:
                                existing_by_url.application_icon = app_icon
                            existing_by_url.application_enabled = app_enabled
                            existing_by_url.application_embedded = app_embedded
                        else:
                            # No conflict - update all fields
                            existing_by_url.application_name = app_name
                            if app_icon:
                                existing_by_url.application_icon = app_icon
                            existing_by_url.application_enabled = app_enabled
                            existing_by_url.application_embedded = app_embedded
                        db.session.commit()
                        registered_count += 1
                    else:
                        # Check by name only if URL doesn't exist
                        existing_by_name = ApplicationCatalog.query.filter_by(
                            application_name=app_name
                        ).first()
                        if existing_by_name:
                            # Name exists and URL doesn't - safe to update URL
                            existing_by_name.application_url = app_url
                            if app_icon:
                                existing_by_name.application_icon = app_icon
                            existing_by_name.application_enabled = app_enabled
                            existing_by_name.application_embedded = app_embedded
                            db.session.commit()
                            registered_count += 1
                        else:
                            logger.warning(f"Failed to create or update application '{app_name}' from ingress: {e}")
                            # Re-raise if it's not a duplicate key error
                            if "duplicate key" not in str(e).lower() and "unique constraint" not in str(e).lower():
                                raise
            except Exception as e:
                db.session.rollback()
                logger.warning(f"Error registering application '{app_name}' from ingress {ingress.metadata.namespace}/{ingress.metadata.name}: {e}")
                continue
        
        if discovered_count > 0:
            logger.info(f"Discovered {discovered_count} ingresses with application-catalog annotation, registered {registered_count} applications")
        else:
            logger.debug("No ingresses found with application-catalog annotation")
            
    except ApiException as error:
        if error.status == 403:
            logger.warning("Permission denied when listing ingresses. Application catalog ingress discovery skipped.")
        else:
            ErrorHandler(logger, error, f"Error discovering ingress applications: {error}")
    except Exception as error:
        if _k8s_unreachable_error(error):
            logger.warning(
                "Kubernetes API unreachable; skipping application catalog ingress discovery: %s",
                error,
            )
            return
        ErrorHandler(logger, error, f"Error discovering ingress applications: {error}")


def _extract_url_from_ingress(ingress):
    """
    Extract URL from an ingress resource.
    Uses the first host from ingress rules.
    If TLS is configured, uses https, otherwise http.
    
    Args:
        ingress: Kubernetes V1Ingress object
        
    Returns:
        str: Constructed URL (scheme://host) or None if cannot be determined
    """
    try:
        # Determine scheme based on TLS configuration
        scheme = "https" if ingress.spec.tls else "http"
        
        # Get the first host from ingress rules
        if not ingress.spec.rules or len(ingress.spec.rules) == 0:
            return None
        
        first_rule = ingress.spec.rules[0]
        host = first_rule.host
        if not host:
            return None
        
        # Construct URL using just the host (no path)
        url = f"{scheme}://{host}"
        return url
        
    except Exception as e:
        logger.warning(f"Error extracting URL from ingress: {e}")
        return None


def discover_service_applications():
    """
    Discover services from all namespaces that have the application-catalog annotation
    and register them as applications in the database.
    
    Looks for services with annotation: metadata.k8s.io/application-catalog = "true"
    For services, embedded defaults to true (unlike ingress where it defaults to false).
    """
    try:
        from kubernetes import client as k8s_client
        from kubernetes.client.rest import ApiException
        from lib.k8s.server import k8sClientConfigGet
        from lib.components import db
        from sqlalchemy.exc import IntegrityError
        
        # Use Admin role to access Kubernetes API
        k8sClientConfigGet("Admin", None)
        
        # List all services across all namespaces
        core_api = k8s_client.CoreV1Api()
        service_list = core_api.list_service_for_all_namespaces(
            _request_timeout=_K8S_DISCOVERY_TIMEOUT
        )
        
        discovered_count = 0
        registered_count = 0
        
        for service in service_list.items:
            # Check for the application-catalog annotation
            annotations = service.metadata.annotations or {}
            app_catalog_annotation = annotations.get("metadata.k8s.io/application-catalog", "").lower()
            
            if app_catalog_annotation != "true":
                continue
            
            discovered_count += 1
            
            # Extract application name from annotation (required)
            app_name = annotations.get("metadata.k8s.io/application-catalog-name")
            if not app_name:
                logger.warning(f"Service {service.metadata.namespace}/{service.metadata.name} has application-catalog annotation but missing metadata.k8s.io/application-catalog-name, skipping")
                continue
            
            # Construct URL from service
            app_url = _extract_url_from_service(service)
            if not app_url:
                logger.warning(f"Could not extract URL from service {service.metadata.namespace}/{service.metadata.name}, skipping")
                continue
            
            # Extract optional fields from annotations
            # Default: enabled=true, embedded=true (different from ingress which defaults to false)
            app_icon = annotations.get("metadata.k8s.io/application-catalog-icon")
            app_enabled_str = annotations.get("metadata.k8s.io/application-catalog-enabled", "true").lower()
            app_enabled = app_enabled_str in ("true", "1", "yes")
            # For services, default embedded to true (can be overridden by annotation)
            app_embedded_str = annotations.get("metadata.k8s.io/application-catalog-embedded", "true").lower()
            app_embedded = app_embedded_str in ("true", "1", "yes")
            
            # Register in database
            try:
                with db.session.no_autoflush:
                    # Priority: URL is unique and service points to this URL, so URL is source of truth
                    # Check if URL already exists
                    existing_by_url = ApplicationCatalog.query.filter_by(
                        application_url=app_url
                    ).first()
                    
                    if existing_by_url:
                        # URL exists - always update this application from service (service points to this URL)
                        # Check if name would conflict before updating
                        existing_by_name = ApplicationCatalog.query.filter_by(
                            application_name=app_name
                        ).first()
                        
                        if existing_by_name and existing_by_name.id != existing_by_url.id:
                            # Name already exists on different application - don't update name, just other fields
                            if app_icon:
                                existing_by_url.application_icon = app_icon
                            existing_by_url.application_enabled = app_enabled
                            existing_by_url.application_embedded = app_embedded
                            logger.debug(f"Updated existing application (URL: {app_url}, kept existing name due to conflict) from service {service.metadata.namespace}/{service.metadata.name}")
                        else:
                            # No name conflict - update all fields including name
                            existing_by_url.application_name = app_name
                            if app_icon:
                                existing_by_url.application_icon = app_icon
                            existing_by_url.application_enabled = app_enabled
                            existing_by_url.application_embedded = app_embedded
                            logger.debug(f"Updated existing application (URL: {app_url}) from service {service.metadata.namespace}/{service.metadata.name}")
                    else:
                        # URL doesn't exist, check if name exists
                        existing_by_name = ApplicationCatalog.query.filter_by(
                            application_name=app_name
                        ).first()
                        
                        if existing_by_name:
                            # Name exists but URL is different and not used - update from service
                            existing_by_name.application_url = app_url
                            if app_icon:
                                existing_by_name.application_icon = app_icon
                            existing_by_name.application_enabled = app_enabled
                            existing_by_name.application_embedded = app_embedded
                            logger.debug(f"Updated existing application '{app_name}' (changed URL to {app_url}) from service {service.metadata.namespace}/{service.metadata.name}")
                        else:
                            # Create new application from service
                            new_app = ApplicationCatalog(
                                application_name=app_name,
                                application_url=app_url,
                                application_icon=app_icon if app_icon else None,
                                application_enabled=app_enabled,
                                application_embedded=app_embedded
                            )
                            db.session.add(new_app)
                            logger.debug(f"Created new application '{app_name}' from service {service.metadata.namespace}/{service.metadata.name}")
                
                # Commit each application individually to handle race conditions
                try:
                    db.session.commit()
                    registered_count += 1
                except IntegrityError as e:
                    # Handle race condition or constraint violation
                    db.session.rollback()
                    # Check again after rollback - prioritize URL
                    existing_by_url = ApplicationCatalog.query.filter_by(
                        application_url=app_url
                    ).first()
                    
                    if existing_by_url:
                        # URL exists - always update this application (service points to this URL)
                        # Check if name would conflict
                        existing_by_name = ApplicationCatalog.query.filter_by(
                            application_name=app_name
                        ).first()
                        
                        if existing_by_name and existing_by_name.id != existing_by_url.id:
                            # Name conflict - don't update name, just other fields
                            if app_icon:
                                existing_by_url.application_icon = app_icon
                            existing_by_url.application_enabled = app_enabled
                            existing_by_url.application_embedded = app_embedded
                        else:
                            # No conflict - update all fields
                            existing_by_url.application_name = app_name
                            if app_icon:
                                existing_by_url.application_icon = app_icon
                            existing_by_url.application_enabled = app_enabled
                            existing_by_url.application_embedded = app_embedded
                        db.session.commit()
                        registered_count += 1
                    else:
                        # Check by name only if URL doesn't exist
                        existing_by_name = ApplicationCatalog.query.filter_by(
                            application_name=app_name
                        ).first()
                        if existing_by_name:
                            # Name exists and URL doesn't - safe to update URL
                            existing_by_name.application_url = app_url
                            if app_icon:
                                existing_by_name.application_icon = app_icon
                            existing_by_name.application_enabled = app_enabled
                            existing_by_name.application_embedded = app_embedded
                            db.session.commit()
                            registered_count += 1
                        else:
                            logger.warning(f"Failed to create or update application '{app_name}' from service: {e}")
                            # Re-raise if it's not a duplicate key error
                            if "duplicate key" not in str(e).lower() and "unique constraint" not in str(e).lower():
                                raise
            except Exception as e:
                db.session.rollback()
                logger.warning(f"Error registering application '{app_name}' from service {service.metadata.namespace}/{service.metadata.name}: {e}")
                continue
        
        if discovered_count > 0:
            logger.info(f"Discovered {discovered_count} services with application-catalog annotation, registered {registered_count} applications")
        else:
            logger.debug("No services found with application-catalog annotation")
            
    except ApiException as error:
        if error.status == 403:
            logger.warning("Permission denied when listing services. Application catalog service discovery skipped.")
        else:
            ErrorHandler(logger, error, f"Error discovering service applications: {error}")
    except Exception as error:
        if _k8s_unreachable_error(error):
            logger.warning(
                "Kubernetes API unreachable; skipping application catalog service discovery: %s",
                error,
            )
            return
        ErrorHandler(logger, error, f"Error discovering service applications: {error}")


def _extract_url_from_service(service):
    """
    Extract URL from a service resource.
    For LoadBalancer services, uses external IP if available.
    Otherwise, constructs URL using Kubernetes service DNS name.
    
    Args:
        service: Kubernetes V1Service object
        
    Returns:
        str: Constructed URL (scheme://host:port) or None if cannot be determined
    """
    try:
        # Default to http scheme (services don't have TLS info in spec)
        scheme = "http"
        
        # Get service name and namespace
        service_name = service.metadata.name
        namespace = service.metadata.namespace
        
        if not service_name or not namespace:
            return None
        
        # Get the first port from service spec
        if not service.spec.ports or len(service.spec.ports) == 0:
            return None
        
        first_port = service.spec.ports[0]
        port = first_port.port
        
        # Try to use LoadBalancer external IP if available
        if service.spec.type == "LoadBalancer" and service.status.load_balancer and service.status.load_balancer.ingress:
            ingress = service.status.load_balancer.ingress[0]
            if ingress.ip:
                # Use external IP
                url = f"{scheme}://{ingress.ip}:{port}"
                return url
            elif ingress.hostname:
                # Use external hostname
                url = f"{scheme}://{ingress.hostname}:{port}"
                return url
        
        # For NodePort, ClusterIP, or LoadBalancer without external IP, use service DNS name
        # Use short form: service-name.namespace (works within cluster)
        # Full form would be: service-name.namespace.svc.cluster.local
        host = f"{service_name}.{namespace}.svc.cluster.local"
        url = f"{scheme}://{host}:{port}"
        return url
        
    except Exception as e:
        logger.warning(f"Error extracting URL from service: {e}")
        return None
