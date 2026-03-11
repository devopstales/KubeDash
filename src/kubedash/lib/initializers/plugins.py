#!/usr/bin/env python3
"""Plugin system initialization for KubeDash."""

import importlib
from pathlib import Path
from flask import Flask

# Standard module names for plugin DB models (tried in order)
PLUGIN_MODEL_NAMES = ("models", "model")


def ensure_plugin_models_loaded(app: Flask):
    """Import plugin model modules so they are on db.metadata (no db.create_all()).

    Use this in the 'db' branch (flask db migrate/upgrade) so Alembic autogenerate
    sees all plugin tables. Does not create tables; only imports so models register.
    Discovers from filesystem (all plugins with model.py or models.py), not config.
    """
    plugins_dir = Path(__file__).parent.parent.parent / "plugins"
    if not plugins_dir.is_dir():
        return
    with app.app_context():
        from lib.components import db
        for path in sorted(plugins_dir.iterdir()):
            if not path.is_dir() or path.name.startswith("__"):
                continue
            plugin_name = path.name
            for mod_name in PLUGIN_MODEL_NAMES:
                try:
                    importlib.import_module(f"plugins.{plugin_name}.{mod_name}")
                    app.logger.info("Plugin models loaded for migrations: plugins.%s.%s", plugin_name, mod_name)
                    break
                except ImportError:
                    continue


def initialize_plugin_models(app: Flask):
    """Initialize database tables for all enabled plugins that define models.

    Call this after the database is initialized (after initialize_app_database).
    Tries to import plugins.{name}.models or plugins.{name}.model for each enabled
    plugin; when found, runs db.create_all() inside the application context.

    No per-plugin registration needed: add model.py or models.py to a plugin and
    enable it in [plugin_settings] to have tables created automatically.
    """
    plugins = app.config.get("plugins") or {}
    if not plugins:
        return

    app.logger.info("Initializing plugin database tables")
    with app.app_context():
        from lib.components import db
        if not hasattr(db, "engine") or db.engine is None:
            app.logger.warning("Database not initialized; skipping plugin model init")
            return

        for plugin_name, is_enabled in plugins.items():
            if not is_enabled:
                continue
            for mod_name in PLUGIN_MODEL_NAMES:
                try:
                    importlib.import_module(f"plugins.{plugin_name}.{mod_name}")
                    app.logger.info("    %s: imported %s, creating tables", plugin_name, mod_name)
                    db.create_all()
                    break
                except ImportError:
                    continue
                except Exception as e:
                    app.logger.error("    %s: error loading %s: %s", plugin_name, mod_name, e)
                    break


def initialize_app_plugins(app: Flask):
    """Initialize and register plugins for the Flask application dynamically.

    Scans the plugins directory and checks against [plugin_settings] in kubedash.ini.
    Each plugin must have:
    - A directory under plugins/
    - An __init__.py exposing a blueprint named {plugin_name}_bp
    """
    app.logger.info("Initializing Plugins Dynamically")
    app.logger.info("#######################################")

    # Initialize plugin system
    app.config["plugins"] = {}

    # Get the plugins directory (src/kubedash/plugins/)
    plugins_dir = Path(__file__).parent.parent.parent / "plugins"

    # Get all plugin folders
    plugin_folders = [f.name for f in plugins_dir.iterdir() if f.is_dir() and not f.name.startswith('__')]

    # Get plugin configuration (empty dict if section doesn't exist)
    try:
        plugin_config = app.config['kubedash.ini']['plugin_settings']
    except KeyError:
        plugin_config = {}

    # Process each discovered plugin
    app.logger.info("Plugins:")
    for plugin_name in plugin_folders:
        # Determine if plugin is enabled (default to False if not in config)
        is_enabled = plugin_config.getboolean(plugin_name, fallback=False)
        app.logger.info(f"  Plugin {plugin_name}: {is_enabled}")

        app.config["plugins"][plugin_name] = is_enabled

        try:
            if is_enabled:
                # Import the plugin module
                module = importlib.import_module(f"plugins.{plugin_name}")

                # Find and register the first matching blueprint
                bp_name = f"{plugin_name}_bp"
                if hasattr(module, bp_name):
                    blueprint = getattr(module, bp_name)
                    app.register_blueprint(blueprint)

                    # Initialize AI Chat LLM provider if this is the ai_chat plugin
                    if plugin_name == 'ai_chat':
                        try:
                            from plugins.ai_chat import initialize_llm_provider
                            initialize_llm_provider(app)
                        except Exception as e:
                            app.logger.warning(f"    Failed to initialize LLM provider: {e}")

                    # Plugin DB models are initialized by initialize_plugin_models() after DB init

                else:
                    app.logger.info(f"    No valid blueprint found for {plugin_name}")

        except ImportError as e:
            app.logger.error(f"  Failed to import plugin {plugin_name}: {str(e)}")
        except Exception as e:
            app.logger.error(f"  Error loading plugin {plugin_name}: {str(e)}")


def initialize_plugin_apis(app: Flask):
    """
    Dynamically discover and register plugin API blueprints.

    Scans the plugins directory for api.py files and registers them
    as sub-blueprints of a parent plugins blueprint, which is then
    registered with api_doc (similar to how api_v1_bp works).
    """
    from lib.components import csrf, api_doc
    from flask_smorest import Blueprint

    app.logger.info("Initializing Plugin APIs Dynamically")
    app.logger.info("#######################################")

    # Create a parent blueprint for all plugin APIs
    plugins_api_bp = Blueprint(
        "plugins_api",
        "plugins_api",
        url_prefix="/api/v1/plugins",
        description="Plugin APIs - Gateway API, Cert Manager, External Load Balancer, etc."
    )
    csrf.exempt(plugins_api_bp)

    # Get the plugins directory (src/kubedash/plugins/)
    plugins_dir = Path(__file__).parent.parent.parent / "plugins"

    # Get all plugin folders
    plugin_folders = [f.name for f in plugins_dir.iterdir() if f.is_dir() and not f.name.startswith('__')]

    # Process each discovered plugin
    app.logger.info("Plugin APIs:")
    for plugin_name in plugin_folders:
        # Check if plugin has an api.py file
        api_file = plugins_dir / plugin_name / "api.py"
        if not api_file.exists():
            continue

        try:
            # Try to import the API module
            api_module = importlib.import_module(f"plugins.{plugin_name}.api")

            # Try different naming conventions for the API blueprint
            # Pattern 1: {plugin_name}_api_bp (e.g., cert_manager_api_bp)
            bp_name = f"{plugin_name}_api_bp"
            # Pattern 2: For plugins with underscores, handle gateway_api -> gateway_api_api_bp
            if plugin_name == "gateway_api":
                bp_name = "gateway_api_api_bp"

            if hasattr(api_module, bp_name):
                api_blueprint = getattr(api_module, bp_name)
                # Exempt from CSRF protection (like extension_api_bp)
                csrf.exempt(api_blueprint)
                # Register as sub-blueprint of plugins_api_bp
                # The blueprint's url_prefix (e.g., /gateway-api) will be combined with /api/v1/plugins
                # Final path: /api/v1/plugins/gateway-api/...
                plugins_api_bp.register_blueprint(api_blueprint)
                app.logger.info(f"  Plugin API {plugin_name} Registered")
            else:
                # Try to find any blueprint ending with _api_bp
                found = False
                for attr_name in dir(api_module):
                    attr = getattr(api_module, attr_name)
                    if attr_name.endswith('_api_bp') and isinstance(attr, Blueprint):
                        api_blueprint = attr
                        # Exempt from CSRF protection (like extension_api_bp)
                        csrf.exempt(api_blueprint)
                        # Register as sub-blueprint of plugins_api_bp
                        plugins_api_bp.register_blueprint(api_blueprint)
                        app.logger.info(f"  Plugin API {plugin_name} Registered")
                        found = True
                        break
                if not found:
                    app.logger.warning(f"  Plugin API {plugin_name}: No API blueprint found (expected {bp_name})")

        except ImportError as e:
            app.logger.error(f"  Failed to import plugin API {plugin_name}: {str(e)}")
        except Exception as e:
            app.logger.error(f"  Error loading plugin API {plugin_name}: {str(e)}")
            app.logger.exception("  Plugin API %s traceback:", plugin_name)

    # Register the parent plugins blueprint with api_doc for Swagger documentation
    # This also registers the routes with the Flask app
    api_doc.register_blueprint(plugins_api_bp)
    app.logger.info(f"Plugin API blueprint registered: {plugins_api_bp.url_prefix}")
    app.logger.info("#######################################")
