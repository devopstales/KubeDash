"""
KubeDash Plugin System

Plugin discovery and registration.
"""

import importlib
from pathlib import Path

PLUGIN_DIR = Path(__file__).parent


def discover_plugins():
    """Discover all plugins in the plugins directory.
    
    Returns:
        list: List of plugin module names
    """
    plugins = []
    for plugin_dir in PLUGIN_DIR.iterdir():
        if plugin_dir.is_dir() and not plugin_dir.name.startswith('_'):
            init_file = plugin_dir / '__init__.py'
            if init_file.exists():
                plugins.append(plugin_dir.name)
    return plugins


def discover_plugin_apis():
    """Discover all plugin API modules.
    
    Returns:
        list: List of tuples (plugin_name, api_module) for plugins with api.py
    """
    plugin_apis = []
    for plugin_dir in PLUGIN_DIR.iterdir():
        if plugin_dir.is_dir() and not plugin_dir.name.startswith('_'):
            api_file = plugin_dir / 'api.py'
            if api_file.exists():
                plugin_apis.append(plugin_dir.name)
    return plugin_apis


def get_plugin_info(plugin_name):
    """Get information about a specific plugin.
    
    Args:
        plugin_name: Name of the plugin directory
        
    Returns:
        dict: Plugin information including enabled status, has_api, has_models
    """
    plugin_path = PLUGIN_DIR / plugin_name
    info = {
        'name': plugin_name,
        'path': str(plugin_path),
        'has_init': (plugin_path / '__init__.py').exists(),
        'has_api': (plugin_path / 'api.py').exists(),
        'has_model': (plugin_path / 'model.py').exists(),
    }
    return info


def register_plugin_blueprint(app, plugin_name):
    """Register a plugin's blueprint with the Flask app.
    
    Args:
        app: Flask application instance
        plugin_name: Name of the plugin
        
    Returns:
        bool: True if blueprint was registered, False otherwise
    """
    try:
        module = importlib.import_module(f"plugins.{plugin_name}")
        bp_name = f"{plugin_name}_bp"
        
        if hasattr(module, bp_name):
            blueprint = getattr(module, bp_name)
            app.register_blueprint(blueprint)
            return True
    except ImportError as e:
        app.logger.error(f"Failed to import plugin {plugin_name}: {e}")
    except Exception as e:
        app.logger.error(f"Error registering plugin {plugin_name}: {e}")
    
    return False


def register_plugin_api(app, plugin_name, parent_blueprint):
    """Register a plugin's API blueprint as a sub-blueprint.
    
    Args:
        app: Flask application instance
        plugin_name: Name of the plugin
        parent_blueprint: Parent smorest Blueprint to register under
        
    Returns:
        bool: True if API blueprint was registered, False otherwise
    """
    try:
        api_module = importlib.import_module(f"plugins.{plugin_name}.api")
        
        # Try different naming conventions
        bp_name = f"{plugin_name}_api_bp"
        
        if hasattr(api_module, bp_name):
            api_blueprint = getattr(api_module, bp_name)
            parent_blueprint.register_blueprint(api_blueprint)
            return True
        
        # Fallback: find any blueprint ending with _api_bp
        for attr_name in dir(api_module):
            attr = getattr(api_module, attr_name)
            if attr_name.endswith('_api_bp') and hasattr(attr, 'name'):
                parent_blueprint.register_blueprint(attr)
                return True
                
    except ImportError as e:
        app.logger.error(f"Failed to import plugin API {plugin_name}: {e}")
    except Exception as e:
        app.logger.error(f"Error registering plugin API {plugin_name}: {e}")
    
    return False


__all__ = [
    'discover_plugins',
    'discover_plugin_apis',
    'get_plugin_info',
    'register_plugin_blueprint',
    'register_plugin_api',
]
