import importlib
import logging
import sys
from logging.config import fileConfig
from pathlib import Path

from alembic import context
from flask import current_app

# Ensure the app root (parent of migrations/) is on sys.path so "plugins" is importable
# when running "flask db migrate" from project root or other cwd.
_env_file = Path(__file__).resolve()
_app_root = _env_file.parent.parent
if str(_app_root) not in sys.path:
    sys.path.insert(0, str(_app_root))

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
# This line sets up loggers basically.
fileConfig(config.config_file_name)
logger = logging.getLogger('alembic.env')

# Plugin model module names (same convention as initialize_plugin_models)
_PLUGIN_MODEL_NAMES = ("models", "model")


def _discover_and_import_plugin_models(target_db):
    """Import plugin model modules so they are in target_db.metadata for autogenerate.

    Discovers plugin dirs from the filesystem (plugins/ next to this migrations dir)
    and tries plugins.{name}.model or .models for each. Does not rely on
    [plugin_settings]: all plugin models present in the repo are visible to Alembic.
    """
    migrations_dir = _env_file.parent
    plugins_dir = migrations_dir.parent / "plugins"
    if not plugins_dir.is_dir():
        logger.warning("Plugin models: plugins dir not found at %s", plugins_dir)
        return
    for path in sorted(plugins_dir.iterdir()):
        if not path.is_dir() or path.name.startswith("__"):
            continue
        plugin_name = path.name
        for mod_name in _PLUGIN_MODEL_NAMES:
            try:
                importlib.import_module(f"plugins.{plugin_name}.{mod_name}")
                logger.info("Plugin models loaded: plugins.%s.%s", plugin_name, mod_name)
                break
            except ImportError as e:
                logger.debug("Plugin %s.%s: %s", plugin_name, mod_name, e)
                continue
    # Guarantee ai_chat models are in metadata (e.g. if discovery missed them)
    if "ai_chat_conversations" not in target_db.metadata.tables:
        try:
            importlib.import_module("plugins.ai_chat.model")
            logger.info("Plugin models loaded: plugins.ai_chat.model (explicit fallback)")
        except ImportError as e:
            logger.warning("Could not load plugins.ai_chat.model for autogenerate: %s", e)


def get_engine():
    try:
        # this works with Flask-SQLAlchemy<3 and Alchemical
        return current_app.extensions['migrate'].db.get_engine()
    except TypeError:
        # this works with Flask-SQLAlchemy>=3
        return current_app.extensions['migrate'].db.engine


def get_engine_url():
    try:
        return get_engine().url.render_as_string(hide_password=False).replace(
            '%', '%%')
    except AttributeError:
        return str(get_engine().url).replace('%', '%%')


# add your model's MetaData object here
# for 'autogenerate' support
# from myapp import mymodel
# target_metadata = mymodel.Base.metadata
config.set_main_option('sqlalchemy.url', get_engine_url())
target_db = current_app.extensions['migrate'].db

# Import all plugin models from the filesystem so they are in target_db.metadata
# for autogenerate (independent of [plugin_settings] so ai_chat etc. are always detected).
# Plugin models loaded inside get_metadata() so autogenerate always sees them

# other values from the config, defined by the needs of env.py,
# can be acquired:
# my_important_option = config.get_main_option("my_important_option")
# ... etc.


def get_metadata():
    """Return db metadata for Alembic. Load plugin models first so autogenerate sees them."""
    _discover_and_import_plugin_models(target_db)
    if hasattr(target_db, 'metadatas'):
        return target_db.metadatas[None]
    return target_db.metadata


def run_migrations_offline():
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.

    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url, target_metadata=get_metadata(), literal_binds=True
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online():
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.

    """

    # this callback is used to prevent an auto-migration from being generated
    # when there are no changes to the schema
    # reference: http://alembic.zzzcomputing.com/en/latest/cookbook.html
    def process_revision_directives(context, revision, directives):
        if getattr(config.cmd_opts, 'autogenerate', False):
            script = directives[0]
            if script.upgrade_ops.is_empty():
                directives[:] = []
                logger.info('No changes in schema detected.')

    connectable = get_engine()

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=get_metadata(),
            process_revision_directives=process_revision_directives,
            **current_app.extensions['migrate'].configure_args
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
