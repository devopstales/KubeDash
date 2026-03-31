#!/usr/bin/env python3
"""KubeDash Command Line Interface.

This module provides a comprehensive CLI for managing KubeDash,
including database operations, user management, plugin management,
and configuration utilities.
"""

import sys
import os
import click
from flask import current_app
from flask.cli import with_appcontext

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@click.group()
@click.version_option(version='4.1.0', prog_name='kubedash')
def cli():
    """KubeDash - Kubernetes Dashboard Management CLI.
    
    This CLI provides commands for managing KubeDash including:
    database operations, user management, plugin management,
    and configuration utilities.
    """
    pass


# =============================================================================
# Database Commands
# =============================================================================

@cli.group()
def db():
    """Database management commands."""
    pass


@db.command('init')
@with_appcontext
def db_init():
    """Initialize the database with all tables.
    
    This creates all database tables without running migrations.
    Use 'kubedash db migrate' for production deployments.
    """
    from lib.components import db
    from lib.k8s.server import k8sClientConfig
    from lib.user import Role
    
    click.echo("Initializing database tables...")
    db.create_all()
    click.echo(click.style("✓ Database tables created successfully", fg='green'))
    
    # Create default roles if they don't exist
    click.echo("Creating default roles...")
    roles = ['admin', 'user', 'viewer']
    for role_name in roles:
        role = Role.query.filter_by(name=role_name).first()
        if not role:
            role = Role(name=role_name)
            db.session.add(role)
            click.echo(f"  Created role: {role_name}")
    db.session.commit()
    click.echo(click.style("✓ Default roles created", fg='green'))


@db.command('migrate')
@with_appcontext
def db_migrate():
    """Run database migrations.
    
    This runs Alembic migrations to update the database schema.
    """
    import subprocess
    
    click.echo("Running database migrations...")
    try:
        result = subprocess.run(
            ['flask', 'db', 'upgrade'],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            click.echo(click.style("✓ Migrations completed successfully", fg='green'))
            if result.stdout:
                click.echo(result.stdout)
        else:
            click.echo(click.style("✗ Migration failed", fg='red'))
            if result.stderr:
                click.echo(result.stderr, err=True)
                sys.exit(1)
    except Exception as e:
        click.echo(click.style(f"✗ Error running migrations: {e}", fg='red'))
        sys.exit(1)


@db.command('backup')
@click.option('--output', '-o', default='kubedash_backup.db',
              help='Output file for backup')
@with_appcontext
def db_backup(output):
    """Backup the database to a file.
    
    Creates a SQLite backup of the current database.
    For PostgreSQL, use native backup tools.
    """
    import shutil
    from lib.components import db
    
    db_uri = current_app.config['SQLALCHEMY_DATABASE_URI']
    
    if not db_uri.startswith('sqlite:///'):
        click.echo(click.style(
            "⚠ Backup command only supports SQLite databases. "
            "For PostgreSQL, use: pg_dump",
            fg='yellow'
        ))
        sys.exit(1)
    
    db_path = db_uri.replace('sqlite:///', '')
    
    try:
        shutil.copy2(db_path, output)
        click.echo(click.style(f"✓ Database backed up to: {output}", fg='green'))
    except Exception as e:
        click.echo(click.style(f"✗ Backup failed: {e}", fg='red'))
        sys.exit(1)


@db.command('drop')
@click.confirmation_option(prompt='Are you sure you want to drop all tables?')
@with_appcontext
def db_drop():
    """Drop all database tables.
    
    ⚠️  WARNING: This will delete all data!
    """
    from lib.components import db
    
    click.echo("Dropping all database tables...")
    db.drop_all()
    click.echo(click.style("✓ All tables dropped", fg='green'))
    click.echo(click.style(
        "⚠️  Warning: All data has been deleted",
        fg='yellow'
    ))


# =============================================================================
# User Management Commands
# =============================================================================

@cli.group()
def user():
    """User management commands."""
    pass


@user.command('create')
@click.argument('username')
@click.option('--password', '-p', prompt=True, hide_input=True,
              confirmation_prompt=True)
@click.option('--email', '-e', default=None, help='User email address')
@click.option('--role', '-r', default='user',
              type=click.Choice(['admin', 'user', 'viewer']),
              help='User role')
@with_appcontext
def user_create(username, password, email, role):
    """Create a new user.
    
    USERNAME is the username for the new user.
    """
    from lib.user import User, UserCreate, Role
    
    # Check if user exists
    existing = User.query.filter_by(username=username).first()
    if existing:
        click.echo(click.style(f"✗ User '{username}' already exists", fg='red'))
        sys.exit(1)
    
    # Create user
    try:
        UserCreate(username, password, email, 'Local', role.capitalize())
        click.echo(click.style(f"✓ User '{username}' created successfully", fg='green'))
        click.echo(f"  Username: {username}")
        click.echo(f"  Role: {role}")
        if email:
            click.echo(f"  Email: {email}")
    except Exception as e:
        click.echo(click.style(f"✗ Failed to create user: {e}", fg='red'))
        sys.exit(1)


@user.command('delete')
@click.argument('username')
@click.confirmation_option(prompt='Are you sure you want to delete this user?')
@with_appcontext
def user_delete(username):
    """Delete a user.
    
    USERNAME is the username to delete.
    """
    from lib.user import UserDelete
    
    try:
        UserDelete(username)
        click.echo(click.style(f"✓ User '{username}' deleted", fg='green'))
    except Exception as e:
        click.echo(click.style(f"✗ Failed to delete user: {e}", fg='red'))
        sys.exit(1)


@user.command('list')
@with_appcontext
def user_list():
    """List all users."""
    from lib.user import User
    
    users = User.query.all()
    
    if not users:
        click.echo("No users found.")
        return
    
    click.echo("\nUsers:")
    click.echo("-" * 60)
    click.echo(f"{'Username':<20} {'Email':<25} {'Role':<15}")
    click.echo("-" * 60)
    
    for user in users:
        email = user.email or 'N/A'
        role = user.roles[0].name if user.roles else 'N/A'
        click.echo(f"{user.username:<20} {email:<25} {role:<15}")
    
    click.echo("-" * 60)
    click.echo(f"Total: {len(users)} user(s)")


@user.command('reset-password')
@click.argument('username')
@click.option('--password', '-p', prompt=True, hide_input=True,
              confirmation_prompt=True)
@with_appcontext
def user_reset_password(username, password):
    """Reset a user's password.
    
    USERNAME is the username whose password to reset.
    """
    from lib.user import User, set_password
    
    user = User.query.filter_by(username=username).first()
    if not user:
        click.echo(click.style(f"✗ User '{username}' not found", fg='red'))
        sys.exit(1)
    
    try:
        set_password(user, password)
        click.echo(click.style(
            f"✓ Password reset for user '{username}'",
            fg='green'
        ))
    except Exception as e:
        click.echo(click.style(f"✗ Failed to reset password: {e}", fg='red'))
        sys.exit(1)


# =============================================================================
# Plugin Management Commands
# =============================================================================

@cli.group()
def plugin():
    """Plugin management commands."""
    pass


@plugin.command('list')
@with_appcontext
def plugin_list():
    """List all plugins and their status."""
    from plugins import discover_plugins, get_plugin_info
    
    plugins = discover_plugins()
    
    if not plugins:
        click.echo("No plugins found.")
        return
    
    click.echo("\nPlugins:")
    click.echo("-" * 70)
    click.echo(f"{'Name':<25} {'Status':<15} {'Version':<15} {'Description':<30}")
    click.echo("-" * 70)
    
    for plugin_name in plugins:
        info = get_plugin_info(plugin_name)
        status = "Enabled" if info.get('enabled', False) else "Disabled"
        version = info.get('version', 'N/A')
        description = info.get('description', 'N/A')[:28] + '...' if len(info.get('description', '')) > 30 else info.get('description', 'N/A')
        
        click.echo(f"{plugin_name:<25} {status:<15} {version:<15} {description:<30}")
    
    click.echo("-" * 70)
    click.echo(f"Total: {len(plugins)} plugin(s)")


@plugin.command('info')
@click.argument('plugin_name')
@with_appcontext
def plugin_info(plugin_name):
    """Show detailed information about a plugin.
    
    PLUGIN_NAME is the name of the plugin.
    """
    from plugins import get_plugin_info, discover_plugins
    
    plugins = discover_plugins()
    if plugin_name not in plugins:
        click.echo(click.style(f"✗ Plugin '{plugin_name}' not found", fg='red'))
        sys.exit(1)
    
    info = get_plugin_info(plugin_name)
    
    click.echo(f"\nPlugin: {plugin_name}")
    click.echo("=" * 60)
    click.echo(f"Name:        {info.get('name', 'N/A')}")
    click.echo(f"Version:     {info.get('version', 'N/A')}")
    click.echo(f"Description: {info.get('description', 'N/A')}")
    click.echo(f"Status:      {'Enabled' if info.get('enabled', False) else 'Disabled'}")
    click.echo(f"Author:      {info.get('author', 'N/A')}")
    click.echo(f"Blueprint:   {info.get('blueprint', 'N/A')}")
    click.echo("=" * 60)


# =============================================================================
# Configuration Commands
# =============================================================================

@cli.group()
def config():
    """Configuration management commands."""
    pass


@config.command('show')
@with_appcontext
def config_show():
    """Show current configuration."""
    import json
    
    # Get configuration (exclude sensitive data)
    config_dict = {}
    for key in sorted(current_app.config.keys()):
        if key not in ['SECRET_KEY', 'kubedash.ini']:
            config_dict[key] = current_app.config[key]
    
    click.echo("\nCurrent Configuration:")
    click.echo("=" * 60)
    click.echo(json.dumps(config_dict, indent=2, default=str))
    click.echo("=" * 60)


@config.command('validate')
@with_appcontext
def config_validate():
    """Validate the current configuration."""
    from lib.config_validator import validate_config, ConfigurationError
    
    click.echo("Validating configuration...")
    
    try:
        ini_dict = {
            section: dict(current_app.config['kubedash.ini'][section])
            for section in current_app.config['kubedash.ini'].sections()
        }
        validate_config(dict(current_app.config), ini_dict)
        click.echo(click.style("✓ Configuration validation passed", fg='green'))
    except ConfigurationError as e:
        click.echo(click.style("✗ Configuration validation failed:", fg='red'))
        for error in str(e).split('\n'):
            click.echo(f"  {error}")
        sys.exit(1)
    except Exception as e:
        click.echo(click.style(f"✗ Validation error: {e}", fg='red'))
        sys.exit(1)


# =============================================================================
# System Commands
# =============================================================================

@cli.command('info')
def system_info():
    """Show KubeDash system information."""
    import platform
    import sys
    
    click.echo("\nKubeDash System Information")
    click.echo("=" * 60)
    click.echo(f"KubeDash Version: 4.1.0")
    click.echo(f"Python Version:   {sys.version}")
    click.echo(f"Platform:         {platform.platform()}")
    click.echo(f"Architecture:     {platform.architecture()[0]}")
    click.echo(f"Machine:          {platform.machine()}")
    click.echo("=" * 60)


@cli.command('health')
@with_appcontext
def health_check():
    """Perform a health check."""
    from lib.components import db
    
    checks = {
        'database': False,
        'configuration': False,
    }
    
    # Check database
    try:
        db.session.execute(db.text('SELECT 1'))
        checks['database'] = True
        click.echo(click.style("✓ Database: OK", fg='green'))
    except Exception as e:
        click.echo(click.style(f"✗ Database: FAILED - {e}", fg='red'))
    
    # Check configuration
    try:
        from lib.config_validator import validate_config
        ini_dict = {
            section: dict(current_app.config['kubedash.ini'][section])
            for section in current_app.config['kubedash.ini'].sections()
        }
        validate_config(dict(current_app.config), ini_dict)
        checks['configuration'] = True
        click.echo(click.style("✓ Configuration: OK", fg='green'))
    except Exception as e:
        click.echo(click.style(f"✗ Configuration: FAILED - {e}", fg='red'))
    
    # Summary
    click.echo("=" * 60)
    if all(checks.values()):
        click.echo(click.style("Overall Status: HEALTHY", fg='green'))
    else:
        click.echo(click.style("Overall Status: UNHEALTHY", fg='red'))
        sys.exit(1)


# =============================================================================
# Main Entry Point
# =============================================================================

def main():
    """Main entry point for the CLI."""
    cli(obj={})


if __name__ == '__main__':
    main()
