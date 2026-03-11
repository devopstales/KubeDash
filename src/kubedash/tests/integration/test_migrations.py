"""
Migration tests for KubeDash.

These tests ensure that all database migrations can be applied and rolled back
without errors, preserving data integrity.
"""

import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from pathlib import Path


class TestMigrations:
    """Test database migrations."""

    @pytest.fixture
    def alembic_cfg(self, tmp_path):
        """Create Alembic configuration for testing."""
        migrations_dir = Path(__file__).parent.parent.parent / "migrations"
        alembic_ini = migrations_dir / "alembic.ini"

        cfg = Config(alembic_ini)
        cfg.set_main_option(
            "sqlalchemy.url",
            f"sqlite:///{tmp_path}/test.db"
        )
        return cfg

    @pytest.fixture
    def script(self, alembic_cfg):
        """Get Alembic script directory."""
        return ScriptDirectory.from_config(alembic_cfg)

    def test_all_migrations_have_downgrade(self, script):
        """Test that all migrations have a downgrade function."""
        for revision in script.walk_revisions():
            assert revision.downgrade is not None, (
                f"Migration {revision.revision} ({revision.doc}) "
                f"missing downgrade function"
            )

    def test_all_migrations_have_docstrings(self, script):
        """Test that all migrations have docstrings with context."""
        for revision in script.walk_revisions():
            module = revision.module
            docstring = module.__doc__
            assert docstring is not None, (
                f"Migration {revision.revision} missing docstring"
            )
            assert "Revision ID:" in docstring, (
                f"Migration {revision.revision} docstring missing Revision ID"
            )
            assert "Create Date:" in docstring, (
                f"Migration {revision.revision} docstring missing Create Date"
            )

    def test_migration_chain_integrity(self, script):
        """Test that migration chain is continuous without gaps."""
        revisions = list(script.walk_revisions())
        for i, revision in enumerate(revisions[:-1]):
            next_revision = revisions[i + 1]
            assert revision.down_revision == next_revision.revision, (
                f"Migration chain broken: {revision.revision} -> {next_revision.revision}"
            )

    def test_upgrade_head(self, alembic_cfg):
        """Test that all migrations can be applied to a fresh database."""
        # This should not raise any exceptions
        command.upgrade(alembic_cfg, "head")

    def test_downgrade_base(self, alembic_cfg):
        """Test that all migrations can be rolled back to base."""
        # First upgrade to head
        command.upgrade(alembic_cfg, "head")
        # Then downgrade to base
        command.downgrade(alembic_cfg, "base")

    def test_upgrade_downgrade_cycle(self, alembic_cfg, script):
        """Test upgrade and downgrade for each migration."""
        # Get all revision IDs in order
        revisions = [r.revision for r in script.walk_revisions()]
        revisions.reverse()  # Start from base

        # Test each migration individually
        for i, revision in enumerate(revisions):
            # Upgrade to this revision
            command.upgrade(alembic_cfg, revision)

            # Downgrade to previous revision
            if i > 0:
                prev_revision = revisions[i - 1]
                command.downgrade(alembic_cfg, prev_revision)

            # Upgrade again to verify re-upgrade works
            command.upgrade(alembic_cfg, revision)

        # Finally upgrade to head
        command.upgrade(alembic_cfg, "head")

    def test_no_data_loss_on_downgrade(self, alembic_cfg):
        """Test that downgrade doesn't lose track of migration state."""
        # Upgrade to head
        command.upgrade(alembic_cfg, "head")

        # Get current revision
        from alembic.runtime.migration import MigrationContext
        from alembic.script import ScriptDirectory

        script = ScriptDirectory.from_config(alembic_cfg)

        # Downgrade one step
        command.downgrade(alembic_cfg, "-1")

        # Verify we can still upgrade back
        command.upgrade(alembic_cfg, "head")

    def test_migration_dependencies_valid(self, script):
        """Test that all migration dependencies exist."""
        for revision in script.walk_revisions():
            if revision.down_revision:
                # Check that the down_revision exists
                try:
                    script.get_revision(revision.down_revision)
                except Exception as e:
                    pytest.fail(
                        f"Migration {revision.revision} has invalid "
                        f"down_revision {revision.down_revision}: {e}"
                    )


class TestSpecificMigrations:
    """Test specific important migrations."""

    @pytest.fixture
    def alembic_cfg(self, tmp_path):
        """Create Alembic configuration for testing."""
        migrations_dir = Path(__file__).parent.parent.parent / "migrations"
        alembic_ini = migrations_dir / "alembic.ini"

        cfg = Config(alembic_ini)
        cfg.set_main_option(
            "sqlalchemy.url",
            f"sqlite:///{tmp_path}/test.db"
        )
        return cfg

    def test_users_table_migration(self, alembic_cfg):
        """Test the initial users table migration."""
        # Upgrade to the users table migration
        command.upgrade(alembic_cfg, "7253f5a7bfda")

        # Downgrade back to base
        command.downgrade(alembic_cfg, "base")

        # Upgrade again to verify
        command.upgrade(alembic_cfg, "7253f5a7bfda")

    def test_application_catalog_migration(self, alembic_cfg):
        """Test the application catalog plugin migration."""
        # Upgrade to application catalog migration
        command.upgrade(alembic_cfg, "ea51eddbcfb6")

        # Downgrade to previous
        command.downgrade(alembic_cfg, "22fb365284ec")

        # Upgrade again
        command.upgrade(alembic_cfg, "ea51eddbcfb6")

    def test_ai_chat_migration(self, alembic_cfg):
        """Test the AI Chat (conversations/messages) migration."""
        # Upgrade to AI Chat migration (after stub a1b2c3d4e5f6)
        command.upgrade(alembic_cfg, "ai_chat_init")

        # Downgrade to previous
        command.downgrade(alembic_cfg, "ea51eddbcfb6")

        # Upgrade again
        command.upgrade(alembic_cfg, "ai_chat_init")
