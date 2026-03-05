#!/usr/bin/env python3
"""Configuration validation for KubeDash.

This module provides configuration validation to ensure required
settings are properly configured before the application starts.
"""

import os
import re
import logging
from typing import Dict, List, Tuple, Optional, Any

logger = logging.getLogger(__name__)


class ConfigurationError(Exception):
    """Exception raised for configuration validation errors."""
    pass


class ConfigValidator:
    """Validates KubeDash configuration.
    
    This validator checks:
    - Required environment variables
    - Security settings (SECRET_KEY length, admin password)
    - Database configuration
    - Cache configuration
    - SSO/OAuth2 settings (if enabled)
    """
    
    # Required configuration keys
    REQUIRED_KEYS = [
        'SECRET_KEY',
        'SQLALCHEMY_DATABASE_URI',
    ]
    
    # Security requirements
    MIN_SECRET_KEY_LENGTH = 32
    MIN_ADMIN_PASSWORD_LENGTH = 8
    
    # Database URI patterns
    VALID_DATABASE_PATTERNS = [
        r'^sqlite:///',
        r'^postgresql://',
        r'^postgresql\+psycopg2://',
        r'^mysql://',
    ]
    
    def __init__(self, config: Dict[str, Any], ini_config: Optional[Dict[str, Any]] = None):
        """Initialize the validator.
        
        Args:
            config: Flask app configuration dictionary
            ini_config: Configuration from kubedash.ini (optional)
        """
        self.config = config
        self.ini_config = ini_config or {}
        self.errors: List[str] = []
        self.warnings: List[str] = []
    
    def validate_all(self) -> bool:
        """Run all validation checks.
        
        Returns:
            bool: True if validation passes, False otherwise
            
        Raises:
            ConfigurationError: If critical validation errors are found
        """
        logger.info("Validating configuration...")
        
        self.validate_required_keys()
        self.validate_security_settings()
        self.validate_database_config()
        self.validate_cache_config()
        self.validate_sso_config()
        self.validate_environment_vars()
        
        # Log warnings
        for warning in self.warnings:
            logger.warning(f"Configuration warning: {warning}")
        
        # Raise error if critical issues found
        if self.errors:
            error_msg = "Configuration validation failed:\n" + "\n".join(f"  - {e}" for e in self.errors)
            logger.error(error_msg)
            raise ConfigurationError(error_msg)
        
        logger.info("Configuration validation passed")
        return True
    
    def validate_required_keys(self) -> None:
        """Validate that all required configuration keys are present."""
        for key in self.REQUIRED_KEYS:
            if key not in self.config or not self.config[key]:
                self.errors.append(f"Required configuration key missing: {key}")
    
    def validate_security_settings(self) -> None:
        """Validate security-related configuration."""
        # Check SECRET_KEY length
        secret_key = self.config.get('SECRET_KEY', '')
        if len(secret_key) < self.MIN_SECRET_KEY_LENGTH:
            self.errors.append(
                f"SECRET_KEY is too short ({len(secret_key)} chars). "
                f"Minimum required: {self.MIN_SECRET_KEY_LENGTH} chars. "
                "Use a secure random value (e.g., os.urandom(32).hex())"
            )
        
        # Check if using default SECRET_KEY
        if secret_key == 'develop':
            self.warnings.append(
                "Using default SECRET_KEY 'develop'. This is insecure for production. "
                "Set a secure random value in production."
            )
        
        # Check admin password from ini config
        admin_password = self.ini_config.get('security', {}).get('admin_password', '')
        if admin_password and len(admin_password) < self.MIN_ADMIN_PASSWORD_LENGTH:
            self.errors.append(
                f"Admin password is too short ({len(admin_password)} chars). "
                f"Minimum required: {self.MIN_ADMIN_PASSWORD_LENGTH} chars"
            )
        
        # Check for default admin password
        if admin_password == 'admin':
            self.warnings.append(
                "Using default admin password 'admin'. This is a security risk. "
                "Change the admin password immediately in production."
            )
        
        # Check SESSION_COOKIE_SECURE in production
        if self.config.get('ENV') == 'production':
            if not self.config.get('SESSION_COOKIE_SECURE', False):
                self.errors.append(
                    "SESSION_COOKIE_SECURE must be True in production"
                )
            if not self.config.get('REMEMBER_COOKIE_SECURE', False):
                self.errors.append(
                    "REMEMBER_COOKIE_SECURE must be True in production"
                )
    
    def validate_database_config(self) -> None:
        """Validate database configuration."""
        db_uri = self.config.get('SQLALCHEMY_DATABASE_URI', '')
        
        if not db_uri:
            self.errors.append("SQLALCHEMY_DATABASE_URI is required")
            return
        
        # Check database URI pattern
        is_valid = any(
            re.match(pattern, db_uri) 
            for pattern in self.VALID_DATABASE_PATTERNS
        )
        if not is_valid:
            self.errors.append(
                f"Invalid database URI format: {db_uri}. "
                f"Must start with one of: {', '.join(self.VALID_DATABASE_PATTERNS)}"
            )
        
        # Warn about SQLite in production
        if db_uri.startswith('sqlite:///') and self.config.get('ENV') == 'production':
            self.warnings.append(
                "Using SQLite database in production. Consider using PostgreSQL for production deployments."
            )
    
    def validate_cache_config(self) -> None:
        """Validate cache configuration."""
        cache_config = self.ini_config.get('remote_cache', {})
        
        redis_enabled = cache_config.get('redis_enabled', 'false').lower() == 'true'
        
        if redis_enabled:
            # Check Redis configuration
            redis_host = cache_config.get('redis_host', '')
            redis_port = cache_config.get('redis_port', '')
            
            if not redis_host:
                self.errors.append("Redis enabled but redis_host is not configured")
            
            if not redis_port:
                self.errors.append("Redis enabled but redis_port is not configured")
            
            # Warn about Redis password
            redis_password = cache_config.get('redis_password', '')
            if not redis_password:
                self.warnings.append(
                    "Redis enabled but no password configured. "
                    "Consider setting a password for Redis authentication."
                )
    
    def validate_sso_config(self) -> None:
        """Validate SSO/OAuth2 configuration if enabled."""
        sso_config = self.ini_config.get('sso_settings', {})
        
        # Check if SSO is enabled
        sso_enabled = self.ini_config.get('authentication', {}).get('sso_enabled', 'false').lower() == 'true'
        
        if sso_enabled:
            # Validate required SSO settings
            client_id = sso_config.get('client_id', '')
            client_secret = sso_config.get('secret', '')
            issuer_url = sso_config.get('issuer_url', '')
            
            if not client_id:
                self.errors.append("SSO enabled but client_id is not configured")
            
            if not client_secret:
                self.errors.append("SSO enabled but client_secret is not configured")
            
            if not issuer_url:
                self.errors.append("SSO enabled but issuer_url is not configured")
            
            # Warn about client_secret in development
            if client_secret and self.config.get('ENV') == 'development':
                self.warnings.append(
                    "SSO client_secret is configured in development mode. "
                    "Ensure you're using development credentials."
                )
    
    def validate_environment_vars(self) -> None:
        """Validate important environment variables."""
        # Check for KUBEDASH_ENV in production
        if self.config.get('ENV') == 'production':
            if not os.getenv('KUBEDASH_ENV'):
                self.warnings.append(
                    "Running in production mode but KUBEDASH_ENV is not set. "
                    "Consider setting KUBEDASH_ENV=production for clarity."
                )
            
            # Check for KUBEDASH_VERSION
            if not os.getenv('KUBEDASH_VERSION'):
                self.warnings.append(
                    "KUBEDASH_VERSION environment variable not set. "
                    "Consider setting it for better version tracking."
                )


def validate_config(config: Dict[str, Any], ini_config: Optional[Dict[str, Any]] = None) -> bool:
    """Validate KubeDash configuration.
    
    This is the main entry point for configuration validation.
    
    Args:
        config: Flask app configuration dictionary
        ini_config: Configuration from kubedash.ini (optional)
        
    Returns:
        bool: True if validation passes
        
    Raises:
        ConfigurationError: If validation fails
    """
    validator = ConfigValidator(config, ini_config)
    return validator.validate_all()
