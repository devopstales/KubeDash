"""
SQL Injection Prevention Utilities

This module provides utilities to ensure all database queries are safe from SQL injection.
All database operations should use SQLAlchemy ORM methods which automatically use
parameterized queries.

DO NOT use raw SQL queries with user input. Always use ORM methods.
"""

from typing import Any, Optional
from sqlalchemy import text
from lib.components import db
from lib.helper_functions import get_logger

logger = get_logger()


def safe_query_filter(model_class, **filters):
    """
    Safely filter a model using keyword arguments.
    This is a wrapper that ensures all filters use parameterized queries.
    
    Args:
        model_class: SQLAlchemy model class
        **filters: Keyword arguments to filter by (e.g., username='test')
    
    Returns:
        Query object that can be further chained
    
    Example:
        users = safe_query_filter(User, username='test', user_type='Local')
        user = users.first()
    """
    query = model_class.query
    for key, value in filters.items():
        if value is not None:
            # Use filter_by which automatically uses parameterized queries
            query = query.filter_by(**{key: value})
    return query


def safe_text_query(sql: str, params: Optional[dict] = None):
    """
    Execute a raw SQL query safely using parameterized queries.
    
    WARNING: Only use this for queries that cannot be expressed with ORM.
    Prefer ORM methods whenever possible.
    
    Args:
        sql: SQL query string with :param_name placeholders
        params: Dictionary of parameters to bind
    
    Returns:
        Query result
    
    Example:
        result = safe_text_query(
            "SELECT * FROM users WHERE username = :username",
            {"username": user_input}
        )
    """
    if params is None:
        params = {}
    
    # Verify SQL doesn't contain user input directly
    # Check for common injection patterns
    dangerous_patterns = [';', '--', '/*', '*/', 'xp_', 'sp_', 'exec', 'execute']
    sql_lower = sql.lower()
    for pattern in dangerous_patterns:
        if pattern in sql_lower and pattern not in ['execute']:  # 'execute' is in our function name
            logger.warning(f"Potential SQL injection pattern detected in query: {pattern}")
    
    # Use text() with bindparams for parameterized queries
    return db.session.execute(text(sql), params)


def validate_sql_input(value: Any, max_length: Optional[int] = None) -> str:
    """
    Validate and sanitize input before using in database queries.
    
    Note: This is a secondary defense. SQLAlchemy ORM already protects against
    SQL injection, but this adds an extra layer of validation.
    
    Args:
        value: Input value to validate
        max_length: Maximum allowed length
    
    Returns:
        Validated string value
    
    Raises:
        ValueError: If input is invalid
    """
    if value is None:
        return None
    
    # Convert to string
    str_value = str(value)
    
    # Check length
    if max_length and len(str_value) > max_length:
        raise ValueError(f"Input exceeds maximum length of {max_length}")
    
    # Check for SQL injection patterns (secondary defense)
    # Note: SQLAlchemy ORM already protects, but this adds extra validation
    dangerous_patterns = [
        ';',  # Statement terminator
        '--',  # SQL comment
        '/*', '*/',  # Multi-line comment
        'xp_', 'sp_',  # SQL Server stored procedures
        'union',  # UNION injection
        'select',  # SELECT injection (in some contexts)
    ]
    
    value_lower = str_value.lower()
    for pattern in dangerous_patterns:
        if pattern in value_lower:
            # Allow if it's part of a legitimate word (e.g., "selection")
            # Only flag if it's a standalone SQL keyword
            import re
            if re.search(r'\b' + re.escape(pattern) + r'\b', value_lower):
                logger.warning(f"Potential SQL injection pattern detected: {pattern}")
                # Don't raise error - SQLAlchemy ORM will handle it safely
                # This is just for logging/monitoring
    
    return str_value


def safe_get_by_id(model_class, id_value: int):
    """
    Safely get a record by ID.
    
    Args:
        model_class: SQLAlchemy model class
        id_value: ID value (must be integer)
    
    Returns:
        Model instance or None
    """
    if not isinstance(id_value, int):
        raise ValueError("ID must be an integer")
    
    return model_class.query.get(id_value)


def safe_filter_by_username(model_class, username: str):
    """
    Safely filter by username using parameterized query.
    
    Args:
        model_class: SQLAlchemy model class with username attribute
        username: Username to search for
    
    Returns:
        Query result
    """
    # Validate username
    validated_username = validate_sql_input(username, max_length=80)
    
    # Use filter_by which uses parameterized queries
    return model_class.query.filter_by(username=validated_username)


# Best practices checklist:
# ✅ Always use ORM methods: Model.query.filter_by(), Model.query.filter()
# ✅ Use parameterized queries with text(): text("SELECT * FROM users WHERE id = :id", {"id": user_id})
# ❌ Never use string formatting: f"SELECT * FROM users WHERE id = {user_id}"
# ❌ Never use % formatting: "SELECT * FROM users WHERE id = %s" % user_id
# ❌ Never concatenate user input: "SELECT * FROM users WHERE username = '" + username + "'"

