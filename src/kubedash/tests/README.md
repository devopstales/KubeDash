# KubeDash Test Suite

This directory contains automated tests for KubeDash. The test suite includes unit tests, integration tests, and functional tests.

## Test Structure

```
tests/
├── conftest.py              # Shared pytest fixtures
├── unit/                     # Unit tests
│   ├── test_k8s_namespace.py
│   ├── test_cache.py
│   ├── test_helper_functions.py
│   ├── test_extension_api_functions.py
│   └── user_test.py
├── integration/             # Integration tests
│   ├── test_auth_integration.py
│   ├── test_api_endpoints.py
│   ├── test_user_management.py
│   ├── test_database_integration.py
│   └── test_extension_api.py
├── functional/              # Functional/E2E tests
│   ├── health_test.py
│   ├── page_test.py
│   └── playwright_test.py
└── security/                 # Security tests
    ├── test_sql_injection.py
    ├── test_xss_prevention.py
    ├── test_csrf_protection.py
    ├── test_authentication_security.py
    ├── test_authorization_security.py
    ├── test_security_headers.py
    ├── test_input_validation.py
    ├── test_api_security.py
    ├── test_pynt_api_security.py
    ├── test_dependency_security.py
```

## Running Tests

### Install Dependencies

```bash
cd src/kubedash

# Using poetry (recommended)
poetry install --with test
poetry run playwright install

# Or using pip
pip install -r tests/requirements.txt
```

### Using the Test Runner Script (Recommended)

A convenient test runner script is provided:

```bash
# Run all tests
./run_test.sh

# Run specific test categories
./run_test.sh -t unit              # Unit tests only
./run_test.sh -t integration       # Integration tests only
./run_test.sh -t functional        # Functional tests only
./run_test.sh -t security          # Security tests only

# Run with coverage
./run_test.sh -c                   # Coverage with terminal report
./run_test.sh -c -o html           # Coverage with HTML report
./run_test.sh -c -o xml            # Coverage with XML report

# Run in parallel
./run_test.sh -p                   # Run tests in parallel

# Verbose output
./run_test.sh -v                   # Verbose output

# Combine options
./run_test.sh -t integration -c -o html -v

# Run with markers
./run_test.sh -m "not slow"        # Exclude slow tests

# Docker container management
./run_test.sh -d                   # Start docker containers before tests
./run_test.sh -d -D                # Start docker, run tests, then stop docker
./run_test.sh -D                   # Run tests and stop docker containers after

# Security tests and scans
./run_test.sh -t security          # Run security tests only
./run_test.sh -s                   # Run security scans (semgrep, safety, pip-audit)
./run_test.sh -t security -s       # Run security tests and scans

# Show help
./run_test.sh -h
```

### Using Poetry Directly

```bash
# Run all tests
poetry run pytest tests/

# Run specific test categories
poetry run pytest tests/unit/      # Unit tests only
poetry run pytest tests/integration/  # Integration tests only
poetry run pytest tests/functional/   # Functional tests only

# Run with coverage
poetry run pytest --cov=. --cov-report=html --cov-report=term tests/

# Run specific test file
poetry run pytest tests/unit/test_k8s_namespace.py

# Run with verbose output
poetry run pytest -v tests/
```

### Using Pytest Directly

If you have dependencies installed via pip:

```bash
# Run all tests
pytest tests/

# Run specific test categories
pytest tests/unit/
pytest tests/integration/
pytest tests/functional/

# Run with coverage
pytest --cov=. --cov-report=html --cov-report=term tests/
```

## Test Categories

### Unit Tests

Unit tests test individual functions and classes in isolation, using mocks where necessary.

- **test_k8s_namespace.py**: Tests Kubernetes namespace operations with mocked K8s API
- **test_cache.py**: Tests caching decorator functionality
- **test_helper_functions.py**: Tests utility functions
- **user_test.py**: Tests user management functions

### Integration Tests

Integration tests test how multiple components work together.

- **test_auth_integration.py**: Tests authentication flow (login, logout, session management)
- **test_api_endpoints.py**: Tests REST API endpoints (health, ping, API v1)
- **test_user_management.py**: Tests user CRUD operations
- **test_database_integration.py**: Tests database operations and relationships
- **test_extension_api.py**: Tests Kubernetes Extension API endpoints

### Functional Tests

Functional tests test end-to-end user workflows.

- **health_test.py**: Tests health check endpoints
- **page_test.py**: Tests page rendering
- **playwright_test.py**: Browser-based E2E tests

## Test Fixtures

The `conftest.py` file provides several useful fixtures:

- `app`: Flask application instance configured for testing
- `client`: Flask test client
- `session`: Database session with transaction rollback
- `authenticated_client`: Test client with authenticated session
- `admin_user`: Admin user fixture
- `regular_user`: Regular user fixture

## Writing New Tests

### Unit Test Example

```python
import pytest
from unittest.mock import patch, MagicMock

def test_my_function():
    """Test description"""
    # Arrange
    mock_value = MagicMock()
    
    # Act
    result = my_function(mock_value)
    
    # Assert
    assert result == expected_value
```

### Integration Test Example

```python
import pytest

def test_api_endpoint(client):
    """Test API endpoint"""
    response = client.get('/api/endpoint')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'expected_field' in data
```

## Test Configuration

### Poetry Test Group

Test dependencies are managed in a separate Poetry group:

```bash
# Install test dependencies
poetry install --with test

# Add test dependency
poetry add --group test pytest-cov

# Remove test dependency
poetry remove --group test pytest-cov
```

### Pytest Configuration

Test configuration is in `pyproject.toml`:

```toml
[tool.pytest.ini_options]
log_cli = true
filterwarnings = [
    "ignore::urllib3.exceptions.InsecureRequestWarning",
    "ignore::DeprecationWarning",
    "ignore::sqlalchemy.exc.SAWarning",
]
pythonpath = "."
testpaths = ["tests"]
```

### Coverage Configuration

Coverage settings are also in `pyproject.toml`:

```toml
[tool.coverage.run]
branch = true
source = ["blueprint", "lib", "plugins"]
omit = ["tests/*", "migrations/*", "__pycache__/*"]

[tool.coverage.report]
exclude_lines = [
    "pragma: no cover",
    "def __repr__",
    "raise NotImplementedError",
]
fail_under = 70
```

## Security Testing

KubeDash includes comprehensive security tests to ensure the application is protected against common vulnerabilities:

### Security Test Categories

1. **SQL Injection Prevention** (`tests/security/test_sql_injection.py`)
   - Tests that user inputs are properly parameterized
   - Verifies SQLAlchemy ORM prevents injection attacks
   - Tests UNION-based and other injection techniques

2. **XSS Prevention** (`tests/security/test_xss_prevention.py`)
   - Tests that user inputs are properly escaped in HTML
   - Verifies Content Security Policy headers
   - Tests XSS payload filtering

3. **CSRF Protection** (`tests/security/test_csrf_protection.py`)
   - Tests that CSRF tokens are required for state-changing operations
   - Verifies CSRF exemption for API endpoints
   - Tests CSRF token validation

4. **Authentication Security** (`tests/security/test_authentication_security.py`)
   - Tests authentication bypass prevention
   - Verifies password hashing (scrypt)
   - Tests session security (HttpOnly, Secure cookies)
   - Tests brute force protection

5. **Authorization Security** (`tests/security/test_authorization_security.py`)
   - Tests privilege escalation prevention
   - Verifies role-based access control
   - Tests namespace access restrictions

6. **Security Headers** (`tests/security/test_security_headers.py`)
   - Tests HTTP security headers (CSP, HSTS, X-Frame-Options, etc.)
   - Verifies CORS configuration
   - Tests header presence and values

7. **Input Validation** (`tests/security/test_input_validation.py`)
   - Tests input sanitization
   - Verifies path traversal prevention
   - Tests command injection prevention

8. **API Security** (`tests/security/test_api_security.py`)
   - Tests API endpoints for OWASP API Security Top 10 vulnerabilities
   - Authentication and authorization testing
   - Input validation and injection prevention
   - Data exposure prevention
   - Rate limiting verification
   - Security headers validation

9. **Pynt API Security** (`tests/security/test_pynt_api_security.py`)
   - Pynt-style comprehensive API security testing
   - Structured test results and reporting
   - Focus on API-specific security issues
   - Authentication, input validation, data exposure tests

10. **Dependency Security** (`tests/security/test_dependency_security.py`)
    - Tests for known vulnerabilities in dependencies
    - Uses `safety` and `pip-audit` for scanning
    - Static code analysis with `semgrep`

### Running Security Tests

```bash
# Run all security tests
./run_test.sh -t security

# Run security tests with coverage
./run_test.sh -t security -c

# Run security scans (semgrep, safety, pip-audit)
./run_test.sh -s

# Run security tests and scans together
./run_test.sh -t security -s
```

### Security Scanning Tools

The test suite includes integration with security scanning tools:

- **Semgrep**: Static code analysis for security issues (replaces Bandit)
- **Safety**: Checks for known vulnerabilities in dependencies
- **pip-audit**: Alternative dependency vulnerability scanner

These tools are run automatically when using the `-s` flag or can be run manually:

```bash
# Run Semgrep (with B101/B601 exclusions; paths in .semgrepignore)
poetry run semgrep --config=auto \
  --exclude-rule python.lang.security.audit.assert_used.assert_used \
  --exclude-rule python.lang.security.audit.subprocess-shell-true.subprocess-shell-true .

# Run Safety
poetry run safety check

# Run pip-audit
poetry run pip-audit
```

### Security Test Configuration

Security tests are configured in:
- `pyproject.toml` - dev/test dependencies (semgrep)
- `.semgrepignore` - path exclusions (tests, migrations, venv, etc.)
- CLI `--exclude-rule` - rule exclusions (assert_used, subprocess-shell-true, matching former Bandit B101/B601)
- Test files use environment variables for optional slow scans:
  - `RUN_DEPENDENCY_SCANS=true` - Enable dependency vulnerability scans
  - `RUN_STATIC_ANALYSIS=true` - Enable static code analysis

## Notes

- Tests use an in-memory SQLite database for isolation
- CSRF protection is disabled in test mode
- Kubernetes API calls are mocked in unit tests
- Integration tests may require a running Kubernetes cluster (optional)
- Security tests verify protection mechanisms are in place

### Configuration File Usage

Tests **do use values from `kubedash.ini`** if the file exists in the `src/kubedash/` directory. The configuration is loaded during app initialization and affects:

- **Redis/Cache settings** (`[remote_cache]` section)
- **Jaeger/Tracing settings** (`[monitoring]` section)
- **Plugin settings** (`[plugin_settings]` section)
- **Kubernetes settings** (`[k8s]` section)
- **SSO settings** (`[sso_settings]` section)
- **Application links** (`[application_list]` section)

**Important exception**: The database type is **always forced to SQLite** for testing mode, regardless of what's configured in `kubedash.ini`. This ensures test isolation and prevents tests from affecting production/development databases.

If `kubedash.ini` doesn't exist, the app uses default values suitable for testing:
- Redis disabled (falls back to in-memory cache)
- Jaeger disabled
- All plugins enabled by default
- SQLite database at `database/testing.db`

To ensure consistent test behavior, you can:
1. Use `kubedash.ini.example` as a template and customize for testing
2. Create a `kubedash.ini.test` file and copy it before running tests
3. Rely on the default values (recommended for CI/CD)

## Continuous Integration

Tests are run automatically in CI/CD pipelines. See `.github/workflows/` for workflow definitions.

