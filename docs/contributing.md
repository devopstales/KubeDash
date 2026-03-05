# Contributing to KubeDash

This document provides detailed information for contributors to the KubeDash project.

> **Note:** This is the detailed contributor guide. For a quick start, see [CONTRIBUTING.md](../CONTRIBUTING.md) in the project root.

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Development Environment](#development-environment)
- [Project Structure](#project-structure)
- [Component Documentation](#component-documentation)
- [Development Workflows](#development-workflows)
- [Testing Guidelines](#testing-guidelines)
- [Documentation Guidelines](#documentation-guidelines)
- [Release Process](#release-process)

## Architecture Overview

KubeDash follows a three-layer architecture:

```
┌─────────────────────────────────────────┐
│         UI Routes (blueprint/)          │  # HTML rendering
└─────────────────┬───────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────┐
│       REST API (blueprint/api/)         │  # JSON responses
└─────────────────┬───────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────┐
│    K8s Wrappers (lib/k8s/)              │  # Pure K8s client
└─────────────────┬───────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────┐
│    Kubernetes API                       │
└─────────────────────────────────────────┘
```

### Key Components

| Component | Location | Description |
|-----------|----------|-------------|
| UI Routes | `blueprint/` | Flask blueprints for HTML pages |
| REST API | `blueprint/api/` | MethodView-based REST endpoints |
| K8s Wrappers | `lib/k8s/` | Pure Kubernetes client wrappers |
| Plugins | `plugins/` | Extendable plugin system |
| Initializers | `lib/initializers/` | Application initialization |

## Development Environment

### Required Tools

```bash
# Python 3.12+
python --version

# Poetry
poetry --version

# Git
git --version

# kubectl (for integration testing)
kubectl version --client
```

### Optional Tools

```bash
# Node.js (for frontend development)
node --version
npm --version

# Docker (for container testing)
docker --version

# Helm (for Helm chart development)
helm version
```

### IDE Setup

**VS Code Recommended Extensions:**
- Python (ms-python.python)
- Black Formatter (ms-python.black-formatter)
- isort (ms-python.isort)
- Flake8 (ms-python.flake8)
- Jinja (wholroyd.jinja-html)

**VS Code Settings** (`.vscode/settings.json`):
```json
{
    "python.formatting.provider": "black",
    "python.formatting.blackArgs": ["--line-length", "100"],
    "python.sortImports.args": ["--profile", "black", "--line-length", "100"],
    "python.linting.flake8Enabled": true,
    "python.linting.flake8Args": ["--max-line-length=100"],
    "[python]": {
        "editor.defaultFormatter": "ms-python.black-formatter",
        "editor.formatOnSave": true,
        "editor.codeActionsOnSave": {
            "source.organizeImports": true
        }
    }
}
```

## Project Structure

```
kubedash/
├── CONTRIBUTING.md          # Contribution guidelines
├── README.md                # Project overview
├── Taskfile.yml             # Task definitions
├── mkdocs.yml               # MkDocs configuration
├── docs/                    # Documentation
│   ├── contributing.md      # This file
│   ├── development/        # Developer guides (plugin-development, extension-api-reference, etc.)
│   ├── plugins/             # Plugin documentation
│   └── ...
├── src/kubedash/            # Main source code
│   ├── kubedash.py          # Application entry point
│   ├── blueprint/           # Flask blueprints
│   ├── lib/                 # Core library
│   ├── plugins/             # Plugins
│   ├── templates/           # Jinja2 templates
│   ├── static/              # Static assets
│   ├── tests/               # Test suite
│   ├── migrations/          # Database migrations
│   └── pyproject.toml       # Project configuration
└── deploy/                  # Deployment manifests
    ├── kubernetes/
    └── docker/
```

## Component Documentation

### Blueprints

Each blueprint follows a standard structure:

```
blueprint/<name>/
├── __init__.py      # Blueprint registration
└── <name>.py        # Routes and handlers
```

Example:
```python
# blueprint/example/__init__.py
from blueprint.example.example import example_bp

__all__ = ['example_bp']

# blueprint/example/example.py
from flask import Blueprint, render_template

example_bp = Blueprint("example", __name__, url_prefix="/example")

@example_bp.route('/')
def index():
    return render_template('example/index.html.j2')
```

### Library Modules

Library modules should:
- Have NO Flask dependencies (for reusability)
- Include comprehensive docstrings
- Use type hints
- Handle errors gracefully

### Plugins

See [Plugin Development Guide](development/plugin-development.md) for detailed plugin development instructions.

## Development Workflows

### Feature Development

1. **Create branch:**
   ```bash
   git checkout -b feature/my-feature
   ```

2. **Make changes** with tests

3. **Run checks:**
   ```bash
   # Format
   poetry run black .
   poetry run isort .
   
   # Lint
   poetry run flake8 .
   
   # Test
   poetry run pytest tests/ -v
   ```

4. **Commit:**
   ```bash
   git add .
   git commit -m "feat: add my feature"
   ```

### Bug Fix Workflow

1. **Create branch:**
   ```bash
   git checkout -b fix/issue-123
   ```

2. **Add test** that reproduces the bug

3. **Fix the bug**

4. **Verify test passes**

5. **Commit:**
   ```bash
   git commit -m "fix: resolve issue #123"
   ```

### Database Migration Workflow

1. **Make model changes** in your code

2. **Generate migration:**
   ```bash
   poetry run alembic revision --autogenerate -m "description"
   ```

3. **Review migration** in `migrations/versions/`

4. **Add context header:**
   ```python
   """description
   
   Revision ID: abc123
   Revises: def456
   Create Date: 2024-01-01 00:00:00.000000
   
   Related Issue: #123
   Related PR: #456
   """
   ```

5. **Test migration:**
   ```bash
   poetry run alembic upgrade head
   poetry run alembic downgrade -1
   poetry run alembic upgrade head
   ```

## Testing Guidelines

### Test Categories

| Category | Location | Purpose |
|----------|----------|---------|
| Unit | `tests/unit/` | Test individual functions |
| Integration | `tests/integration/` | Test component interactions |
| Security | `tests/security/` | OWASP security testing |
| Functional | `tests/functional/` | End-to-end testing |

### Writing Unit Tests

```python
# tests/unit/test_example.py
import pytest
from lib.example import example_function

def test_example_function():
    """Test example function."""
    result = example_function("input")
    assert result == "expected"

@pytest.fixture
def sample_data():
    """Provide sample data for tests."""
    return {"key": "value"}

def test_with_fixture(sample_data):
    """Test using fixture."""
    assert sample_data["key"] == "value"
```

### Writing Integration Tests

```python
# tests/integration/test_api.py
import pytest
import json

def test_api_endpoint(client, logged_in_client):
    """Test API endpoint."""
    # Anonymous should redirect
    response = client.get('/api/v1/example')
    assert response.status_code == 302
    
    # Logged in should work
    response = logged_in_client.get('/api/v1/example')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'items' in data
```

### Running Tests

```bash
# All tests
./run_test.sh -c -o html

# Specific test file
poetry run pytest tests/unit/test_example.py -v

# Test with coverage
poetry run pytest tests/ --cov=kubedash --cov-report=html

# Security tests
poetry run pytest tests/security/ -v
```

## Documentation Guidelines

### Code Documentation

```python
def example_function(param1: str, param2: int = 10) -> bool:
    """
    One-line description.
    
    Longer description if needed.
    
    Args:
        param1: Description of param1
        param2: Description of param2 (default: 10)
    
    Returns:
        bool: Description of return value
    
    Raises:
        ValueError: When param1 is invalid
    
    Example:
        >>> example_function("test", 20)
        True
    """
    pass
```

### Documentation Files

- Use Markdown format
- Include code examples
- Link to related documentation
- Keep examples up-to-date

### Building Documentation

```bash
# Build docs
./run_mkdocs.sh

# Serve locally
mkdocs serve

# Open in browser
open http://localhost:8000
```

## Release Process

### Version Numbering

KubeDash follows [Semantic Versioning](https://semver.org/):

- **MAJOR** - Breaking changes
- **MINOR** - New features (backwards compatible)
- **PATCH** - Bug fixes (backwards compatible)

### Release Checklist

1. **Update version** in `pyproject.toml`
2. **Update CHANGELOG.md** with changes
3. **Run all tests** and verify passing
4. **Build documentation** and verify
5. **Create release tag:**
   ```bash
   git tag -a v1.2.3 -m "Release v1.2.3"
   git push origin v1.2.3
   ```
6. **Create GitHub release** with changelog
7. **Publish to PyPI** (if applicable)

## Getting Help

- **GitHub Issues** - Bugs and feature requests
- **GitHub Discussions** - Questions and discussions
- **Documentation** - [docs/](.) folder

## Recognition

Contributors are recognized in:
- [CHANGELOG.md](../CHANGELOG.md)
- [README.md](../README.md)
- Release notes

Thank you for contributing to KubeDash!
