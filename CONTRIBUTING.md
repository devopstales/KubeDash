# Contributing to KubeDash

Thank you for your interest in contributing to KubeDash! This guide will help you get started with development and contributions.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Code Style](#code-style)
- [Testing](#testing)
- [Making Contributions](#making-contributions)
- [Pull Request Process](#pull-request-process)
- [Reporting Issues](#reporting-issues)

## Code of Conduct

Please be respectful and constructive in your interactions. We welcome contributors of all backgrounds and experience levels.

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/kubedash.git
   cd kubedash
   ```
3. **Add upstream remote**:
   ```bash
   git remote add upstream https://github.com/devopstales/kubedash.git
   ```

## Development Setup

### Prerequisites

- Python 3.12 or higher
- Poetry (dependency management)
- Node.js 18+ (optional, for frontend development)
- Kubernetes cluster (for integration testing)
- kubectl configured to access your cluster

### Install Dependencies

```bash
# Install Poetry if not already installed
curl -sSL https://install.python-poetry.org | python3 -

# Install dependencies
cd src/kubedash
poetry install --with dev,test

# Install Playwright browsers (for browser tests)
poetry run playwright install
```

### Configuration

```bash
# Copy example configuration
cp kubedash.ini.example kubedash.ini

# Edit configuration for your environment
# Required settings:
# - SECRET_KEY (minimum 32 characters)
# - SQLALCHEMY_DATABASE_URI
# - Admin password (minimum 8 characters)
```

### Running the Application

```bash
# Development mode
poetry run python kubedash.py

# Or using gunicorn
poetry run gunicorn kubedash:app -b 0.0.0.0:8000 --reload
```

### Running Database Migrations

```bash
# Initialize database
poetry run python kubedash.py db

# Or using alembic directly
poetry run alembic upgrade head
```

## Code Style

### Python

We use the following tools for code quality:

- **Black** - Code formatting
- **isort** - Import sorting
- **flake8** - Linting
- **mypy** - Type checking (optional)

```bash
# Format code
poetry run black .
poetry run isort .

# Check code quality
poetry run flake8 .
poetry run mypy .  # Optional
```

### Configuration

Our code style settings are in `pyproject.toml`:

```toml
[tool.black]
line-length = 100
target-version = ['py312']

[tool.isort]
profile = "black"
line_length = 100
```

### Best Practices

1. **Write docstrings** for all public functions and classes
2. **Use type hints** where possible
3. **Follow PEP 8** style guidelines
4. **Keep functions small** and focused
5. **Write tests** for new functionality

## Testing

### Running Tests

```bash
# Run all tests
./run_test.sh -c -o html

# Or using pytest directly
poetry run pytest tests/ -v

# Run specific test category
poetry run pytest tests/unit/ -v
poetry run pytest tests/integration/ -v
poetry run pytest tests/security/ -v

# Run with coverage
poetry run pytest tests/ --cov=kubedash --cov-report=html
```

### Writing Tests

```python
# tests/unit/test_example.py
import pytest

def test_example():
    """Example test."""
    assert True

@pytest.fixture
def sample_data():
    """Fixture for test data."""
    return {"key": "value"}

def test_with_fixture(sample_data):
    """Test using fixture."""
    assert sample_data["key"] == "value"
```

### Test Categories

- **Unit Tests** (`tests/unit/`) - Test individual functions and classes
- **Integration Tests** (`tests/integration/`) - Test component interactions
- **Security Tests** (`tests/security/`) - OWASP security testing
- **Functional Tests** (`tests/functional/`) - End-to-end testing

## Making Contributions

### Types of Contributions

1. **Bug Fixes** - Always welcome!
2. **New Features** - Please discuss in an issue first
3. **Documentation** - Improvements to docs, examples, guides
4. **Tests** - Additional test coverage
5. **Performance Improvements** - Optimizations and benchmarks

### Finding Issues

Look for issues labeled:
- `good first issue` - Good for newcomers
- `help wanted` - Need community help
- `bug` - Bug fixes needed
- `enhancement` - New features

### Creating a Branch

```bash
# Update from upstream
git fetch upstream
git checkout main
git merge upstream/main

# Create feature branch
git checkout -b feature/your-feature-name
```

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add new plugin system
fix: resolve database connection issue
docs: update installation guide
test: add integration tests for API
refactor: improve error handling
chore: update dependencies
```

## Pull Request Process

1. **Create a feature branch** from `main`
2. **Make your changes** with tests
3. **Run tests and linting**:
   ```bash
   ./run_test.sh -c
   poetry run black .
   poetry run isort .
   poetry run flake8 .
   ```
4. **Update documentation** if needed
5. **Submit PR** with clear description
6. **Address review feedback**
7. **Squash commits** if requested

### PR Checklist

- [ ] Tests added/updated
- [ ] Documentation updated
- [ ] Code follows style guidelines
- [ ] All tests pass
- [ ] Changes are backwards compatible (or breaking changes documented)

## Reporting Issues

### Bug Reports

Include:
- **Description** - Clear description of the issue
- **Steps to Reproduce** - Exact steps to reproduce
- **Expected Behavior** - What should happen
- **Actual Behavior** - What actually happens
- **Environment** - Python version, OS, KubeDash version
- **Logs** - Relevant error logs

### Feature Requests

Include:
- **Problem Statement** - What problem does this solve?
- **Proposed Solution** - How should it work?
- **Use Cases** - Who will use this and how?
- **Alternatives** - What alternatives exist?

## Documentation

### Building Documentation

```bash
# Install docs dependencies
cd src/kubedash
poetry install --with docs

# Build documentation
./run_mkdocs.sh

# View locally
mkdocs serve
```

### Documentation Structure

```
docs/
├── contributing.md      # Contributor guide (this doc lives in docs/)
├── development/         # Developer guides
│   ├── plugin-development.md
│   ├── extension-api-reference.md
│   ├── extension-api-examples.md
│   └── ...
├── plugins/             # Plugin reference docs
│   ├── README.md
│   ├── helm.md
│   └── ...
└── ...
```

## Getting Help

- **GitHub Issues** - For bugs and feature requests
- **Discussions** - For questions and general discussion
- **Documentation** - Check existing docs first

## Recognition

Contributors will be recognized in:
- CHANGELOG.md
- README.md (Contributors section)
- Release notes

Thank you for contributing to KubeDash!
