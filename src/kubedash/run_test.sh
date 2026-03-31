#!/bin/bash

# KubeDash Test Runner Script
# This script runs the test suite with various options

# Don't exit on error for docker operations - we want to run tests even if docker fails
set +e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default values
TEST_TYPE="all"
COVERAGE=false
VERBOSE=false
PARALLEL=false
MARKERS=""
OUTPUT_FORMAT=""
DOCKER_START=false
DOCKER_STOP=false
SECURITY_SCAN=false

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Function to print usage
usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Run KubeDash test suite

OPTIONS:
    -t, --type TYPE          Test type: all, unit, integration, functional, security (default: all)
    -c, --coverage           Run tests with coverage report
    -v, --verbose            Verbose output
    -p, --parallel           Run tests in parallel
    -m, --marker MARKER      Run tests with specific marker (e.g., -m "not slow")
    -o, --output FORMAT      Output format: html, xml, term (default: term)
    -d, --docker-start       Start docker containers before running tests
    -D, --docker-stop        Stop docker containers after running tests
    -s, --security-scan      Run security scans (semgrep, safety, pip-audit)
    -h, --help               Show this help message

EXAMPLES:
    $0                                    # Run all tests
    $0 -t unit                           # Run only unit tests
    $0 -t integration -c                  # Run integration tests with coverage
    $0 -c -o html                        # Run all tests with HTML coverage report
    $0 -p -v                             # Run tests in parallel with verbose output
    $0 -m "not slow"                     # Run tests excluding slow ones
    $0 -d                                # Start docker containers and run tests
    $0 -d -D                             # Start docker, run tests, then stop docker
    $0 -D                                # Run tests and stop docker containers after
    $0 -t security                      # Run security tests only
    $0 -s                                # Run security scans (semgrep, safety, pip-audit)
    $0 -t security -s                   # Run security tests and scans

EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -t|--type)
            TEST_TYPE="$2"
            shift 2
            ;;
        -c|--coverage)
            COVERAGE=true
            shift
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -p|--parallel)
            PARALLEL=true
            shift
            ;;
        -m|--marker)
            MARKERS="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_FORMAT="$2"
            shift 2
            ;;
        -d|--docker-start)
            DOCKER_START=true
            shift
            ;;
        -D|--docker-stop)
            DOCKER_STOP=true
            shift
            ;;
        -s|--security-scan)
            SECURITY_SCAN=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            usage
            exit 1
            ;;
    esac
done

# Check if poetry is available
if ! command -v poetry &> /dev/null; then
    echo -e "${RED}Error: poetry is not installed or not in PATH${NC}"
    echo "Please install poetry: https://python-poetry.org/docs/#installation"
    exit 1
fi

# Check if task is available (for docker management)
if [ "$DOCKER_START" = true ] || [ "$DOCKER_STOP" = true ]; then
    if ! command -v task &> /dev/null; then
        echo -e "${YELLOW}Warning: task command not found. Docker management requires Taskfile.${NC}"
        echo "Install task: https://taskfile.dev/installation/"
        echo "Skipping docker operations..."
        DOCKER_START=false
        DOCKER_STOP=false
    fi
fi

# Start docker containers if requested
if [ "$DOCKER_START" = true ]; then
    echo -e "${YELLOW}Starting docker containers...${NC}"
    # Go to project root for taskfile (from src/kubedash, go up 2 levels)
    PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
    cd "$PROJECT_ROOT"
    if task docker-up; then
        cd "$SCRIPT_DIR"  # Return to script directory
        echo -e "${GREEN}Docker containers started${NC}"
        echo ""
    else
        cd "$SCRIPT_DIR"  # Return to script directory
        echo -e "${YELLOW}Warning: Failed to start docker containers, continuing with tests...${NC}"
        echo ""
    fi
fi

# Enable exit on error for test execution
set -e

# Check if test dependencies are installed
echo -e "${YELLOW}Checking test dependencies...${NC}"
if ! poetry run pytest --version &> /dev/null; then
    echo -e "${YELLOW}Installing test dependencies...${NC}"
    poetry install --with test
fi

# Build pytest command
PYTEST_CMD="poetry run pytest"

# Add test path based on type
case $TEST_TYPE in
    unit)
        PYTEST_CMD="$PYTEST_CMD tests/unit/"
        ;;
    integration)
        PYTEST_CMD="$PYTEST_CMD tests/integration/"
        ;;
    functional)
        PYTEST_CMD="$PYTEST_CMD tests/functional/"
        ;;
    security)
        # Security tests
        PYTEST_CMD="$PYTEST_CMD tests/security/"
        ;;
    all)
        PYTEST_CMD="$PYTEST_CMD tests/"
        ;;
    *)
        echo -e "${RED}Error: Invalid test type: $TEST_TYPE${NC}"
        echo "Valid types: all, unit, integration, functional, security"
        exit 1
        ;;
esac

# Add verbose flag
if [ "$VERBOSE" = true ]; then
    PYTEST_CMD="$PYTEST_CMD -v"
else
    PYTEST_CMD="$PYTEST_CMD -v"  # Default to verbose
fi

# Add coverage
if [ "$COVERAGE" = true ]; then
    PYTEST_CMD="$PYTEST_CMD --cov=. --cov-report=term"
    
    case $OUTPUT_FORMAT in
        html)
            PYTEST_CMD="$PYTEST_CMD --cov-report=html:reports/coverage_html"
            ;;
        xml)
            PYTEST_CMD="$PYTEST_CMD --cov-report=xml:reports/coverage.xml"
            ;;
        term|"")
            # Already added term above
            ;;
        *)
            PYTEST_CMD="$PYTEST_CMD --cov-report=html:reports/coverage_html --cov-report=xml:reports/coverage.xml"
            ;;
    esac
fi

# Add parallel execution
if [ "$PARALLEL" = true ]; then
    if poetry run pytest --collect-only -q 2>/dev/null | grep -q "pytest-xdist"; then
        PYTEST_CMD="$PYTEST_CMD -n auto"
    else
        echo -e "${YELLOW}Warning: pytest-xdist not installed, running sequentially${NC}"
    fi
fi

# Add markers
if [ -n "$MARKERS" ]; then
    PYTEST_CMD="$PYTEST_CMD -m \"$MARKERS\""
fi

# Create reports directory if coverage is enabled
if [ "$COVERAGE" = true ]; then
    mkdir -p reports
fi

# Run security scans if requested
if [ "$SECURITY_SCAN" = true ]; then
    echo -e "${YELLOW}Running security scans...${NC}"
    echo ""

    # Semgrep static analysis (replaces Bandit)
    if command -v poetry &> /dev/null && poetry run semgrep --version &> /dev/null; then
        echo -e "${YELLOW}Running Semgrep security scan...${NC}"
        # Rule exclusions are now in .semgrepignore (B101/B601 equivalents)
        poetry run semgrep --config=auto \
          --json -o reports/semgrep.json . 2>/dev/null || true
        poetry run semgrep --config=auto \
          . || true
        echo ""
    else
        echo -e "${YELLOW}Semgrep not available, skipping...${NC}"
    fi
    
    # Safety dependency check
    if command -v poetry &> /dev/null && poetry run safety --version &> /dev/null; then
        echo -e "${YELLOW}Running Safety dependency check...${NC}"
        poetry run safety check --json --output reports/safety.json || true
        poetry run safety check || true
        echo ""
    else
        echo -e "${YELLOW}Safety not available, skipping...${NC}"
    fi
    
    # pip-audit dependency check
    if command -v poetry &> /dev/null && poetry run pip-audit --version &> /dev/null; then
        echo -e "${YELLOW}Running pip-audit dependency check...${NC}"
        poetry run pip-audit --format json --output reports/pip-audit.json || true
        poetry run pip-audit || true
        echo ""
    else
        echo -e "${YELLOW}pip-audit not available, skipping...${NC}"
    fi
    
    echo -e "${GREEN}Security scans completed${NC}"
    echo ""
fi

# Print configuration
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}KubeDash Test Runner${NC}"
echo -e "${GREEN}========================================${NC}"
echo -e "Test Type: ${YELLOW}$TEST_TYPE${NC}"
echo -e "Coverage: ${YELLOW}$COVERAGE${NC}"
echo -e "Verbose: ${YELLOW}$VERBOSE${NC}"
echo -e "Parallel: ${YELLOW}$PARALLEL${NC}"
[ -n "$MARKERS" ] && echo -e "Markers: ${YELLOW}$MARKERS${NC}"
[ -n "$OUTPUT_FORMAT" ] && echo -e "Output Format: ${YELLOW}$OUTPUT_FORMAT${NC}"
echo -e "Docker Start: ${YELLOW}$DOCKER_START${NC}"
echo -e "Docker Stop: ${YELLOW}$DOCKER_STOP${NC}"
echo -e "Security Scan: ${YELLOW}$SECURITY_SCAN${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# Run tests
echo -e "${YELLOW}Running tests...${NC}"
echo -e "Command: ${PYTEST_CMD}${NC}"
echo ""

eval $PYTEST_CMD
EXIT_CODE=$?

# Print results
echo ""
echo -e "${GREEN}========================================${NC}"
if [ $EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}✓ Tests passed!${NC}"
    if [ "$COVERAGE" = true ] && [ "$OUTPUT_FORMAT" = "html" ]; then
        echo -e "${GREEN}Coverage report: reports/coverage_html/index.html${NC}"
    fi
else
    echo -e "${RED}✗ Tests failed with exit code: $EXIT_CODE${NC}"
fi
echo -e "${GREEN}========================================${NC}"

# Stop docker containers if requested
# Disable exit on error for cleanup operations
set +e
if [ "$DOCKER_STOP" = true ]; then
    echo ""
    echo -e "${YELLOW}Stopping docker containers...${NC}"
    # Go to project root for taskfile (from src/kubedash, go up 2 levels)
    PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
    cd "$PROJECT_ROOT"
    if task docker-down; then
        cd "$SCRIPT_DIR"  # Return to script directory
        echo -e "${GREEN}Docker containers stopped${NC}"
    else
        cd "$SCRIPT_DIR"  # Return to script directory
        echo -e "${YELLOW}Warning: Failed to stop docker containers${NC}"
    fi
fi
set -e

exit $EXIT_CODE

