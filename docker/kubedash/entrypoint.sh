#!/bin/bash

# Ensure PATH includes /usr/local/bin where Python packages are installed
export PATH=/usr/local/bin:$PATH

# Find Python executable
# Prefer Python from /usr/local/bin (from installed packages) if available
if [ -f /usr/local/bin/python3.12 ]; then
    PYTHON_CMD=/usr/local/bin/python3.12
elif [ -f /usr/local/bin/python3 ]; then
    PYTHON_CMD=/usr/local/bin/python3
elif command -v python3.12 >/dev/null 2>&1; then
    PYTHON_CMD=python3.12
elif command -v python3 >/dev/null 2>&1; then
    PYTHON_CMD=python3
elif [ -f /usr/bin/python3.12 ]; then
    PYTHON_CMD=/usr/bin/python3.12
elif [ -f /usr/bin/python3 ]; then
    PYTHON_CMD=/usr/bin/python3
else
    PYTHON_CMD=python
fi

# Find site-packages directory where packages are installed
# Packages installed with --prefix=/install-dir are copied to /usr/local
# On Amazon Linux, packages with compiled extensions go to lib64
SITE_PACKAGES=""
for path in /usr/local/lib64/python3.12/site-packages /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/dist-packages; do
    if [ -d "$path" ] && [ "$(ls -A $path 2>/dev/null)" ]; then
        SITE_PACKAGES="$path"
        echo "Found site-packages at: $SITE_PACKAGES"
        break
    fi
done

# Set PYTHONPATH to include site-packages
if [ -n "$SITE_PACKAGES" ]; then
    export PYTHONPATH="$SITE_PACKAGES:${PYTHONPATH:-}"
    echo "PYTHONPATH set to: $PYTHONPATH"
else
    echo "WARNING: No site-packages directory found. Checking /usr/local structure..."
    find /usr/local -type d -name "site-packages" -o -name "dist-packages" 2>/dev/null | head -10
fi

# Fix getpwuid(): uid not found: 1001 by setting the USER env var to prevent python from looking for a matching uid/gid in the password database.
# See https://github.com/python/cpython/blob/v3.6.0/Lib/getpass.py#L155-L170.
USER=$(id -u)
echo "Setting USER environment variable to ${USER}"
export USER=$USER

# Ensure certs directory exists with proper permissions
# cert_utils.py uses PROJECT_ROOT / 'certs' where PROJECT_ROOT = /code
# So cert_dir = /code/certs
echo "Checking /code/certs directory permissions..."
# Check current permissions
if [ -d /code ]; then
    echo "Directory /code exists:"
    ls -ld /code 2>/dev/null || true
else
    echo "WARNING: /code directory does not exist"
fi

# Ensure /code/certs exists and is writable
if [ ! -d /code/certs ]; then
    echo "Creating /code/certs directory..."
    if mkdir -p /code/certs 2>/dev/null; then
        chmod 755 /code/certs 2>/dev/null || true
        echo "Created /code/certs directory"
    else
        echo "ERROR: Failed to create /code/certs directory"
        echo "Current user: $(id 2>/dev/null || echo 'unknown')"
        echo "Directory permissions:"
        ls -ld /code 2>/dev/null || true
        echo "This may require rebuilding the Docker image with updated Dockerfile"
    fi
else
    echo "/code/certs directory exists"
    if [ ! -w /code/certs ]; then
        echo "WARNING: /code/certs exists but is not writable"
        ls -ld /code/certs 2>/dev/null || true
        echo "Attempting to fix permissions..."
        chmod 755 /code/certs 2>/dev/null || echo "Cannot fix permissions - may need to rebuild image"
    else
        echo "/code/certs is writable"
    fi
fi

# Also ensure /code/kubedash/certs exists for compatibility (though not used)
if [ ! -d /code/kubedash/certs ]; then
    mkdir -p /code/kubedash/certs 2>/dev/null && chmod 755 /code/kubedash/certs 2>/dev/null || true
fi

echo ""
echo "Start Migration"
echo "###########################################################################################"
# Use executables from /usr/local/bin if available (installed by pip)
if [ -f /usr/local/bin/flask ]; then
    /usr/local/bin/flask db upgrade
else
    # Use PYTHONPATH that was set earlier
    if [ -n "$SITE_PACKAGES" ] && [ -f "$SITE_PACKAGES/flask/__init__.py" ]; then
        ${PYTHON_CMD} -m flask db upgrade
    else
        echo "ERROR: Could not find Flask installation. Checking available paths..."
        ${PYTHON_CMD} -c "import sys; print('Python paths:', sys.path)" 2>&1
        echo "Looking for flask in /usr/local..."
        find /usr/local -name "flask" -type d 2>/dev/null | head -10
        echo "Checking for flask executables..."
        find /usr/local -name "flask" -type f 2>/dev/null | head -10
        echo "Checking site-packages contents..."
        if [ -n "$SITE_PACKAGES" ]; then
            ls -la "$SITE_PACKAGES" | head -20
        fi
        echo "Checking lib64 directory..."
        if [ -d /usr/local/lib64/python3.12/site-packages ]; then
            echo "lib64 site-packages contents:"
            ls -la /usr/local/lib64/python3.12/site-packages | head -20
        fi
        echo "Checking /usr/local/bin for executables..."
        ls -la /usr/local/bin | grep -E "(flask|gunicorn)" | head -10
        echo "Checking entire /usr/local structure..."
        find /usr/local -type d -name "*flask*" -o -name "*gunicorn*" 2>/dev/null | head -10
        exit 1
    fi
fi
# separator_long is already printed in initialize_app_database() before migration
echo ${KUBEDASH_VERSION} > /code/kubedash/app-release

echo ""
echo "Start Applications"
echo "###########################################################################################"
#flask run --host=0.0.0.0 --port=8765
#python3 kubedash.py
# Use gunicorn executable from /usr/local/bin if available
if [ -f /usr/local/bin/gunicorn ]; then
    /usr/local/bin/gunicorn --worker-class eventlet --conf gunicorn_conf.py kubedash:app
else
    # PYTHONPATH should already be set from earlier
    ${PYTHON_CMD} -m gunicorn --worker-class eventlet --conf gunicorn_conf.py kubedash:app
fi
