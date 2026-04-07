#!/bin/bash
USER=$(id -u)
echo "Setting USER environment variable to ${USER}"
export USER=$USER

# Multi-replica mode setup
REPLICAS=${REPLICAS:-1}
echo "Starting KubeDash with REPLICAS=${REPLICAS}"

# If multi-replica mode, enable cluster mode and require PostgreSQL
if [ "$REPLICAS" -gt 1 ]; then
    echo "Multi-replica mode detected (REPLICAS=$REPLICAS)"
    export REPLICA_MODE=cluster
    export REPLICA_COUNT="$REPLICAS"
    export LEADER_ELECTION_ENABLED=true
    
    # Check database type from kubedash.ini
    DB_TYPE=$(grep '^type =' kubedash.ini | cut -d'=' -f2 | tr -d ' ')
    echo "Database type from kubedash.ini: $DB_TYPE"
    
    # Require PostgreSQL in cluster mode
    if [ "$DB_TYPE" != "postgres" ]; then
        echo "ERROR: Multi-replica mode requires PostgreSQL. Set 'type = postgres' in kubedash.ini [database] section."
        echo "Current database type: $DB_TYPE"
        exit 1
    fi
    
    # Require Redis for session sharing
    if [ -z "$SESSION_REDIS_URL" ]; then
        echo "WARNING: Multi-replica mode recommended to use Redis for session sharing. Set SESSION_REDIS_URL for better experience."
    fi
fi

export DOCKER_COMPOSE_FILES="-f ../../deploy/docker-compose/dc-nginx.yaml"

# App
#export K8S_CLUSTER_NAME=
export KUBEDASH_VERSION=$(grep -m1 '^version' pyproject.toml | cut -d'"' -f2)
export FLASK_APP="kubedash"
export FLASK_DEBUG=1
export TEMPLATES_AUTO_RELOAD=1
#export FLASK_ENV=testing
export FLASK_ENV=development
export PYTHONFAULTHANDLER=1
export JAEGER_HTTP_ENDPOINT="http://127.0.0.1:4318/v1/traces"

#export KUBEDASH_DISABLE_CACHE=true

mkdir -p /tmp/kubedash

$(poetry env activate)

# Nginx Reverse Proxy
#kubectx $K8S_CLUSTER_NAME
CA_CERTS_FOLDER="$PWD/../../deploy/docker-compose/config"
# Generate Certificate
if [ ! -f $CA_CERTS_FOLDER/rootCA.pem ]; then
	echo "##  Generate CA Certificate"
	CAROOT=${CA_CERTS_FOLDER} mkcert -install kubedash.k3s.intra
	rm -rf $CA_CERTS_FOLDER/kubedash.k3s.*/
	mv kubedash.k3s.intra.pem kubedash.k3s.intra-key.pem $CA_CERTS_FOLDER/
fi

echo "Start Nginx Proxy in Docker Compose"
task docker-up

# Start DB migration
echo ""
echo "Start Migration"
flask db upgrade
echo "###########################################################################################"

# Start Gunicorn (Flask app)
echo ""
echo "Start Applications: KubeDash ${KUBEDASH_VERSION} (Replicas: ${REPLICAS})"
echo "###########################################################################################"
#flask run --host=0.0.0.0 --port=8000

# For multi-replica testing, start multiple gunicorn processes
if [ "$REPLICAS" -gt 1 ]; then
    echo "Starting $REPLICAS replica instances"
    PIDS=()
    for i in $(seq 0 $((REPLICAS-1))); do
        PORT=$((8000 + i))
        POD_NAME="kubedash-$i"
        REPLICA_ID=$i
        
        export POD_NAME=$POD_NAME
        export REPLICA_ID=$REPLICA_ID
        export FLASK_DEBUG=0  # Disable auto-reload in multi-replica mode
        
        echo "Starting replica $i (POD_NAME=$POD_NAME) on port $PORT"
        gunicorn --worker-class eventlet --conf gunicorn_conf.py --bind 0.0.0.0:$PORT kubedash:app &
        PIDS+=($!)
    done
    
    GUNICORN_PIDS=("${PIDS[@]}")
else
    export POD_NAME="kubedash-0"
    gunicorn --worker-class eventlet --conf gunicorn_conf.py kubedash:app --reload &
    GUNICORN_PID=$!
fi

# Start Celery Worker
#echo ""
#echo "Starting Celery Worker..."
#celery -A lib.components.celery worker --loglevel=info &
#CELERY_WORKER_PID=$!

# Start Celery Beat
#echo ""
#echo "Starting Celery Beat..."
#celery -A lib.components.celery beat --loglevel=info &
#CELERY_BEAT_PID=$!


# Function to handle shutdown gracefully
function shutdown {
    echo "Stopping processes..."
    if [ "$REPLICAS" -gt 1 ]; then
        for pid in "${GUNICORN_PIDS[@]}"; do
            kill -TERM $pid 2>/dev/null
        done
        for pid in "${GUNICORN_PIDS[@]}"; do
            wait $pid 2>/dev/null
        done
    else
        kill -TERM $GUNICORN_PID 2>/dev/null
        wait $GUNICORN_PID 2>/dev/null
    fi
    #kill -TERM $CELERY_WORKER_PID
    #kill -TERM $CELERY_BEAT_PID
    #wait $CELERY_WORKER_PID
    #wait $CELERY_BEAT_PID
    #docker compose $DOCKER_COMPOSE_FILES down
}

# Trap signals for graceful exit
trap shutdown SIGTERM SIGINT

# Wait for processes to finish (prevents container from exiting)
wait

