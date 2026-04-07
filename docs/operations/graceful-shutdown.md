# Graceful Shutdown for Multi-Replica KubeDash

## Overview

Graceful shutdown ensures KubeDash can cleanly release leadership, stop running tasks, and close connections before termination. This is critical for zero-downtime deployments.

## Shutdown Sequence

### Normal Pod Lifetime

```
Pod Running
  ↓
Kube-scheduler sends SIGTERM
  ↓
preStop Hook executes (30 seconds)
  ├─ Release leadership
  ├─ Stop accepting new requests
  ├─ Wait for in-flight requests to complete
  └─ Close connections
  ↓
terminationGracePeriodSeconds (30 seconds) elapsed
  ↓
SIGKILL sent (forced termination)
  ↓
Pod Terminated
```

### Key Phases

1. **SIGTERM Signal** (Kubernetes sends when pod should stop)
   - Graceful shutdown begins
   - ~30 seconds available for cleanup

2. **Leadership Release** (Multi-replica only)
   - Immediately release Kubernetes Lease
   - New leader elected from remaining replicas
   - No more leader-only tasks

3. **Request Drainage**
   - Stop accepting new requests
   - Wait for in-flight requests to complete (with timeout)
   - Close HTTP connections

4. **Resource Cleanup**
   - Stop APScheduler jobs
   - Close database connections
   - Flush logs and metrics
   - Close Redis connections

5. **Process Termination**
   - Exit with code 0 (success)
   - Or exit with code 1 if unclean shutdown

---

## Implementation

### 1. SIGTERM Signal Handler

File: `src/kubedash/lib/shutdown.py`

```python
import signal
import sys
import logging
import threading
from datetime import datetime, timedelta
from typing import Optional, Callable, List

logger = logging.getLogger(__name__)


class GracefulShutdown:
    """Handle graceful shutdown of KubeDash application"""
    
    def __init__(self, app, db, scheduler, leader_elector):
        self.app = app
        self.db = db
        self.scheduler = scheduler
        self.leader_elector = leader_elector
        self.is_shutting_down = False
        self.start_time = None
        self.handlers: List[Callable] = []
        self.in_flight_requests = 0
        self._lock = threading.Lock()
    
    def register_handler(self, handler: Callable):
        """Register a shutdown handler"""
        self.handlers.append(handler)
    
    def setup_signal_handlers(self, timeout_seconds: int = 30):
        """Setup SIGTERM and SIGINT signal handlers"""
        
        def signal_handler(signum, frame):
            logger.warning(f"Received signal {signum}. Starting graceful shutdown...")
            self.initiate_shutdown(timeout_seconds)
        
        # Register handlers
        signal.signal(signal.SIGTERM, signal_handler)  # Normal shutdown
        signal.signal(signal.SIGINT, signal_handler)   # Ctrl+C
    
    def initiate_shutdown(self, timeout_seconds: int = 30):
        """Start graceful shutdown process"""
        
        with self._lock:
            if self.is_shutting_down:
                logger.warning("Shutdown already in progress")
                return
            
            self.is_shutting_down = True
            self.start_time = datetime.utcnow()
        
        logger.info(f"🛑 Graceful shutdown initiated (timeout: {timeout_seconds}s)")
        
        try:
            # Phase 1: Release leadership (if leader)
            self._release_leadership()
            
            # Phase 2: Stop accepting new requests
            self._stop_accepting_requests()
            
            # Phase 3: Wait for in-flight requests
            self._drain_in_flight_requests(timeout_seconds)
            
            # Phase 4: Stop scheduler and tasks
            self._stop_scheduler()
            
            # Phase 5: Run shutdown handlers
            self._run_shutdown_handlers()
            
            # Phase 6: Close database connections
            self._close_database()
            
            logger.info("✅ Graceful shutdown completed successfully")
            sys.exit(0)
        
        except Exception as e:
            logger.error(f"❌ Error during graceful shutdown: {e}", exc_info=True)
            sys.exit(1)
    
    def _release_leadership(self):
        """Release leadership if currently leader"""
        if not self.leader_elector:
            return
        
        logger.info("Releasing leadership...")
        
        try:
            self.leader_elector.stop()  # Stop renewing lease
            logger.info("✅ Leadership released")
        except Exception as e:
            logger.error(f"Error releasing leadership: {e}")
    
    def _stop_accepting_requests(self):
        """Signal that application is no longer ready for new requests"""
        logger.info("Stopping acceptance of new requests...")
        
        # Set flag that readiness probe can check
        self.app.config['SHUTTING_DOWN'] = True
        
        logger.info("✅ New request acceptance stopped")
    
    def _drain_in_flight_requests(self, timeout_seconds: int):
        """Wait for in-flight requests to complete with timeout"""
        logger.info(f"Waiting for {self.in_flight_requests} in-flight requests...")
        
        deadline = datetime.utcnow() + timedelta(seconds=timeout_seconds)
        
        while self.in_flight_requests > 0:
            remaining = (deadline - datetime.utcnow()).total_seconds()
            
            if remaining <= 0:
                logger.warning(f"⚠️  Shutdown timeout reached. {self.in_flight_requests} requests still in flight.")
                break
            
            logger.debug(f"  {self.in_flight_requests} requests in flight ({remaining:.0f}s remaining)")
            threading.Event().wait(0.5)  # Sleep 500ms
        
        logger.info("✅ In-flight requests drained")
    
    def _stop_scheduler(self):
        """Stop APScheduler gracefully"""
        if not self.scheduler or not self.scheduler.running:
            return
        
        logger.info("Stopping scheduler...")
        
        try:
            self.scheduler.shutdown(wait=True)
            logger.info("✅ Scheduler stopped")
        except Exception as e:
            logger.error(f"Error stopping scheduler: {e}")
    
    def _run_shutdown_handlers(self):
        """Run registered shutdown handlers"""
        logger.info(f"Running {len(self.handlers)} shutdown handlers...")
        
        for handler in self.handlers:
            try:
                logger.debug(f"Running handler: {handler.__name__}")
                handler()
            except Exception as e:
                logger.error(f"Error in shutdown handler {handler.__name__}: {e}")
    
    def _close_database(self):
        """Close database connections"""
        if not self.db:
            return
        
        logger.info("Closing database connections...")
        
        try:
            self.db.engine.dispose()
            logger.info("✅ Database connections closed")
        except Exception as e:
            logger.error(f"Error closing database: {e}")
    
    def increment_request_counter(self):
        """Called at start of each request"""
        with self._lock:
            if self.is_shutting_down:
                return False  # Reject new requests during shutdown
            self.in_flight_requests += 1
        return True
    
    def decrement_request_counter(self):
        """Called at end of each request"""
        with self._lock:
            self.in_flight_requests = max(0, self.in_flight_requests - 1)


# Global instance
_graceful_shutdown: Optional[GracefulShutdown] = None


def init_graceful_shutdown(app, db, scheduler, leader_elector) -> GracefulShutdown:
    """Initialize graceful shutdown"""
    global _graceful_shutdown
    
    _graceful_shutdown = GracefulShutdown(app, db, scheduler, leader_elector)
    _graceful_shutdown.setup_signal_handlers()
    
    return _graceful_shutdown


def get_graceful_shutdown() -> Optional[GracefulShutdown]:
    """Get global graceful shutdown instance"""
    return _graceful_shutdown
```

### 2. Integration with Flask App

File: `src/kubedash/app.py`

```python
from lib.shutdown import init_graceful_shutdown

def create_app(config_name='default'):
    app = Flask(__name__)
    app.config.from_object(config)
    
    # ... database initialization ...
    
    # Initialize graceful shutdown
    graceful_shutdown = init_graceful_shutdown(app, db, scheduler, leader_elector)
    
    # Template for monitoring shutdown
    @app.before_request
    def before_request():
        """Track in-flight requests"""
        if app.config.get('SHUTTING_DOWN', False):
            return {'error': 'Service is shutting down'}, 503
        
        graceful_shutdown.increment_request_counter()
    
    @app.after_request
    def after_request(response):
        """Decrement in-flight request counter"""
        graceful_shutdown.decrement_request_counter()
        return response
    
    # Register shutdown handler for session cleanup
    def cleanup_sessions():
        logger.info("Cleaning up sessions...")
        # Clear expired sessions, etc.
    
    graceful_shutdown.register_handler(cleanup_sessions)
    
    return app
```

---

## Kubernetes Configuration

### 1. preStop Hook

Execute graceful shutdown logic before SIGTERM:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: kubedash
spec:
  template:
    spec:
      terminationGracePeriodSeconds: 30  # Time allowed for graceful shutdown
      
      containers:
      - name: kubedash
        image: kubedash:latest
        
        lifecycle:
          preStop:
            exec:
              # HTTP GET with timeout
              command:
              - /bin/bash
              - -c
              - |
                # Signal to application that it's shutting down
                curl -X POST http://localhost:8000/api/shutdown \
                  --max-time 28 \
                  --silent \
                  --show-error || true
                
                # Wait for graceful shutdown to complete
                sleep 2
        
        readinessProbe:
          httpGet:
            path: /api/health/ready
            port: 8000
          initialDelaySeconds: 10
          periodSeconds: 5
          failureThreshold: 2
```

### 2. Readiness Probe

Exclude pod from load balancer during shutdown:

```python
@app.route('/api/health/ready')
def readiness():
    """Readiness probe endpoint"""
    
    if app.config.get('SHUTTING_DOWN', False):
        return {'status': 'not_ready', 'reason': 'shutting_down'}, 503
    
    # Check database
    try:
        db.session.execute(text("SELECT 1"))
    except Exception as e:
        logger.error(f"Database not ready: {e}")
        return {'status': 'not_ready', 'reason': 'database'}, 503
    
    return {'status': 'ready'}, 200
```

### 3. Complete Pod Spec

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: kubedash
  namespace: default
spec:
  replicas: 3
  
  template:
    metadata:
      labels:
        app: kubedash
    
    spec:
      # Give 30 seconds for graceful shutdown
      terminationGracePeriodSeconds: 30
      
      containers:
      - name: kubedash
        image: kubedash:latest
        imagePullPolicy: IfNotPresent
        
        ports:
        - containerPort: 8000
          name: http
        
        env:
        - name: POD_NAME
          valueFrom:
            fieldRef:
              fieldPath: metadata.name
        - name: POD_NAMESPACE
          valueFrom:
            fieldRef:
              fieldPath: metadata.namespace
        
        # Graceful shutdown configuration
        lifecycle:
          preStop:
            exec:
              command:
              - /bin/bash
              - -c
              - |
                set -e
                
                # Log shutdown start
                echo "Starting graceful shutdown..."
                
                # Signal application shutdown (28 second timeout)
                curl -s -X POST http://localhost:8000/api/shutdown \
                  --max-time 28 || true
                
                # Wait for background cleanup
                sleep 1
        
        # Readiness probe (remove from LB during shutdown)
        readinessProbe:
          httpGet:
            path: /api/health/ready
            port: 8000
          initialDelaySeconds: 10
          periodSeconds: 5
          failureThreshold: 2
          timeoutSeconds: 3
        
        # Liveness probe (restart if unhealthy)
        livenessProbe:
          httpGet:
            path: /api/health/live
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
          failureThreshold: 3
          timeoutSeconds: 3
        
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
```

---

## APScheduler Graceful Shutdown

File: `src/kubedash/lib/scheduler.py`

```python
from apscheduler.schedulers.background import BackgroundScheduler
import logging

logger = logging.getLogger(__name__)


def configure_scheduler(app):
    """Configure APScheduler with graceful shutdown support"""
    
    scheduler = BackgroundScheduler()
    
    # Configure graceful shutdown
    scheduler.configure(
        job_defaults={
            'coalesce': True,  # Don't queue multiple missed jobs
            'max_instances': 1,  # Only one instance per job
        }
    )
    
    # Add shutdown listener
    def scheduler_shutdown_listener(event):
        """Called when scheduler is shutting down"""
        logger.info(f"APScheduler shutdown event: {event}")
    
    scheduler.add_listener(scheduler_shutdown_listener)
    
    # Register job shutdown
    def register_jobs():
        scheduler.add_job(
            heartbeat_job,
            'interval',
            seconds=60,
            id='heartbeat',
            name='Heartbeat',
            replace_existing=True
        )
    
    register_jobs()
    
    # Start scheduler
    try:
        scheduler.start()
        logger.info("✅ APScheduler started")
    except Exception as e:
        logger.error(f"Failed to start scheduler: {e}")
        raise
    
    return scheduler


def graceful_scheduler_shutdown(scheduler):
    """Shut down scheduler gracefully"""
    if not scheduler or not scheduler.running:
        return
    
    logger.info("Shutting down APScheduler gracefully...")
    
    try:
        # Retrieve all jobs
        jobs = scheduler.get_jobs()
        logger.info(f"Stopping {len(jobs)} scheduled jobs")
        
        # Mark jobs as should_stop
        for job in jobs:
            logger.debug(f"Pausing job: {job.id}")
            job.prevent_rescheduling = True
        
        # Give running jobs time to complete (max 10 seconds)
        scheduler.shutdown(wait=True)
        
        logger.info("✅ APScheduler shutdown complete")
    
    except Exception as e:
        logger.error(f"Error during scheduler shutdown: {e}", exc_info=True)
```

---

## Session Cleanup on Shutdown

File: `src/kubedash/lib/session_cleanup.py`

```python
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)


def cleanup_sessions(db):
    """Clean up expired sessions on shutdown"""
    logger.info("Cleaning up sessions...")
    
    try:
        # Get session store (Redis or database)
        session_store = get_session_store()
        
        if session_store.type == 'redis':
            cleanup_redis_sessions(session_store)
        else:
            cleanup_database_sessions(db)
        
        logger.info("✅ Sessions cleaned up")
    
    except Exception as e:
        logger.error(f"Error cleaning up sessions: {e}")


def cleanup_redis_sessions(session_store):
    """Clean up Redis sessions"""
    logger.debug("Cleaning up Redis sessions...")
    
    # Redis automatically cleans up expired keys via TTL
    # Just ensure connection is closed
    try:
        session_store.redis.close()
        logger.debug("Redis connection closed")
    except Exception as e:
        logger.warning(f"Error closing Redis: {e}")


def cleanup_database_sessions(db):
    """Clean up database sessions"""
    logger.debug("Cleaning up database sessions...")
    
    try:
        # Delete expired sessions
        from models import Session
        
        expiration_time = datetime.utcnow() - timedelta(days=30)
        deleted = db.session.query(Session).filter(
            Session.updated_at < expiration_time
        ).delete()
        
        db.session.commit()
        
        logger.info(f"  Deleted {deleted} expired sessions")
    
    except Exception as e:
        logger.error(f"Error cleaning up database sessions: {e}")
        db.session.rollback()
```

---

## Shutdown Endpoint

File: `src/kubedash/routes/shutdown.py`

```python
from flask import Blueprint, current_app, jsonify
from lib.shutdown import get_graceful_shutdown
import logging

logger = logging.getLogger(__name__)

shutdown_bp = Blueprint('shutdown', __name__, url_prefix='/api')


@shutdown_bp.route('/shutdown', methods=['POST'])
def initiate_shutdown():
    """
    Endpoint to gracefully shutdown the application
    
    Called by Kubernetes preStop hook
    Timeout: 28 seconds (leave 2s buffer for cleanup)
    """
    
    graceful_shutdown = get_graceful_shutdown()
    
    if not graceful_shutdown:
        return {'error': 'Graceful shutdown not initialized'}, 500
    
    logger.warning("Shutdown endpoint called")
    
    # Run shutdown in background thread to return 200 immediately
    import threading
    shutdown_thread = threading.Thread(
        target=graceful_shutdown.initiate_shutdown,
        args=(28,)  # 28 second timeout
    )
    shutdown_thread.daemon = False
    shutdown_thread.start()
    
    return {'status': 'shutting_down'}, 200
```

Register in Flask app:

```python
from routes.shutdown import shutdown_bp

app.register_blueprint(shutdown_bp)
```

---

## Helm Chart Configuration

File: `deploy/kubedash/templates/deployment.yaml`

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ include "kubedash.fullname" . }}
  labels:
    {{- include "kubedash.labels" . | nindent 4 }}
spec:
  replicas: {{ .Values.replicaCount }}
  selector:
    matchLabels:
      {{- include "kubedash.selectorLabels" . | nindent 6 }}
  
  template:
    metadata:
      labels:
        {{- include "kubedash.selectorLabels" . | nindent 8 }}
    
    spec:
      # Graceful shutdown configuration
      terminationGracePeriodSeconds: {{ .Values.terminationGracePeriodSeconds | default 30 }}
      
      containers:
      - name: {{ .Chart.Name }}
        image: "{{ .Values.image.repository }}:{{ .Values.image.tag }}"
        imagePullPolicy: {{ .Values.image.pullPolicy }}
        
        ports:
        - name: http
          containerPort: 8000
          protocol: TCP
        
        env:
        - name: POD_NAME
          valueFrom:
            fieldRef:
              fieldPath: metadata.name
        - name: POD_NAMESPACE
          valueFrom:
            fieldRef:
              fieldPath: metadata.namespace
        
        # Graceful shutdown hook
        lifecycle:
          {{- if .Values.lifecycle.preStop }}
          preStop:
            {{- toYaml .Values.lifecycle.preStop | nindent 12 }}
          {{- else }}
          preStop:
            exec:
              command:
              - /bin/bash
              - -c
              - |
                curl -s -X POST http://localhost:8000/api/shutdown \
                  --max-time 28 || true
                sleep 1
          {{- end }}
        
        # Readiness probe
        readinessProbe:
          httpGet:
            path: /api/health/ready
            port: http
          initialDelaySeconds: {{ .Values.readinessProbe.initialDelaySeconds | default 10 }}
          periodSeconds: {{ .Values.readinessProbe.periodSeconds | default 5 }}
          failureThreshold: {{ .Values.readinessProbe.failureThreshold | default 2 }}
          timeoutSeconds: {{ .Values.readinessProbe.timeoutSeconds | default 3 }}
        
        # Liveness probe
        livenessProbe:
          httpGet:
            path: /api/health/live
            port: http
          initialDelaySeconds: {{ .Values.livenessProbe.initialDelaySeconds | default 30 }}
          periodSeconds: {{ .Values.livenessProbe.periodSeconds | default 10 }}
          failureThreshold: {{ .Values.livenessProbe.failureThreshold | default 3 }}
          timeoutSeconds: {{ .Values.livenessProbe.timeoutSeconds | default 3 }}
        
        resources:
          {{- toYaml .Values.resources | nindent 12 }}
```

File: `deploy/kubedash/values.yaml`

```yaml
# Graceful shutdown configuration
terminationGracePeriodSeconds: 30

# Probe configuration
readinessProbe:
  initialDelaySeconds: 10
  periodSeconds: 5
  failureThreshold: 2
  timeoutSeconds: 3

livenessProbe:
  initialDelaySeconds: 30
  periodSeconds: 10
  failureThreshold: 3
  timeoutSeconds: 3

# Lifecycle hooks
lifecycle:
  preStop:
    exec:
      command:
      - /bin/bash
      - -c
      - |
        curl -s -X POST http://localhost:8000/api/shutdown \
          --max-time 28 || true
        sleep 1
```

---

## Testing Graceful Shutdown

### 1. Local Testing

```bash
# Start application
cd src/kubedash
python app.py &
APP_PID=$!

# Send SIGTERM
sleep 5
kill -TERM $APP_PID

# Wait for graceful shutdown
wait $APP_PID
EXIT_CODE=$?

echo "Exit code: $EXIT_CODE"
# Should be 0 for clean shutdown
```

### 2. Kubernetes Testing

```bash
# Deploy 3 replicas
kubectl scale deployment kubedash --replicas=3

# Monitor leader when pod is deleted
kubectl logs -f kubedash-0 | grep -i leader &
kubectl logs -f kubedash-1 | grep -i leader &
kubectl logs -f kubedash-2 | grep -i leader &

# Delete leader pod and watch election
kubectl delete pod kubedash-0

# Verify:
# - Leadership released immediately
# - New leader elected in < 5 seconds
# - In-flight requests completed
# - Pod terminates cleanly
```

### 3. Test with In-Flight Requests

```bash
# Create persistent load
kubectl run load-gen --image=curlimages/curl -- \
  sh -c 'while true; do curl http://kubedash:8000/api/v1/cluster/mode; sleep 0.1; done' &

# Delete pod while requests in-flight
kubectl delete pod kubedash-0 --grace-period=30

# Monitor logs
kubectl logs -f kubedash-0 | grep -E "in-flight|drained|shutdown"

# Verify: No 503 errors or connection resets
```

### 4. Timeout Test

```bash
# Verify termination if shutdown takes too long
# Monitor process using:
kubectl exec kubedash-0 -- ps aux | grep python

# After terminationGracePeriodSeconds (30s), SIGKILL is sent
# Process should be gone

# Check that pods restart cleanly
kubectl get pods -l app=kubedash -w
```

---

## Monitoring and Observability

### Metrics to Track

```python
# Prometheus metrics
from prometheus_client import Counter, Histogram

shutdown_initiated = Counter(
    'kubedash_shutdown_initiated_total',
    'Times graceful shutdown was initiated',
    ['reason']  # 'sigterm', 'api', 'error'
)

shutdown_duration_seconds = Histogram(
    'kubedash_shutdown_duration_seconds',
    'Time taken for graceful shutdown'
)

in_flight_requests = Gauge(
    'kubedash_in_flight_requests',
    'Number of in-flight HTTP requests'
)

leadership_release_duration_seconds = Histogram(
    'kubedash_leadership_release_duration_seconds',
    'Time taken to release leadership'
)
```

### Logging

```
2026-04-05 10:15:30 WARNING Received signal 15. Starting graceful shutdown...
2026-04-05 10:15:30 INFO 🛑 Graceful shutdown initiated (timeout: 30s)
2026-04-05 10:15:30 INFO Releasing leadership...
2026-04-05 10:15:30 INFO ✅ Leadership released (0.15s)
2026-04-05 10:15:30 INFO Stopping acceptance of new requests...
2026-04-05 10:15:30 INFO ✅ New request acceptance stopped
2026-04-05 10:15:30 INFO Waiting for 5 in-flight requests...
2026-04-05 10:15:31 DEBUG  4 requests in flight (28.5s remaining)
2026-04-05 10:15:32 INFO ✅ In-flight requests drained
2026-04-05 10:15:32 INFO Stopping scheduler...
2026-04-05 10:15:32 INFO APScheduler shutdown complete
2026-04-05 10:15:32 INFO ✅ Scheduler stopped
2026-04-05 10:15:32 INFO Running 3 shutdown handlers...
2026-04-05 10:15:32 INFO Cleaning up sessions...
2026-04-05 10:15:32 INFO ✅ Sessions cleaned up
2026-04-05 10:15:32 INFO Closing database connections...
2026-04-05 10:15:33 INFO ✅ Database connections closed
2026-04-05 10:15:33 INFO ✅ Graceful shutdown completed successfully
```

---

## Troubleshooting

### Pod Not Terminating

**Symptoms:**
```
WARNING ⏱️  Pod not terminating after SIGTERM
```

**Investigation:**
```bash
# Check if shutdown endpoint is reachable
kubectl exec kubedash-0 -- \
  curl -X POST http://localhost:8000/api/shutdown -v

# Check application logs
kubectl logs kubedash-0 | tail -50

# Check if process has child processes not terminating
kubectl exec kubedash-0 -- ps auxf
```

**Fix:**
- Increase `terminationGracePeriodSeconds` if requests take long
- Check for blocking I/O in shutdown handlers
- Review database connection pool recycling

### Leadership Not Released

**Symptoms:**
```
WARNING Leadership not released before pod termination
```

**Investigation:**
```bash
# Check leader election logs
kubectl logs kubedash-leader-0 | grep -i "leadership\|lease"

# Check Kubernetes Lease object
kubectl get leases

# Check if preStop hook is executing
kubectl logs kubedash-0 | grep "preStop\|shutdown"
```

**Fix:**
-Check that preStop hook is configured
- Verify `/api/shutdown` endpoint is accessible
- Check Kubernetes RBAC permissions for Leases

### Requests Not Draining

**Symptoms:**
```
WARNING Shutdown timeout reached. 10 requests still in flight.
```

**Investigation:**
```bash
# Check what requests are hanging
kubectl logs kubedash-0 | grep -E "request|in-flight"

# Monitor active connections
kubectl exec postgres-0 -- psql -c \
  "SELECT pid, query FROM pg_stat_activity WHERE datname='kubedash';"
```

**Fix:**
- Increase `terminationGracePeriodSeconds` to 60+
- Optimize slow SQL queries
- Add query timeouts to prevent hanging

---

## Best Practices

✅ **DO:**
- Test graceful shutdown in staging
- Monitor shutdown metrics in production
- Log all shutdown events
- Drain in-flight requests before exit
- Release leadership immediately
- Use reasonable timeouts (30-60 seconds)
- Test with realistic load

❌ **DON'T:**
- Force kill processes during shutdown
- Leave database connections open
- Skip preStop hook setup
- Set timeout too short (< 10s)
- Log at INFO level during shutdown (use reduced logging)

## Success Criteria

- [ ] Pod terminates cleanly on delete
- [ ] Leadership released within 1 second
- [ ] In-flight requests complete without errors
- [ ] Readiness probe marks pod as not-ready immediately
- [ ] Exit code is 0 for clean shutdowns
- [ ] Logs show all progress steps
- [ ] No database connection errors during shutdown
- [ ] New leader elected within 30 seconds
- [ ] Scheduler jobs stopped gracefully
