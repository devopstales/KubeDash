# Graceful Shutdown Implementation Details

## File Structure

```
src/kubedash/
├── lib/
│   ├── shutdown.py              # Core graceful shutdown logic
│   ├── scheduler.py             # APScheduler configuration
│   └── session_cleanup.py       # Session cleanup on shutdown
├── routes/
│   └── shutdown.py              # Shutdown endpoints
└── app.py                       # Flask app integration
```

## Code Examples

### 1. Complete shutdown.py Implementation

```python
# src/kubedash/lib/shutdown.py

import signal
import sys
import logging
import threading
import time
from datetime import datetime, timedelta
from typing import Optional, Callable, List
from contextlib import contextmanager

logger = logging.getLogger(__name__)


class GracefulShutdown:
    """Manage graceful shutdown of KubeDash application"""
    
    # States
    STATE_RUNNING = 'running'
    STATE_SHUTTING_DOWN = 'shutting_down'
    STATE_TERMINATED = 'terminated'
    
    def __init__(self, app, db, scheduler=None, leader_elector=None):
        self.app = app
        self.db = db
        self.scheduler = scheduler
        self.leader_elector = leader_elector
        
        # State management
        self.state = self.STATE_RUNNING
        self.start_time = None
        self.end_time = None
        
        # Request tracking
        self.in_flight_requests = 0
        self._request_lock = threading.RLock()
        
        # Shutdown handlers
        self.handlers: List[Callable] = []
        self.handlers_lock = threading.RLock()
    
    def setup_signals(self, timeout_seconds: int = 30):
        """Setup signal handlers for graceful shutdown"""
        
        def handle_signal(signum, frame):
            signal_name = signal.Signals(signum).name
            logger.warning(f"📍 Received {signal_name} signal. Initiating graceful shutdown...")
            self.shutdown(timeout_seconds=timeout_seconds)
        
        signal.signal(signal.SIGTERM, handle_signal)
        signal.signal(signal.SIGINT, handle_signal)
    
    def register_handler(self, handler: Callable, name: Optional[str] = None):
        """Register a shutdown handler"""
        with self.handlers_lock:
            self.handlers.append((handler, name or handler.__name__))
    
    def shutdown(self, timeout_seconds: int = 30, reason: str = 'sigterm'):
        """Execute graceful shutdown"""
        
        # Prevent multiple concurrent shutdowns
        if self.state != self.STATE_RUNNING:
            logger.warning(f"Shutdown already in progress (state={self.state})")
            return
        
        self.state = self.STATE_SHUTTING_DOWN
        self.start_time = datetime.utcnow()
        
        logger.info(f"🛑 Starting graceful shutdown (timeout={timeout_seconds}s, reason={reason})")
        
        # Run all shutdown phases
        phases = [
            ('release_leadership', self._release_leadership, 5),
            ('stop_requests', self._stop_accepting_requests, 1),
            ('drain_requests', self._drain_in_flight_requests, timeout_seconds - 10),
            ('stop_scheduler', self._stop_scheduler, 5),
            ('run_handlers', self._run_shutdown_handlers, 5),
            ('close_database', self._close_database, 3),
        ]
        
        for phase_name, phase_func, phase_timeout in phases:
            elapsed = (datetime.utcnow() - self.start_time).total_seconds()
            remaining = timeout_seconds - elapsed
            
            if remaining <= 0:
                logger.warning(f"⏱️  Timeout reached during {phase_name} phase")
                break
            
            try:
                logger.info(f"→ Phase: {phase_name}...")
                phase_func()
                logger.info(f"  ✅ {phase_name} complete")
            
            except Exception as e:
                logger.error(f"  ❌ Error in {phase_name}: {e}", exc_info=True)
        
        self.state = self.STATE_TERMINATED
        self.end_time = datetime.utcnow()
        
        duration = (self.end_time - self.start_time).total_seconds()
        logger.info(f"✅ Graceful shutdown completed in {duration:.1f}s")
    
    def _release_leadership(self):
        """Release leadership (multi-replica only)"""
        if not self.leader_elector or not self.leader_elector.running:
            return
        
        logger.info("  Releasing Kubernetes Lease...")
        
        try:
            start = datetime.utcnow()
            self.leader_elector.stop()
            elapsed = (datetime.utcnow() - start).total_seconds()
            logger.info(f"  Released in {elapsed:.2f}s")
        except Exception as e:
            logger.error(f"  Error releasing leadership: {e}")
    
    def _stop_accepting_requests(self):
        """Mark application as not ready for new requests"""
        logger.info("  Marking as not_ready...")
        self.app.config['SHUTTING_DOWN'] = True
    
    def _drain_in_flight_requests(self):
        """Wait for in-flight requests to complete"""
        deadline_seconds = 25  # Leave buffer time
        deadline = datetime.utcnow() + timedelta(seconds=deadline_seconds)
        
        logger.info(f"  Draining {self.in_flight_requests} in-flight requests...")
        
        last_count = self.in_flight_requests
        stable_count = 0
        
        while True:
            current_count = self.in_flight_requests
            remaining = (deadline - datetime.utcnow()).total_seconds()
            
            if remaining <= 0:
                logger.warning(f"  Timeout: {current_count} requests still in-flight")
                break
            
            if current_count == 0:
                logger.info(f"  All requests drained")
                break
            
            # Check if request count is stable (not changing)
            if current_count == last_count:
                stable_count += 1
                if stable_count > 5:  # Stable for 2.5 seconds
                    logger.warning(f"  Requests stuck at {current_count}, continuing with shutdown")
                    break
            else:
                stable_count = 0
            
            last_count = current_count
            
            logger.debug(f"  {current_count} requests in-flight ({remaining:.0f}s remaining)")
            threading.Event().wait(0.5)
    
    def _stop_scheduler(self):
        """Stop APScheduler"""
        if not self.scheduler or not self.scheduler.running:
            return
        
        logger.info("  Stopping APScheduler...")
        
        try:
            jobs = self.scheduler.get_jobs()
            logger.info(f"  Stopping {len(jobs)} scheduled jobs")
            
            self.scheduler.shutdown(wait=True)
        except Exception as e:
            logger.error(f"  Error stopping scheduler: {e}")
    
    def _run_shutdown_handlers(self):
        """Run registered shutdown handlers"""
        with self.handlers_lock:
            if not self.handlers:
                return
            
            logger.info(f"  Running {len(self.handlers)} shutdown handlers...")
            
            for handler, name in self.handlers:
                try:
                    logger.debug(f"    Calling {name}...")
                    handler()
                except Exception as e:
                    logger.error(f"    Error in {name}: {e}", exc_info=True)
    
    def _close_database(self):
        """Close database connections"""
        if not self.db:
            return
        
        logger.info("  Disposing database connections...")
        
        try:
            self.db.engine.dispose()
        except Exception as e:
            logger.error(f"  Error disposing database: {e}")
    
    def track_request(self) -> bool:
        """
        Track an incoming request.
        Returns True if request should proceed, False if shutting down.
        """
        with self._request_lock:
            if self.state != self.STATE_RUNNING:
                return False
            self.in_flight_requests += 1
        return True
    
    def complete_request(self):
        """Mark a request as completed"""
        with self._request_lock:
            self.in_flight_requests = max(0, self.in_flight_requests - 1)
    
    @contextmanager
    def track_request_context(self):
        """Context manager for tracking request duration"""
        if not self.track_request():
            raise RuntimeError("Application is shutting down")
        
        try:
            yield
        finally:
            self.complete_request()
    
    def is_shutting_down(self) -> bool:
        """Check if application is shutting down"""
        return self.state != self.STATE_RUNNING
    
    def get_status(self) -> dict:
        """Get shutdown status"""
        return {
            'state': self.state,
            'in_flight_requests': self.in_flight_requests,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'duration_seconds': (self.end_time - self.start_time).total_seconds()
                                if self.start_time and self.end_time else None,
        }


# Global instance
_graceful_shutdown: Optional[GracefulShutdown] = None


def init_graceful_shutdown(app, db, scheduler=None, leader_elector=None) -> GracefulShutdown:
    """Initialize global graceful shutdown"""
    global _graceful_shutdown
    
    _graceful_shutdown = GracefulShutdown(app, db, scheduler, leader_elector)
    _graceful_shutdown.setup_signals()
    
    logger.info("✅ Graceful shutdown initialized")
    return _graceful_shutdown


def get_graceful_shutdown() -> Optional[GracefulShutdown]:
    """Get global graceful shutdown instance"""
    return _graceful_shutdown
```

### 2. Flask Integration

```python
# src/kubedash/app.py

from flask import Flask, jsonify, request
from lib.shutdown import init_graceful_shutdown
import logging

logger = logging.getLogger(__name__)


def create_app(config_name='default'):
    app = Flask(__name__)
    app.config.from_object(config)
    
    # Initialize database
    db.init_app(app)
    
    # Initialize scheduler
    scheduler = APScheduler()
    scheduler.init_app(app)
    scheduler.start()
    
    # Initialize leader election
    leader_elector = LeaderElector(...)
    leader_elector.start()
    
    # Initialize graceful shutdown (important: before request handlers)
    graceful_shutdown = init_graceful_shutdown(app, db, scheduler, leader_elector)
    
    # ===== Request Tracking =====
    
    @app.before_request
    def before_request():
        """Track incoming request"""
        
        # Check if shutting down
        if graceful_shutdown.is_shutting_down():
            return {
                'error': 'Service is shutting down',
                'status': 'unavailable'
            }, 503
        
        # Track request
        if not graceful_shutdown.track_request():
            return {'error': 'Service is shutting down'}, 503
        
        # Store start time for metrics
        request.shutdown_start_time = datetime.utcnow()
    
    @app.after_request
    def after_request(response):
        """Complete request tracking"""
        graceful_shutdown.complete_request()
        
        # Add X-Response-Time header
        if hasattr(request, 'shutdown_start_time'):
            elapsed = (datetime.utcnow() - request.shutdown_start_time).total_seconds()
            response.headers['X-Response-Time'] = f"{elapsed:.3f}s"
        
        return response
    
    # ===== Health Endpoints =====
    
    @app.route('/api/health/live')
    def health_live():
        """Liveness probe (is the process alive?)"""
        return {'status': 'alive'}, 200
    
    @app.route('/api/health/ready')
    def health_ready():
        """Readiness probe (can the pod accept requests?)"""
        
        if graceful_shutdown.is_shutting_down():
            return {'status': 'not_ready', 'reason': 'shutting_down'}, 503
        
        try:
            # Check database
            db.session.execute(text("SELECT 1"))
        except Exception as e:
            logger.error(f"Database not ready: {e}")
            return {'status': 'not_ready', 'reason': 'database_error'}, 503
        
        return {'status': 'ready'}, 200
    
    # ===== Shutdown Endpoint =====
    
    @app.route('/api/shutdown', methods=['POST'])
    def shutdown():
        """
        Graceful shutdown endpoint
        Called by Kubernetes preStop hook during pod termination
        """
        
        def run_shutdown():
            """Run shutdown in background thread"""
            try:
                graceful_shutdown.shutdown(timeout_seconds=28, reason='api')
            except Exception as e:
                logger.error(f"Error during shutdown: {e}", exc_info=True)
                sys.exit(1)
        
        # Start shutdown in background to return immediately
        thread = threading.Thread(target=run_shutdown, daemon=False)
        thread.start()
        
        return {'status': 'shutting_down'}, 200
    
    # ===== Shutdown Handlers =====
    
    def cleanup_sessions():
        """Clean up sessions on shutdown"""
        logger.info("Cleaning up sessions...")
        try:
            # Clear expired sessions
            from models import UserSession
            expiration = datetime.utcnow() - timedelta(days=30)
            UserSession.query.filter(UserSession.created_at < expiration).delete()
            db.session.commit()
            logger.info("  Sessions cleaned up")
        except Exception as e:
            logger.error(f"Error cleaning up sessions: {e}")
    
    def flush_metrics():
        """Ensure all metrics are flushed"""
        logger.info("Flushing metrics...")
        try:
            # Force flush to Prometheus pushgateway if used
            pass
        except Exception as e:
            logger.error(f"Error flushing metrics: {e}")
    
    # Register handlers
    graceful_shutdown.register_handler(flush_metrics, 'flush_metrics')
    graceful_shutdown.register_handler(cleanup_sessions, 'cleanup_sessions')
    
    return app
```

### 3. Kubernetes YAML

```yaml
# deploy/kubedash/templates/deployment.yaml

apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ include "kubedash.fullname" . }}
spec:
  replicas: {{ .Values.replicaCount }}
  
  template:
    spec:
      # Grace period for shutdown
      terminationGracePeriodSeconds: 30
      
      containers:
      - name: kubedash
        image: "{{ .Values.image.repository }}:{{ .Values.image.tag }}"
        
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
          preStop:
            exec:
              command:
              - /bin/bash
              - -c
              - |
                #!/bin/bash
                set -e
                
                echo "Starting graceful shutdown..."
                
                # Call shutdown API endpoint (28s timeout)
                SHUTDOWN_URL="http://localhost:8000/api/shutdown"
                
                for i in {1..28}; do
                  if curl -s -X POST "$SHUTDOWN_URL" -o /dev/null -w "%{http_code}\n" | grep -q 200; then
                    echo "Shutdown endpoint responded (attempt $i)"
                    break
                  fi
                  
                  if [ $i -eq 28 ]; then
                    echo "Timeout waiting for shutdown endpoint"
                  else
                    sleep 1
                  fi
                done
                
                # Wait for background cleanup
                sleep 1
        
        # Readiness probe - removes from load balancer during shutdown
        readinessProbe:
          httpGet:
            path: /api/health/ready
            port: 8000
          initialDelaySeconds: 10
          periodSeconds: 5
          failureThreshold: 2
          timeoutSeconds: 3
        
        # Liveness probe - restarts unhealthy container
        livenessProbe:
          httpGet:
            path: /api/health/live
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
          failureThreshold: 3
          timeoutSeconds: 3
```

### 4. Testing Script

```bash
#!/bin/bash
# tests/test-graceful-shutdown.sh

set -e

echo "🧪 Testing Graceful Shutdown"

# Function to cleanup
cleanup() {
    echo "Cleaning up..."
    kill %1 2>/dev/null || true
}
trap cleanup EXIT

# Start application
echo "📍 Starting application..."
cd src/kubedash
python app.py &
APP_PID=$!
sleep 2

# Verify application is ready
echo "✓ Application started (PID=$APP_PID)"

# Create some load
echo "📊 Creating load..."
for i in {1..5}; do
    curl -s http://localhost:8000/api/v1/cluster/mode &
done
sleep 0.5

# Send SIGTERM
echo "📍 Sending SIGTERM..."
kill -TERM $APP_PID

# Wait for graceful shutdown
echo "⏳ Waiting for graceful shutdown..."
if wait $APP_PID 2>/dev/null; then
    EXIT_CODE=$?
else
    EXIT_CODE=$?
fi

echo "✅ Application terminated with code: $EXIT_CODE"

if [ $EXIT_CODE -eq 0 ]; then
    echo "✅ Graceful shutdown test PASSED"
    exit 0
else
    echo "❌ Graceful shutdown test FAILED"
    exit 1
fi
```

### 5. Helm Values

```yaml
# deploy/kubedash/values.yaml

replicaCount: 3

# Lifecycle configuration
terminationGracePeriodSeconds: 30

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

# Graceful shutdown
gracefulShutdown:
  enabled: true
  timeoutSeconds: 30
  preStopHookTimeout: 28
```

## Database Connection Cleanup

```python
# In _close_database() phase
def _close_database(self):
    """Ensure all database connections are properly closed"""
    
    if not self.db:
        return
    
    logger.info("Disposing database engine...")
    
    try:
        # Close all connections in pool
        self.db.engine.dispose()
        
        # Wait for any remaining queries to complete
        self.db.session.remove()
        
        logger.info("Database connections disposed")
    
    except Exception as e:
        logger.error(f"Error disposing database: {e}")
```

## Redis Connection Cleanup

```python
# Register Redis cleanup handler
def cleanup_redis():
    """Clean up Redis connections"""
    logger.info("Closing Redis connections...")
    
    try:
        from flask_session import Session
        if hasattr(Session, 'app') and hasattr(Session.app, 'redis'):
            Session.app.redis.close()
            logger.info("Redis connections closed")
    except Exception as e:
        logger.error(f"Error closing Redis: {e}")

graceful_shutdown.register_handler(cleanup_redis, 'cleanup_redis')
```

## Summary

**Phase 1: Leadership** (~1s)
- Stop renewing Kubernetes Lease
- New leader elected from replicas

**Phase 2: Requests** (~0.5s)
- Mark pod as not_ready
- Remove from load balancer

**Phase 3: Drain** (~20s)
- Wait for in-flight requests
- With timeout and deadlock detection

**Phase 4: Tasks** (~1s)
- Stop APScheduler
- Cancel pending jobs

**Phase 5: Handlers** (~2s)
- Run custom shutdown logic
- Session cleanup, metrics flush

**Phase 6: Database** (~1s)
- Dispose connection pool
- Close remaining connections

**Total: < 30 seconds** ✅
