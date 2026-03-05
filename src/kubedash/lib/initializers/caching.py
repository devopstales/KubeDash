#!/usr/bin/env python3
"""Redis caching initialization for KubeDash."""

import os
import socket
from flask import Flask
from redis.exceptions import AuthenticationError, ConnectionError, RedisError
from redis.cluster import RedisCluster


def initialize_app_caching(app: Flask):
    """Initialize caching with Redis or Redis Cluster. If Redis is not available, fallback to SimpleCache.

    Args:
        app (Flask): Flask app object
    """
    from lib.cache import cache, cached_base, cached_base2

    # Check if caching is disabled via environment variable
    disable_cache = os.getenv('KUBEDASH_DISABLE_CACHE', 'false').lower() in ('true', '1', 'yes', 'on')
    if disable_cache:
        app.logger.info("Caching disabled via KUBEDASH_DISABLE_CACHE environment variable")
        app.config['CACHE_TYPE'] = 'NullCache'
        cache.init_app(app)
        app.cache = cache
        return

    ini = app.config['kubedash.ini']
    redis_enabled = ini.get('remote_cache', 'redis_enabled', fallback='none').lower() == 'true'
    cluster_enabled = ini.get('remote_cache', 'cluster_enabled', fallback='false').lower() == 'true'

    redis_port = int(ini.get('remote_cache', 'redis_port', fallback='6379'))
    redis_password = ini.get('remote_cache', 'redis_password', fallback=None) or None
    redis_db = int(ini.get('remote_cache', 'redis_db', fallback='0'))

    cache_ready = False

    if redis_enabled:
        if cluster_enabled:
            # Parse cluster startup nodes
            startup_nodes_raw = ini.get('remote_cache', 'cluster_startup_nodes', fallback='')
            startup_nodes = [{'host': host.strip(), 'port': redis_port} for host in startup_nodes_raw.split(',') if host.strip()]

            try:
                test_cluster = RedisCluster(startup_nodes=startup_nodes, decode_responses=True, password=redis_password, socket_timeout=2)
                test_cluster.ping()
                app.logger.info("Redis Cluster connection established.")

                app.config['CACHE_TYPE'] = 'RedisClusterCache'
                app.config['CACHE_REDIS_CLUSTER_STARTUP_NODES'] = startup_nodes
                app.config['CACHE_REDIS_PASSWORD'] = redis_password
                cache_ready = True
            except (AuthenticationError, ConnectionError, RedisError) as e:
                app.logger.error(f"Redis Cluster connection failed: {e}")
            except Exception as e:
                app.logger.exception(f"Unexpected error with Redis Cluster: {e}")

        else:
            # Standalone Redis
            redis_host = ini.get('remote_cache', 'redis_host', fallback='127.0.0.1')
            endpoint = f"{redis_host}:{redis_port}"

            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                result = sock.connect_ex((redis_host, redis_port))
                sock.close()

                if result == 0:
                    # Test Redis connection - use socket_keepalive to avoid eventlet greenio issues
                    # when running in restricted security contexts
                    import redis
                    test_redis = redis.StrictRedis(
                        host=redis_host,
                        port=redis_port,
                        db=redis_db,
                        password=redis_password,
                        socket_connect_timeout=2,
                        socket_keepalive=True,
                        socket_keepalive_options={}
                    )
                    test_redis.ping()
                    app.logger.info(f"Redis connection established at {endpoint}")

                    app.config['CACHE_TYPE'] = 'RedisCache'
                    app.config['CACHE_REDIS_HOST'] = redis_host
                    app.config['CACHE_REDIS_PORT'] = redis_port
                    app.config['CACHE_REDIS_DB'] = redis_db
                    app.config['CACHE_REDIS_PASSWORD'] = redis_password
                    # Configure Redis to avoid eventlet greenio issues in restricted environments
                    app.config['CACHE_REDIS_SOCKET_KEEPALIVE'] = True
                    cache_ready = True
                else:
                    app.logger.error(f"Cannot connect to Redis socket at {endpoint}")
            except (AuthenticationError, ConnectionError, RedisError) as e:
                app.logger.error(f"Redis error at {endpoint}: {e}")
            except (PermissionError, OSError) as e:
                # Handle EPERM errors when eventlet greenio can't create sockets
                # due to restricted security contexts (e.g., dropped capabilities)
                if hasattr(e, 'errno') and e.errno == 1:  # EPERM
                    app.logger.warning(f"Redis connection blocked by security context (EPERM) at {endpoint}. "
                                     f"Falling back to in-memory cache. Error: {e}")
                else:
                    app.logger.error(f"Permission/system error connecting to Redis at {endpoint}: {e}")
            except Exception as e:
                app.logger.exception(f"Unexpected Redis error at {endpoint}: {e}")

    if not cache_ready:
        app.logger.warning("Using in-memory fallback cache (SimpleCache)")
        app.config['CACHE_TYPE'] = 'SimpleCache'

    # Optional cache durations
    app.config['SHORT_CACHE_TIMEOUT'] = int(ini.get('remote_cache', 'short_cache_time', fallback='60'))
    app.config['LONG_CACHE_TIMEOUT'] = int(ini.get('remote_cache', 'long_cache_time', fallback='900'))

    # Finalize cache setup
    cache.init_app(app)
    app.cache = cache

    # Post-initialization test: Verify cache actually works (catches EPERM at runtime)
    # This is important because eventlet's greenio may fail even if initial connection test passed
    if cache_ready and app.config.get('CACHE_TYPE') in ('RedisCache', 'RedisClusterCache'):
        try:
            # Test actual cache operations which will use eventlet's greenio if available
            test_key = '__kubedash_cache_test__'
            test_value = 'test'
            cache.set(test_key, test_value, timeout=1)
            retrieved = cache.get(test_key)
            if retrieved == test_value:
                cache.delete(test_key)
                app.logger.info("Cache operations verified successfully")
            else:
                app.logger.warning("Cache test failed: value mismatch. Falling back to SimpleCache")
                cache_ready = False
                app.config['CACHE_TYPE'] = 'SimpleCache'
        except (PermissionError, OSError) as e:
            # Handle EPERM errors when eventlet greenio can't create sockets at runtime
            if hasattr(e, 'errno') and e.errno == 1:  # EPERM
                app.logger.warning(f"Cache operations blocked by security context (EPERM). "
                                 f"Falling back to in-memory cache. Error: {e}")
                cache_ready = False
                app.config['CACHE_TYPE'] = 'SimpleCache'
                # Re-initialize cache with SimpleCache
                cache.init_app(app)
            else:
                app.logger.error(f"Permission/system error during cache operations: {e}")
                cache_ready = False
                app.config['CACHE_TYPE'] = 'SimpleCache'
                cache.init_app(app)
        except Exception as e:
            app.logger.warning(f"Cache test failed with unexpected error: {e}. Falling back to SimpleCache")
            cache_ready = False
            app.config['CACHE_TYPE'] = 'SimpleCache'
            cache.init_app(app)

    # Register decorators or cache-bound setup
    cached_base(app)
    cached_base2(app)
