import logging

"""Exclude requests logging"""
class NoPing(logging.Filter):
    def filter(self, record):
        """Filter GET requests for /api/ping endpoint"""
        return 'GET /api/ping' not in record.getMessage()
    
class NoHealth(logging.Filter):
    def filter(self, record):
        """Filter GET requests for /api/health endpoint"""
        return 'GET /api/health' not in record.getMessage()

class NoMetrics(logging.Filter):
    def filter(self, record):
        """Filter GET requests for /api/metrics endpoint"""
        return 'GET /metrics' not in record.getMessage()
   
class NoSocketIoGet(logging.Filter):
    def filter(self, record):
        """Filter GET requests for /socket.io endpoint"""
        return 'GET /socket.io' not in record.getMessage()
    
class NoSocketIoPost(logging.Filter):
    def filter(self, record):
        """Filter POST requests for /socket.io endpoint"""
        return 'POST /socket.io' not in record.getMessage()