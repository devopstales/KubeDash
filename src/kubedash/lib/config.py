import os

basedir = os.path.abspath(os.path.dirname(__file__))
class Config(object):
    """
    Common configurations
    """
    # sqlAlchemi config   
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    # apiflask config
    DOCS_FAVICON = "/vendor/wagger-ui@5.0/favicon.svg"
    SWAGGER_UI_CSS = "/vendor/wagger-ui@5.0/swagger-ui.css"
    SWAGGER_UI_BUNDLE_JS = "/vendor/wagger-ui@5.0/swagger-ui-bundle.js"
    SWAGGER_UI_STANDALONE_PRESET_JS = "/vendor/wagger-ui@5.0/swagger-ui-standalone-preset.js"
    # cookie config
    REMEMBER_COOKIE_SECURE = True
    REMEMBER_COOKIE_HTTPONLY = True
    # session config
    PERMANENT_SESSION_LIFETIME = 600
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_TYPE = "sqlalchemy"
    SESSION_REDIS_URL = None
    SESSION_KEY_PREFIX = "kubedash:session:"
    SESSION_FILE_DIR = "/tmp/kubedash-sessions"
    SESSION_PERMANENT = False
    SESSION_USE_SIGNER = True
    # replica mode
    REPLICA_MODE = "single"
    REPLICA_COUNT = 1
    LEADER_ELECTION_ENABLED = False
    LEADER_ELECTION_LEASE_NAME = "kubedash-leader-election"
    LEADER_ELECTION_LEASE_DURATION = 30
    LEADER_ELECTION_RENEW_DEADLINE = 20
    LEADER_ELECTION_RETRY_PERIOD = 5
    # security
    CORS_HEADERS = 'Content-Type'
    SECRET_KEY = "develop"
    WTF_CSRF_ENABLED = True

class DevelopmentConfig(Config):
    """
    Development configurations
    """
    #SQLALCHEMY_ECHO = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///"+basedir+"/database/development.db"
    DEBUG = True

class ProductionConfig(Config):
    """
    Production configurations
    """
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = "sqlite:///"+basedir+"/database/production.db"

class TestingConfig(Config):
    """
    Testing configurations
    """
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///"+basedir+"/database/testing.db"
    WTF_CSRF_ENABLED = False

app_config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig
}