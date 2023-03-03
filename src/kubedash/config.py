class Config(object):
    """
    Common configurations
    """
    DEBUG = True
    SQLALCHEMY_TRACK_MODIFICATIONS = True
    SESSION_COOKIE_SECURE = True
    REMEMBER_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    PERMANENT_SESSION_LIFETIME = 600
    SECRET_KEY = "FesC9cBSuxakv9yN0vBY"

class DevelopmentConfig(Config):
    """
    Development configurations
    """
    #SQLALCHEMY_ECHO = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///development.db"

class ProductionConfig(Config):
    """
    Production configurations
    """
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = "sqlite:///production.db"

class TestingConfig(Config):
    """
    Testing configurations
    """
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///testing.db"
    WTF_CSRF_ENABLED = False

app_config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig
}