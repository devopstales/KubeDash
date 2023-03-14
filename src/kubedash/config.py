import os

basedir = os.path.abspath(os.path.dirname(__file__))
class Config(object):
    """
    Common configurations
    """
    DEBUG = True
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SESSION_COOKIE_SECURE = True
    REMEMBER_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    PERMANENT_SESSION_LIFETIME = 600
    SECRET_KEY = "develop"

class DevelopmentConfig(Config):
    """
    Development configurations
    """
    #SQLALCHEMY_ECHO = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///"+basedir+"/database/development.db"

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