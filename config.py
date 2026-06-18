import os
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
_db_path = os.path.join(BASE_DIR, 'instance', 'soc_platform.db')


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'soc-platform-secret-key-change-in-prod')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///' + _db_path)
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    UPLOAD_FOLDER    = os.path.join(BASE_DIR, 'uploads')
    REPORTS_FOLDER   = os.path.join(BASE_DIR, 'reports_output')
    MAX_CONTENT_LENGTH = int(os.environ.get('MAX_CONTENT_LENGTH', 52428800))
    ALLOWED_EXTENSIONS = {'log', 'txt', 'csv', 'evtx', 'xml', 'json'}

    # ─────────────── THREAT INTELLIGENCE APIS ───────────────
    VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '')
    ABUSEIPDB_API_KEY  = os.environ.get('ABUSEIPDB_API_KEY', '')
    OTX_API_KEY        = os.environ.get('OTX_API_KEY', '')

    
    # ─────────────── THREAT INTEL ENRICHMENT ──────────────────
    TI_AUTO_ENRICH      = bool(int(os.environ.get('TI_AUTO_ENRICH', 1)))
    TI_CACHE_TTL        = int(os.environ.get('TI_CACHE_TTL', 86400))  # 24 hours
    TI_BATCH_SIZE       = int(os.environ.get('TI_BATCH_SIZE', 50))
    TI_ENABLE_BACKGROUND_JOBS = bool(int(os.environ.get('TI_ENABLE_BACKGROUND_JOBS', 1)))

    MAIL_SERVER      = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT        = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS     = bool(int(os.environ.get('MAIL_USE_TLS', 1)))
    MAIL_USERNAME    = os.environ.get('MAIL_USERNAME', '')
    MAIL_PASSWORD    = os.environ.get('MAIL_PASSWORD', '')
    ALERT_RECIPIENTS = [r for r in os.environ.get('ALERT_RECIPIENTS', '').split(',') if r]

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SECURE   = bool(int(os.environ.get('SESSION_COOKIE_SECURE', 0)))
    WTF_CSRF_ENABLED        = bool(int(os.environ.get('WTF_CSRF_ENABLED', 1)))

    MONITOR_INTERVAL      = int(os.environ.get('MONITOR_INTERVAL', 30))
    AUTO_REFRESH_INTERVAL = int(os.environ.get('AUTO_REFRESH_INTERVAL', 60))


class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_ECHO = False


class ProductionConfig(Config):
    DEBUG = False
    SESSION_COOKIE_SECURE = True


class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False


config = {
    'development': DevelopmentConfig,
    'production':  ProductionConfig,
    'testing':     TestingConfig,
    'default':     DevelopmentConfig,
}
