"""
SOC Platform – Database Models
All SQLAlchemy ORM models with full relationships and indexes.
"""
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


# ─────────────────────────── USERS ───────────────────────────
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(80),  unique=True, nullable=False, index=True)
    email         = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    role          = db.Column(db.String(20),  nullable=False, default='analyst')   # admin/soc_manager/analyst/viewer
    organization  = db.Column(db.String(100), default='Default Org')
    department    = db.Column(db.String(100), default='SOC')
    is_active     = db.Column(db.Boolean, default=True)
    mfa_enabled   = db.Column(db.Boolean, default=False)
    mfa_secret    = db.Column(db.String(32))
    last_login    = db.Column(db.DateTime)
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at    = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    incidents  = db.relationship('Incident', backref='assigned_analyst', lazy='dynamic', foreign_keys='Incident.analyst_id')
    audit_logs = db.relationship('AuditLog', backref='user', lazy='dynamic')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def has_role(self, *roles):
        return self.role in roles

    def to_dict(self):
        return {
            'id': self.id, 'username': self.username, 'email': self.email,
            'role': self.role, 'organization': self.organization,
            'is_active': self.is_active, 'last_login': str(self.last_login or ''),
        }


# ─────────────────────────── LOGS ────────────────────────────
class LogEntry(db.Model):
    __tablename__ = 'logs'
    id          = db.Column(db.Integer, primary_key=True)
    timestamp   = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    source_file = db.Column(db.String(255))
    log_type    = db.Column(db.String(50),  index=True)   # auth/syslog/apache/nginx/windows/sysmon/firewall/winevent
    raw_log     = db.Column(db.Text)
    parsed_data = db.Column(db.Text)          # JSON string
    source_ip   = db.Column(db.String(45),   index=True)
    destination_ip = db.Column(db.String(45))
    username    = db.Column(db.String(100),  index=True)
    hostname    = db.Column(db.String(255))
    event_id    = db.Column(db.String(20),   index=True)
    severity    = db.Column(db.String(20),   default='info', index=True)
    is_threat   = db.Column(db.Boolean,      default=False, index=True)
    upload_id   = db.Column(db.Integer,      db.ForeignKey('log_uploads.id'))
    created_at  = db.Column(db.DateTime,     default=datetime.utcnow)

    alerts = db.relationship('Alert', backref='log_entry', lazy='dynamic')

    def to_dict(self):
        return {
            'id': self.id, 'timestamp': str(self.timestamp),
            'log_type': self.log_type, 'source_ip': self.source_ip,
            'username': self.username, 'hostname': self.hostname,
            'event_id': self.event_id, 'severity': self.severity,
            'is_threat': self.is_threat, 'raw_log': self.raw_log,
        }


class LogUpload(db.Model):
    __tablename__ = 'log_uploads'
    id          = db.Column(db.Integer, primary_key=True)
    filename    = db.Column(db.String(255), nullable=False)
    original_name = db.Column(db.String(255))
    log_type    = db.Column(db.String(50))
    file_size   = db.Column(db.Integer)
    total_lines = db.Column(db.Integer, default=0)
    parsed_lines = db.Column(db.Integer, default=0)
    threat_count = db.Column(db.Integer, default=0)
    status      = db.Column(db.String(20), default='processing')  # processing/completed/failed
    uploaded_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)

    logs = db.relationship('LogEntry', backref='upload', lazy='dynamic')


# ─────────────────────────── ALERTS ──────────────────────────
class Alert(db.Model):
    __tablename__ = 'alerts'
    id           = db.Column(db.Integer, primary_key=True)
    alert_id     = db.Column(db.String(50), unique=True, index=True)
    timestamp    = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    title        = db.Column(db.String(255), nullable=False)
    description  = db.Column(db.Text)
    threat_type  = db.Column(db.String(100), index=True)
    severity     = db.Column(db.String(20),  index=True)   # informational/low/medium/high/critical
    source_ip    = db.Column(db.String(45),  index=True)
    destination_ip = db.Column(db.String(45))
    username     = db.Column(db.String(100))
    hostname     = db.Column(db.String(255))
    event_count  = db.Column(db.Integer, default=1)
    log_id       = db.Column(db.Integer, db.ForeignKey('logs.id'))
    incident_id  = db.Column(db.Integer, db.ForeignKey('incidents.id'))
    mitre_tactic = db.Column(db.String(100))
    mitre_technique = db.Column(db.String(100))
    raw_evidence = db.Column(db.Text)          # JSON
    status       = db.Column(db.String(20), default='open')
    false_positive = db.Column(db.Boolean, default=False)
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id, 'alert_id': self.alert_id, 'title': self.title,
            'threat_type': self.threat_type, 'severity': self.severity,
            'source_ip': self.source_ip, 'username': self.username,
            'timestamp': str(self.timestamp), 'status': self.status,
            'mitre_tactic': self.mitre_tactic, 'mitre_technique': self.mitre_technique,
        }


# ─────────────────────────── INCIDENTS ───────────────────────
class Incident(db.Model):
    __tablename__ = 'incidents'
    id           = db.Column(db.Integer, primary_key=True)
    incident_id  = db.Column(db.String(50), unique=True, index=True)
    title        = db.Column(db.String(255), nullable=False)
    description  = db.Column(db.Text)
    threat_type  = db.Column(db.String(100))
    severity     = db.Column(db.String(20), index=True)
    status       = db.Column(db.String(30), default='open', index=True)  # open/investigating/contained/resolved/closed
    source_ip    = db.Column(db.String(45))
    target_asset = db.Column(db.String(255))
    analyst_id   = db.Column(db.Integer, db.ForeignKey('users.id'))
    analyst_notes = db.Column(db.Text)
    attack_chain = db.Column(db.Text)   # JSON
    mitre_mapping = db.Column(db.Text)  # JSON
    timeline     = db.Column(db.Text)   # JSON
    created_at   = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at   = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    resolved_at  = db.Column(db.DateTime)

    alerts   = db.relationship('Alert',   backref='incident', lazy='dynamic')
    comments = db.relationship('IncidentComment', backref='incident', lazy='dynamic', cascade='all, delete-orphan')

    def to_dict(self):
        return {
            'id': self.id, 'incident_id': self.incident_id, 'title': self.title,
            'severity': self.severity, 'status': self.status,
            'source_ip': self.source_ip, 'target_asset': self.target_asset,
            'created_at': str(self.created_at), 'updated_at': str(self.updated_at),
        }


class IncidentComment(db.Model):
    __tablename__ = 'incident_comments'
    id          = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.Integer, db.ForeignKey('incidents.id'), nullable=False)
    author_id   = db.Column(db.Integer, db.ForeignKey('users.id'))
    comment     = db.Column(db.Text, nullable=False)
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)

    author = db.relationship('User', backref='comments')


# ──────────────────────── THREAT INTEL ───────────────────────
class ThreatIntelligence(db.Model):
    __tablename__ = 'threat_intelligence'
    id           = db.Column(db.Integer, primary_key=True)
    indicator    = db.Column(db.String(255), nullable=False, index=True)
    indicator_type = db.Column(db.String(50))  # ip/domain/hash/url
    source       = db.Column(db.String(100))   # virustotal/abuseipdb/otx/manual
    reputation_score = db.Column(db.Float, default=0.0)
    is_malicious = db.Column(db.Boolean, default=False)
    tags         = db.Column(db.String(500))
    country      = db.Column(db.String(100))
    asn          = db.Column(db.String(100))
    raw_response = db.Column(db.Text)
    last_checked = db.Column(db.DateTime, default=datetime.utcnow)
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id, 'indicator': self.indicator, 'indicator_type': self.indicator_type,
            'source': self.source, 'reputation_score': self.reputation_score,
            'is_malicious': self.is_malicious, 'country': self.country,
            'last_checked': str(self.last_checked),
        }


# ─────────────────────────── REPORTS ─────────────────────────
class Report(db.Model):
    __tablename__ = 'reports'
    id          = db.Column(db.Integer, primary_key=True)
    title       = db.Column(db.String(255), nullable=False)
    report_type = db.Column(db.String(50))   # pdf/csv/executive
    file_path   = db.Column(db.String(500))
    generated_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    date_from   = db.Column(db.DateTime)
    date_to     = db.Column(db.DateTime)
    parameters  = db.Column(db.Text)   # JSON
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)

    generator = db.relationship('User', backref='reports')


# ─────────────────────────── AUDIT ───────────────────────────
class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey('users.id'))
    action     = db.Column(db.String(100), index=True)
    resource   = db.Column(db.String(100))
    resource_id = db.Column(db.String(50))
    details    = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)


# ─────────────────────── BEHAVIOR ANALYTICS ──────────────────
class UserBehaviorBaseline(db.Model):
    __tablename__ = 'user_behavior_baselines'
    id           = db.Column(db.Integer, primary_key=True)
    username     = db.Column(db.String(100), nullable=False, index=True)
    normal_hours = db.Column(db.String(50), default='08:00-18:00')
    normal_ips   = db.Column(db.Text)       # JSON list
    avg_daily_logins = db.Column(db.Float, default=0)
    last_known_location = db.Column(db.String(100))
    risk_score   = db.Column(db.Float, default=0.0)
    updated_at   = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class BehaviorAnomaly(db.Model):
    __tablename__ = 'behavior_anomalies'
    id           = db.Column(db.Integer, primary_key=True)
    username     = db.Column(db.String(100), index=True)
    anomaly_type = db.Column(db.String(100))   # impossible_travel/off_hours/unusual_access
    description  = db.Column(db.Text)
    risk_score   = db.Column(db.Float, default=0.0)
    source_ip    = db.Column(db.String(45))
    detected_at  = db.Column(db.DateTime, default=datetime.utcnow)
    resolved     = db.Column(db.Boolean, default=False)


# ─────────────────────── FORENSICS ───────────────────────────
class ForensicArtifact(db.Model):
    __tablename__ = 'forensic_artifacts'
    id           = db.Column(db.Integer, primary_key=True)
    incident_id  = db.Column(db.Integer, db.ForeignKey('incidents.id'))
    artifact_type = db.Column(db.String(50))   # file/hash/process/network/registry
    name         = db.Column(db.String(255))
    value        = db.Column(db.Text)
    md5_hash     = db.Column(db.String(32))
    sha1_hash    = db.Column(db.String(40))
    sha256_hash  = db.Column(db.String(64))
    is_malicious = db.Column(db.Boolean)
    notes        = db.Column(db.Text)
    collected_at = db.Column(db.DateTime, default=datetime.utcnow)
    collected_by = db.Column(db.Integer, db.ForeignKey('users.id'))


# ─────────────── THREAT INTEL CACHING (PHASE 1) ──────────────
class ThreatIntelCache(db.Model):
    """
    Cache for threat intelligence enrichment results.
    Reduces duplicate API calls and improves performance.
    TTL-based expiration via background job.
    """
    __tablename__ = 'threat_intel_cache'
    id              = db.Column(db.Integer, primary_key=True)
    indicator       = db.Column(db.String(255), nullable=False, index=True, unique=True)
    indicator_type  = db.Column(db.String(50))  # ip/domain/hash/url
    
    # Aggregated results from all providers
    malicious_score = db.Column(db.Float, default=0.0)     # 0-100
    suspicious_score = db.Column(db.Float, default=0.0)     # 0-100
    harmless_score  = db.Column(db.Float, default=0.0)      # 0-100
    reputation_score = db.Column(db.Float, default=0.0)     # 0-100
    
    # Provider-specific data (JSON)
    virustotal_data = db.Column(db.Text)  # Cached VT response
    abuseipdb_data  = db.Column(db.Text)  # Cached AbuseIPDB response
    otx_data        = db.Column(db.Text)  # Cached OTX response
    
    # Unified metadata
    tags            = db.Column(db.String(1000))  # Comma-separated
    country         = db.Column(db.String(100))
    asn             = db.Column(db.String(100))
    isp             = db.Column(db.String(255))
    is_malicious    = db.Column(db.Boolean, default=False, index=True)
    
    # Cache lifecycle
    cached_at       = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at      = db.Column(db.DateTime)
    
    def is_expired(self):
        return datetime.utcnow() > self.expires_at if self.expires_at else False


# ────────── CORRELATION ENGINE (PHASE 6) ──────────────────────
class CorrelationLink(db.Model):
    """
    Links between alerts/incidents that form attack chains.
    Supports correlation engine visualization and analysis.
    """
    __tablename__ = 'correlation_links'
    id              = db.Column(db.Integer, primary_key=True)
    
    # Source & target
    source_alert_id = db.Column(db.Integer, db.ForeignKey('alerts.id'), index=True)
    target_alert_id = db.Column(db.Integer, db.ForeignKey('alerts.id'), index=True)
    
    # Correlation metadata
    correlation_type = db.Column(db.String(50))   # same_source_ip/same_user/same_process/etc
    confidence      = db.Column(db.Float, default=0.0)  # 0-1
    pattern         = db.Column(db.String(255))   # Attack pattern name (e.g., "brute_force_to_privesc")
    
    # Timeline
    time_delta_seconds = db.Column(db.Integer)    # Seconds between events
    sequence_order  = db.Column(db.Integer)       # Order in attack chain
    
    created_at      = db.Column(db.DateTime, default=datetime.utcnow)
    
    __table_args__ = (db.Index('ix_correlation_links_timeline', 'source_alert_id', 'target_alert_id', 'sequence_order'),)


# ───────── THREAT HUNTING QUERIES ─────────────────────────
class ThreatHuntingQuery(db.Model):
    """
    Saved threat hunting queries and results.
    """
    __tablename__ = 'threat_hunting_queries'
    id              = db.Column(db.Integer, primary_key=True)
    
    # Query definition
    natural_language = db.Column(db.Text)         # "Show lateral movement activity from 192.168.1.100"
    query_type      = db.Column(db.String(50))    # ip_hunt/hash_hunt/user_hunt/pattern_hunt
    
    # Execution
    execution_query = db.Column(db.Text)          # Generated SQL/filter logic (JSON)
    search_scope    = db.Column(db.String(50))    # logs/alerts/incidents/all
    
    # Results metadata
    result_count    = db.Column(db.Integer, default=0)
    first_result_at = db.Column(db.DateTime)
    last_result_at  = db.Column(db.DateTime)
    
    # Targeting
    target_indicator = db.Column(db.String(255), index=True)  # IP/hash/domain/user
    target_type     = db.Column(db.String(50))    # ip/hash/domain/url/username/hostname
    
    # Metadata
    created_by      = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at      = db.Column(db.DateTime, default=datetime.utcnow)


class IOCIndicator(db.Model):
    """
    Indicators of Compromise for threat hunting.
    Can be manually added or imported from STIX/CSV.
    """
    __tablename__ = 'ioc_indicators'
    id              = db.Column(db.Integer, primary_key=True)
    indicator       = db.Column(db.String(255), nullable=False, index=True)
    indicator_type  = db.Column(db.String(50))    # ip/domain/hash/url/email/username
    
    source          = db.Column(db.String(100))   # manual/stix_feed/csv_import
    threat_type     = db.Column(db.String(100))   # malware/ransomware/botnet/phishing
    severity        = db.Column(db.String(20))    # low/medium/high/critical
    
    # Context
    description     = db.Column(db.Text)
    mitre_techniques = db.Column(db.String(500))  # Comma-separated
    
    # Hunting metrics
    occurrences_in_logs = db.Column(db.Integer, default=0)
    occurrences_in_alerts = db.Column(db.Integer, default=0)
    related_alerts_count = db.Column(db.Integer, default=0)
    
    # Timeline
    first_seen      = db.Column(db.DateTime)
    last_seen       = db.Column(db.DateTime)
    imported_at     = db.Column(db.DateTime, default=datetime.utcnow)
    
    created_by      = db.Column(db.Integer, db.ForeignKey('users.id'))
