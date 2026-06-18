"""
Utility helpers – decorators, validators, audit logging, email alerts.
"""
import re
import uuid
import json
import smtplib
import hashlib
from functools import wraps
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from flask import request, g, current_app, abort
from flask_login import current_user


# ─────────────── DECORATORS ─────────────────────────────────
def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)
            if current_user.role not in roles:
                abort(403)
            return f(*args, **kwargs)
        return decorated
    return decorator


def audit_action(action: str, resource: str = '', resource_id: str = ''):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            result = f(*args, **kwargs)
            try:
                from app.models.models import AuditLog, db
                log = AuditLog(
                    user_id     = current_user.id if current_user.is_authenticated else None,
                    action      = action,
                    resource    = resource,
                    resource_id = str(resource_id or kwargs.get('id', '')),
                    ip_address  = request.remote_addr,
                    user_agent  = request.user_agent.string[:500],
                )
                db.session.add(log)
                db.session.commit()
            except Exception:
                pass
            return result
        return decorated
    return decorator


# ─────────────── VALIDATORS ─────────────────────────────────
def is_valid_ip(ip: str) -> bool:
    if not ip:
        return False
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def is_valid_email(email: str) -> bool:
    return bool(re.match(r'^[^@]+@[^@]+\.[^@]+$', email))


def allowed_file(filename: str, allowed: set) -> bool:
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed


def sanitize_filename(filename: str) -> str:
    filename = re.sub(r'[^\w\s\-\.]', '', filename)
    return filename[:255]


# ─────────────── HASH UTILITIES ─────────────────────────────
def compute_hashes(data: bytes) -> dict:
    return {
        'md5':    hashlib.md5(data).hexdigest(),
        'sha1':   hashlib.sha1(data).hexdigest(),
        'sha256': hashlib.sha256(data).hexdigest(),
    }


def compute_file_hashes(filepath: str) -> dict:
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
        return compute_hashes(data)
    except Exception:
        return {}


# ─────────────── EMAIL ALERTING ─────────────────────────────
def send_alert_email(subject: str, body: str, recipients: list = None):
    try:
        cfg  = current_app.config
        recip = recipients or cfg.get('ALERT_RECIPIENTS', [])
        if not recip or not cfg.get('MAIL_USERNAME'):
            return False
        msg = MIMEMultipart('alternative')
        msg['Subject'] = f'[SOC ALERT] {subject}'
        msg['From']    = cfg.get('MAIL_USERNAME')
        msg['To']      = ', '.join(recip)
        html_body = f"""
<html><body style="font-family:Arial;background:#0d1117;color:#c9d1d9;padding:20px;">
<div style="max-width:600px;margin:auto;background:#161b22;border-radius:8px;padding:24px;">
<h2 style="color:#f85149;">🚨 SOC Security Alert</h2>
<pre style="background:#0d1117;padding:16px;border-radius:6px;overflow:auto;">{body}</pre>
<p style="color:#8b949e;font-size:12px;">SOC Platform – Automated Alert System</p>
</div></body></html>"""
        msg.attach(MIMEText(html_body, 'html'))
        msg.attach(MIMEText(body, 'plain'))
        with smtplib.SMTP(cfg.get('MAIL_SERVER'), cfg.get('MAIL_PORT')) as smtp:
            if cfg.get('MAIL_USE_TLS'):
                smtp.starttls()
            smtp.login(cfg.get('MAIL_USERNAME'), cfg.get('MAIL_PASSWORD'))
            smtp.sendmail(cfg.get('MAIL_USERNAME'), recip, msg.as_string())
        return True
    except Exception as e:
        current_app.logger.error(f'Email alert failed: {e}')
        return False


# ─────────────── PAGINATION HELPER ──────────────────────────
def paginate_query(query, page: int, per_page: int = 25):
    return query.paginate(page=page, per_page=per_page, error_out=False)



# ─────────────── SEVERITY HELPER ────────────────────────────
SEVERITY_ORDER = {'informational': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}

def severity_color(severity: str) -> str:
    return {
        'critical':      '#f85149',
        'high':          '#d29922',
        'medium':        '#e3b341',
        'low':           '#3fb950',
        'informational': '#8b949e',
    }.get(severity.lower() if severity else '', '#8b949e')
