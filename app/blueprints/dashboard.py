"""Dashboard blueprint – main SOC overview with all stats and charts."""
from datetime import datetime, timedelta
from collections import defaultdict
from flask import Blueprint, render_template, jsonify
from flask_login import login_required
from sqlalchemy import func, desc
from app.models.models import db, LogEntry, Alert, Incident, LogUpload, BehaviorAnomaly

dashboard_bp = Blueprint('dashboard', __name__)


def _get_stats():
    now = datetime.utcnow()
    last_24h = now - timedelta(hours=24)
    last_7d  = now - timedelta(days=7)

    total_logs    = db.session.query(func.count(LogEntry.id)).scalar() or 0
    total_alerts  = db.session.query(func.count(Alert.id)).scalar() or 0
    total_incidents = db.session.query(func.count(Incident.id)).scalar() or 0
    critical_alerts = db.session.query(func.count(Alert.id)).filter(Alert.severity == 'critical').scalar() or 0
    high_alerts     = db.session.query(func.count(Alert.id)).filter(Alert.severity == 'high').scalar() or 0
    medium_alerts   = db.session.query(func.count(Alert.id)).filter(Alert.severity == 'medium').scalar() or 0
    low_alerts      = db.session.query(func.count(Alert.id)).filter(Alert.severity == 'low').scalar() or 0
    open_incidents  = db.session.query(func.count(Incident.id)).filter(Incident.status == 'open').scalar() or 0
    unique_ips      = db.session.query(func.count(func.distinct(Alert.source_ip))).scalar() or 0
    logs_24h        = db.session.query(func.count(LogEntry.id)).filter(LogEntry.created_at >= last_24h).scalar() or 0
    alerts_24h      = db.session.query(func.count(Alert.id)).filter(Alert.created_at >= last_24h).scalar() or 0

    # Threats over time (last 7 days)
    threats_timeline = []
    for i in range(7):
        day_start = (now - timedelta(days=6-i)).replace(hour=0, minute=0, second=0, microsecond=0)
        day_end   = day_start + timedelta(days=1)
        count     = db.session.query(func.count(Alert.id)).filter(
            Alert.created_at >= day_start, Alert.created_at < day_end).scalar() or 0
        threats_timeline.append({'date': day_start.strftime('%m/%d'), 'count': count})

    # Top attack sources
    top_ips = db.session.query(
        Alert.source_ip, func.count(Alert.id).label('count')
    ).filter(Alert.source_ip != None).group_by(Alert.source_ip)\
     .order_by(desc('count')).limit(10).all()

    # Severity distribution
    sev_dist = {'critical': critical_alerts, 'high': high_alerts,
                'medium': medium_alerts, 'low': low_alerts}

    # Threat types
    top_threats = db.session.query(
        Alert.threat_type, func.count(Alert.id).label('count')
    ).group_by(Alert.threat_type).order_by(desc('count')).limit(8).all()

    # Recent alerts
    recent_alerts = Alert.query.order_by(desc(Alert.created_at)).limit(10).all()

    # Recent incidents
    recent_incidents = Incident.query.order_by(desc(Incident.created_at)).limit(5).all()

    # Log type distribution
    log_types = db.session.query(
        LogEntry.log_type, func.count(LogEntry.id).label('count')
    ).group_by(LogEntry.log_type).all()

    return {
        'total_logs':        total_logs,
        'total_alerts':      total_alerts,
        'total_incidents':   total_incidents,
        'critical_alerts':   critical_alerts,
        'high_alerts':       high_alerts,
        'medium_alerts':     medium_alerts,
        'low_alerts':        low_alerts,
        'open_incidents':    open_incidents,
        'unique_ips':        unique_ips,
        'logs_24h':          logs_24h,
        'alerts_24h':        alerts_24h,
        'threats_timeline':  threats_timeline,
        'top_ips':           [{'ip': r.source_ip, 'count': r.count} for r in top_ips],
        'severity_dist':     sev_dist,
        'top_threats':       [{'type': r.threat_type, 'count': r.count} for r in top_threats],
        'recent_alerts':     [a.to_dict() for a in recent_alerts],
        'recent_incidents':  [i.to_dict() for i in recent_incidents],
        'log_types':         [{'type': r.log_type, 'count': r.count} for r in log_types],
    }


@dashboard_bp.route('/')
@login_required
def index():
    stats = _get_stats()
    return render_template('dashboard/index.html', stats=stats)


@dashboard_bp.route('/api/stats')
@login_required
def api_stats():
    return jsonify(_get_stats())


@dashboard_bp.route('/api/live-alerts')
@login_required
def live_alerts():
    from flask import request as req
    since = req.args.get('since', '')
    query = Alert.query.order_by(desc(Alert.created_at))
    if since:
        try:
            dt = datetime.fromisoformat(since)
            query = query.filter(Alert.created_at > dt)
        except Exception:
            pass
    alerts = query.limit(20).all()
    return jsonify({'alerts': [a.to_dict() for a in alerts],
                    'timestamp': datetime.utcnow().isoformat()})
