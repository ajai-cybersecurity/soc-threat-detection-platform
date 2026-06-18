"""Alerts blueprint – view, filter, manage security alerts."""
from datetime import datetime
from flask import Blueprint, render_template, request, jsonify, redirect, url_for, flash
from flask_login import login_required, current_user
from sqlalchemy import desc, func
from app.models.models import db, Alert, Incident
from app.services import threat_intel_service

alerts_bp = Blueprint('alerts', __name__, url_prefix='/alerts')


@alerts_bp.route('/')
@login_required
def index():
    page      = request.args.get('page', 1, type=int)
    severity  = request.args.get('severity', '')
    threat    = request.args.get('threat_type', '')
    status    = request.args.get('status', '')
    search    = request.args.get('q', '')

    query = Alert.query
    if severity:
        query = query.filter(Alert.severity == severity)
    if threat:
        query = query.filter(Alert.threat_type == threat)
    if status:
        query = query.filter(Alert.status == status)
    if search:
        query = query.filter(
            (Alert.source_ip.contains(search)) | (Alert.title.contains(search)) |
            (Alert.username.contains(search)) | (Alert.description.contains(search))
        )

    alerts = query.order_by(desc(Alert.created_at)).paginate(page=page, per_page=25, error_out=False)

    # Summary stats
    stats = {
        'total':    Alert.query.count(),
        'critical': Alert.query.filter_by(severity='critical').count(),
        'high':     Alert.query.filter_by(severity='high').count(),
        'open':     Alert.query.filter_by(status='open').count(),
    }
    threat_types = db.session.query(Alert.threat_type, func.count(Alert.id))\
                             .group_by(Alert.threat_type).all()
    return render_template('alerts/index.html', alerts=alerts, stats=stats,
                           threat_types=threat_types,
                           filters={'severity': severity, 'threat_type': threat, 'status': status, 'q': search})


@alerts_bp.route('/<int:alert_id>')
@login_required
def view_alert(alert_id):
    alert = Alert.query.get_or_404(alert_id)
    return render_template('alerts/view.html', alert=alert)


@alerts_bp.route('/<int:alert_id>/status', methods=['POST'])
@login_required
def update_status(alert_id):
    alert  = Alert.query.get_or_404(alert_id)
    status = request.form.get('status', 'open')
    alert.status = status
    db.session.commit()
    flash(f'Alert status updated to {status}.', 'success')
    return redirect(url_for('alerts.view_alert', alert_id=alert_id))


@alerts_bp.route('/<int:alert_id>/false-positive', methods=['POST'])
@login_required
def mark_false_positive(alert_id):
    alert = Alert.query.get_or_404(alert_id)
    alert.false_positive = True
    alert.status = 'closed'
    db.session.commit()
    return jsonify({'success': True})


@alerts_bp.route('/<int:alert_id>/enrich', methods=['POST'])
@login_required
def enrich_alert_threat_intel(alert_id):
    """
    Enrich alert with threat intelligence from VirusTotal, AbuseIPDB, OTX.
    Automatically caches results for 24 hours.
    """
    alert = Alert.query.get_or_404(alert_id)
    
    try:
        if not alert.source_ip:
            return jsonify({'error': 'Alert has no source IP to enrich'}), 400
        
        # Enrich with threat intelligence
        enrichment = threat_intel_service.enrich_indicator(
            indicator=alert.source_ip,
            indicator_type='ip',
            use_cache=True,
            store_in_db=True
        )
        
        if 'error' in enrichment:
            return jsonify({
                'success': False,
                'error': enrichment.get('error', 'Enrichment failed')
            }), 500
        
        # Update alert with enrichment
        import json
        alert.raw_evidence = json.dumps({
            'original_evidence': json.loads(alert.raw_evidence or '{}'),
            'threat_intel': enrichment
        })
        db.session.commit()
        
        return jsonify({
            'success': True,
            'enrichment': enrichment,
            'cached': enrichment.get('cached', False)
        })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Enrichment failed: {str(e)}'
        }), 500



@login_required
def api_summary():
    from datetime import timedelta
    now    = datetime.utcnow()
    last7  = now - timedelta(days=7)
    summary = {
        'total':      Alert.query.count(),
        'critical':   Alert.query.filter_by(severity='critical').count(),
        'high':       Alert.query.filter_by(severity='high').count(),
        'medium':     Alert.query.filter_by(severity='medium').count(),
        'low':        Alert.query.filter_by(severity='low').count(),
        'open':       Alert.query.filter_by(status='open').count(),
        'last_7d':    Alert.query.filter(Alert.created_at >= last7).count(),
        'top_types':  [{'type': r[0], 'count': r[1]} for r in
                       db.session.query(Alert.threat_type, func.count(Alert.id))
                                 .group_by(Alert.threat_type).order_by(desc(func.count(Alert.id))).limit(5).all()],
    }
    return jsonify(summary)
