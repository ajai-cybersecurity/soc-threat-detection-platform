"""
Logs blueprint – upload, parse, view, search log files.
DELETE cascade removes all alerts/incidents tied to that upload's logs.
"""
import os
import uuid
import json
from datetime import datetime
from flask import (Blueprint, render_template, request, redirect, url_for,
                   flash, jsonify, current_app)
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from sqlalchemy import desc, func

from app.models.models import db, LogEntry, LogUpload, Alert, Incident
from app.parsers import parse_log_file
from app.detectors import ThreatDetector
from app.detectors.correlation_engine import CorrelationEngine
from app.utils.helpers import allowed_file, sanitize_filename, send_alert_email
from app.utils.behavior_analytics import behavior_analytics

logs_bp    = Blueprint('logs', __name__, url_prefix='/logs')
detector   = ThreatDetector()
correlator = CorrelationEngine()


# ── Helpers ───────────────────────────────────────────────────
def _alert_ids_for_upload(upload_id: int):
    """Return all alert IDs whose log_id belongs to this upload."""
    log_ids = db.session.query(LogEntry.id).filter_by(upload_id=upload_id).all()
    log_ids = [r[0] for r in log_ids]
    if not log_ids:
        return []
    alert_ids = db.session.query(Alert.id).filter(Alert.log_id.in_(log_ids)).all()
    return [r[0] for r in alert_ids]


def _cascade_delete_upload(upload_id: int):
    """Delete upload + its log entries + their alerts + orphaned incidents."""
    # 1. Gather alert IDs linked to this upload's log entries
    log_ids = [r[0] for r in db.session.query(LogEntry.id).filter_by(upload_id=upload_id).all()]
    alert_ids = []
    if log_ids:
        alert_ids = [r[0] for r in db.session.query(Alert.id).filter(Alert.log_id.in_(log_ids)).all()]

    # 2. Also grab alerts that carry the upload's source_file path
    upload = LogUpload.query.get(upload_id)
    if upload:
        path_alerts = [r[0] for r in db.session.query(Alert.id)
                       .join(LogEntry, Alert.log_id == LogEntry.id)
                       .filter(LogEntry.upload_id == upload_id).all()]
        alert_ids = list(set(alert_ids + path_alerts))

    # 3. Collect incident IDs tied to those alerts
    incident_ids = []
    if alert_ids:
        incident_ids = list(set(
            r[0] for r in db.session.query(Alert.incident_id)
                                    .filter(Alert.id.in_(alert_ids))
                                    .filter(Alert.incident_id != None).all()
        ))

    # 4. Detach alerts from incidents then delete alerts
    if alert_ids:
        Alert.query.filter(Alert.id.in_(alert_ids)).delete(synchronize_session=False)

    # 5. Delete incidents that now have zero remaining alerts
    for inc_id in incident_ids:
        remaining = Alert.query.filter_by(incident_id=inc_id).count()
        if remaining == 0:
            Incident.query.filter_by(id=inc_id).delete(synchronize_session=False)

    # 6. Delete log entries and upload record
    LogEntry.query.filter_by(upload_id=upload_id).delete(synchronize_session=False)
    if upload:
        db.session.delete(upload)

    db.session.commit()


# ── Routes ────────────────────────────────────────────────────
@logs_bp.route('/')
@login_required
def index():
    page     = request.args.get('page', 1, type=int)
    log_type = request.args.get('type', '')
    severity = request.args.get('severity', '')
    search   = request.args.get('q', '')
    upload_f = request.args.get('upload_id', '', type=str)
    show_all = request.args.get('show_all', '0')   # '0'=threats only, '1'=all entries

    query = LogEntry.query
    if upload_f:
        query = query.filter(LogEntry.upload_id == int(upload_f))
    if log_type:
        query = query.filter(LogEntry.log_type == log_type)
    if severity:
        query = query.filter(LogEntry.severity == severity)
    if show_all == '0':
        # default: show only threat entries
        pass  # show all entries but mark them — filter handled in template
    if search:
        query = query.filter(
            (LogEntry.source_ip.contains(search)) |
            (LogEntry.username.contains(search)) |
            (LogEntry.raw_log.contains(search))
        )

    logs      = query.order_by(desc(LogEntry.timestamp)).paginate(page=page, per_page=50, error_out=False)
    uploads   = LogUpload.query.order_by(desc(LogUpload.uploaded_at)).all()
    log_types = db.session.query(LogEntry.log_type, func.count(LogEntry.id)).group_by(LogEntry.log_type).all()

    # Per-upload stats for the sidebar
    upload_stats = {}
    for u in uploads:
        total  = LogEntry.query.filter_by(upload_id=u.id).count()
        threat = LogEntry.query.filter_by(upload_id=u.id, is_threat=True).count()
        alrt   = Alert.query.join(LogEntry, Alert.log_id == LogEntry.id)\
                            .filter(LogEntry.upload_id == u.id).count()
        upload_stats[u.id] = {'total': total, 'threat': threat, 'alerts': alrt}

    return render_template('logs/index.html',
                           logs=logs, uploads=uploads, log_types=log_types,
                           upload_stats=upload_stats,
                           filters={'type': log_type, 'severity': severity,
                                    'q': search, 'upload_id': upload_f, 'show_all': show_all})


@logs_bp.route('/entries')
@login_required
def all_entries():
    """Full log viewer — shows EVERY entry (threat + non-threat) with alert indicator."""
    page      = request.args.get('page', 1, type=int)
    upload_f  = request.args.get('upload_id', '', type=str)
    log_type  = request.args.get('type', '')
    entry_filter = request.args.get('entry_filter', 'all')  # all / threat / clean
    search    = request.args.get('q', '')

    query = LogEntry.query
    if upload_f:
        query = query.filter(LogEntry.upload_id == int(upload_f))
    if log_type:
        query = query.filter(LogEntry.log_type == log_type)
    if entry_filter == 'threat':
        query = query.filter(LogEntry.is_threat == True)
    elif entry_filter == 'clean':
        query = query.filter(LogEntry.is_threat == False)
    if search:
        query = query.filter(
            (LogEntry.source_ip.contains(search)) |
            (LogEntry.username.contains(search)) |
            (LogEntry.raw_log.contains(search))
        )

    logs      = query.order_by(desc(LogEntry.timestamp)).paginate(page=page, per_page=100, error_out=False)
    uploads   = LogUpload.query.order_by(desc(LogUpload.uploaded_at)).all()
    log_types = db.session.query(LogEntry.log_type, func.count(LogEntry.id)).group_by(LogEntry.log_type).all()

    # Build alert map: log_id -> alert info
    visible_ids = [l.id for l in logs.items]
    alert_map   = {}
    if visible_ids:
        alerts_for_logs = Alert.query.filter(Alert.log_id.in_(visible_ids)).all()
        for a in alerts_for_logs:
            alert_map[a.log_id] = a

    # Count stats for this view
    total_count  = LogEntry.query.count()
    threat_count = LogEntry.query.filter_by(is_threat=True).count()
    clean_count  = total_count - threat_count

    if upload_f:
        uid = int(upload_f)
        total_count  = LogEntry.query.filter_by(upload_id=uid).count()
        threat_count = LogEntry.query.filter_by(upload_id=uid, is_threat=True).count()
        clean_count  = total_count - threat_count

    return render_template('logs/all_entries.html',
                           logs=logs, uploads=uploads, log_types=log_types,
                           alert_map=alert_map,
                           total_count=total_count,
                           threat_count=threat_count,
                           clean_count=clean_count,
                           filters={'type': log_type, 'q': search,
                                    'upload_id': upload_f, 'entry_filter': entry_filter})


@logs_bp.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        if 'logfile' not in request.files:
            flash('No file selected.', 'danger')
            return redirect(request.url)

        file     = request.files['logfile']
        log_type = request.form.get('log_type', 'auto')
        if file.filename == '':
            flash('No file selected.', 'danger')
            return redirect(request.url)

        allowed = current_app.config.get('ALLOWED_EXTENSIONS', {'log', 'txt', 'csv', 'xml', 'json', 'evtx'})
        if not allowed_file(file.filename, allowed):
            flash(f'Unsupported file type. Allowed: {", ".join(allowed)}', 'danger')
            return redirect(request.url)

        filename    = secure_filename(sanitize_filename(file.filename))
        unique_name = f'{uuid.uuid4().hex[:8]}_{filename}'
        folder      = current_app.config.get('UPLOAD_FOLDER', 'uploads')
        os.makedirs(folder, exist_ok=True)
        filepath    = os.path.join(folder, unique_name)
        file.save(filepath)

        upload_rec = LogUpload(
            filename      = unique_name,
            original_name = filename,
            log_type      = log_type,
            file_size     = os.path.getsize(filepath),
            status        = 'processing',
            uploaded_by   = current_user.id,
        )
        db.session.add(upload_rec)
        db.session.commit()

        result = _process_log_file(filepath, log_type, upload_rec.id)
        flash(
            f'✔ Processed {result["parsed"]} entries — '
            f'{result["threats"]} threats, {result["alerts"]} alerts generated.',
            'success'
        )
        return redirect(url_for('logs.index'))

    return render_template('logs/upload.html')


def _process_log_file(filepath: str, log_type: str, upload_id: int) -> dict:
    try:
        parsed_logs, detected_type = parse_log_file(filepath, log_type if log_type != 'auto' else None)

        # Save log entries and capture their DB IDs
        entries = []
        for p in parsed_logs:
            e = LogEntry(
                timestamp      = p.get('timestamp', datetime.utcnow()),
                source_file    = filepath,
                log_type       = p.get('log_type', detected_type),
                raw_log        = (p.get('raw_log') or '')[:2000],
                parsed_data    = p.get('parsed_data', ''),
                source_ip      = p.get('source_ip'),
                destination_ip = p.get('destination_ip'),
                username       = p.get('username'),
                hostname       = p.get('hostname'),
                event_id       = str(p.get('event_id', ''))[:20] if p.get('event_id') else None,
                severity       = p.get('severity', 'informational'),
                is_threat      = p.get('is_threat', False),
                upload_id      = upload_id,
            )
            db.session.add(e)
            entries.append((e, p))

        db.session.flush()   # assign IDs without committing

        # Run threat detection
        raw_alerts = detector.analyze_parsed_logs(parsed_logs)

        # Build source_ip -> log_id map for linking alerts to log entries
        ip_to_log_id = {}
        for entry_obj, p in entries:
            if p.get('source_ip') and p.get('source_ip') not in ip_to_log_id:
                ip_to_log_id[p['source_ip']] = entry_obj.id

        for a in raw_alerts:
            alert = Alert(
                alert_id        = a['alert_id'],
                title           = a['title'][:255],
                description     = a.get('description', ''),
                threat_type     = a.get('threat_type', ''),
                severity        = a.get('severity', 'low'),
                source_ip       = a.get('source_ip'),
                destination_ip  = a.get('destination_ip'),
                username        = a.get('username'),
                hostname        = a.get('hostname'),
                timestamp       = a.get('timestamp', datetime.utcnow()),
                mitre_tactic    = a.get('mitre_tactic', ''),
                mitre_technique = a.get('mitre_technique', ''),
                event_count     = a.get('event_count', 1),
                raw_evidence    = a.get('raw_evidence', ''),
                log_id          = ip_to_log_id.get(a.get('source_ip')),
            )
            db.session.add(alert)

        db.session.commit()

        # Email critical alerts
        critical = [a for a in raw_alerts if a.get('severity') == 'critical']
        if critical:
            try:
                body = '\n'.join([f"[{a['severity'].upper()}] {a['title']} | IP: {a.get('source_ip','N/A')}"
                                  for a in critical[:5]])
                send_alert_email(f'{len(critical)} Critical Alert(s) Detected', body)
            except Exception:
                pass

        # Correlation → incidents
        incidents_data = correlator.correlate(raw_alerts)
        for inc_data in incidents_data:
            inc = Incident(
                incident_id   = f'INC-{uuid.uuid4().hex[:8].upper()}',
                title         = inc_data['title'],
                description   = inc_data['description'],
                threat_type   = inc_data['threat_type'],
                severity      = inc_data['severity'],
                source_ip     = inc_data.get('source_ip'),
                target_asset  = inc_data.get('target_asset', 'Unknown'),
                attack_chain  = inc_data.get('attack_chain', ''),
                mitre_mapping = inc_data.get('mitre_mapping', ''),
                timeline      = inc_data.get('timeline', ''),
                status        = 'open',
            )
            db.session.add(inc)
        db.session.commit()

        # Behavior analytics
        anomalies = behavior_analytics.analyze_user_behavior(parsed_logs)
        behavior_analytics.save_anomalies(anomalies)

        # Update upload record
        rec = LogUpload.query.get(upload_id)
        if rec:
            rec.total_lines  = len(parsed_logs)
            rec.parsed_lines = len(parsed_logs)
            rec.threat_count = sum(1 for p in parsed_logs if p.get('is_threat'))
            rec.status       = 'completed'
            rec.completed_at = datetime.utcnow()
            db.session.commit()

        return {'parsed': len(parsed_logs),
                'threats': rec.threat_count if rec else 0,
                'alerts': len(raw_alerts),
                'incidents': len(incidents_data)}

    except Exception as e:
        current_app.logger.error(f'Log processing error: {e}', exc_info=True)
        rec = LogUpload.query.get(upload_id)
        if rec:
            rec.status = 'failed'
            db.session.commit()
        return {'parsed': 0, 'threats': 0, 'alerts': 0, 'incidents': 0}


@logs_bp.route('/view/<int:log_id>')
@login_required
def view_log(log_id):
    log   = LogEntry.query.get_or_404(log_id)
    alert = Alert.query.filter_by(log_id=log_id).first()
    return render_template('logs/view.html', log=log, alert=alert)


@logs_bp.route('/delete/<int:upload_id>', methods=['POST'])
@login_required
def delete_upload(upload_id):
    LogUpload.query.get_or_404(upload_id)   # 404 if not found
    _cascade_delete_upload(upload_id)
    flash('Upload, logs, alerts and linked incidents deleted.', 'success')
    return redirect(url_for('logs.index'))


@logs_bp.route('/api/search')
@login_required
def api_search():
    q        = request.args.get('q', '')
    log_type = request.args.get('type', '')
    page     = request.args.get('page', 1, type=int)
    query    = LogEntry.query
    if q:
        query = query.filter(
            (LogEntry.source_ip.contains(q)) | (LogEntry.username.contains(q)) |
            (LogEntry.raw_log.contains(q))   | (LogEntry.hostname.contains(q))
        )
    if log_type:
        query = query.filter(LogEntry.log_type == log_type)
    result = query.order_by(desc(LogEntry.timestamp)).paginate(page=page, per_page=25, error_out=False)
    return jsonify({'logs': [l.to_dict() for l in result.items],
                    'total': result.total, 'pages': result.pages})
