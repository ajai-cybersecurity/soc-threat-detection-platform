"""Reports blueprint – generate PDF/CSV reports scoped to active uploads only.
Reports only include data from log entries that still exist in the DB.
Includes delete endpoint to remove generated report records.
"""
import os
import uuid
from datetime import datetime, timedelta
from flask import (Blueprint, render_template, request, redirect, url_for,
                   flash, send_file, current_app)
from flask_login import login_required, current_user
from sqlalchemy import desc, func

from app.models.models import db, Alert, Incident, LogEntry, Report, LogUpload
from app.reports.report_generator import generate_pdf_report, generate_csv_report

reports_bp = Blueprint('reports', __name__, url_prefix='/reports')


def _active_upload_ids():
    """IDs of uploads that still have log entries in DB."""
    ids = db.session.query(LogEntry.upload_id).distinct().all()
    return [r[0] for r in ids if r[0] is not None]


def _alert_ids_from_active_uploads():
    """Alert IDs that are linked to log entries that still exist."""
    active = _active_upload_ids()
    if not active:
        return []
    log_ids = [r[0] for r in db.session.query(LogEntry.id)
                                        .filter(LogEntry.upload_id.in_(active)).all()]
    if not log_ids:
        return []
    return [r[0] for r in db.session.query(Alert.id)
                                     .filter(Alert.log_id.in_(log_ids)).all()]


def _build_stats_active():
    """Build statistics only from alerts tied to currently active uploads."""
    active_alert_ids = _alert_ids_from_active_uploads()

    if not active_alert_ids:
        return {k: 0 for k in ['total_logs', 'total_alerts', 'total_incidents',
                                'critical_alerts', 'high_alerts', 'medium_alerts',
                                'low_alerts', 'unique_ips', 'log_sources']}

    base_q = Alert.query.filter(Alert.id.in_(active_alert_ids))
    active = _active_upload_ids()

    return {
        'total_logs':      LogEntry.query.filter(LogEntry.upload_id.in_(active)).count(),
        'total_alerts':    base_q.count(),
        'total_incidents': Incident.query.count(),
        'critical_alerts': base_q.filter(Alert.severity == 'critical').count(),
        'high_alerts':     base_q.filter(Alert.severity == 'high').count(),
        'medium_alerts':   base_q.filter(Alert.severity == 'medium').count(),
        'low_alerts':      base_q.filter(Alert.severity == 'low').count(),
        'unique_ips':      db.session.query(func.count(func.distinct(Alert.source_ip)))
                                     .filter(Alert.id.in_(active_alert_ids)).scalar() or 0,
        'log_sources':     db.session.query(func.count(func.distinct(LogEntry.log_type)))
                                     .filter(LogEntry.upload_id.in_(active)).scalar() or 0,
    }


def _top_threats_active():
    active_alert_ids = _alert_ids_from_active_uploads()
    if not active_alert_ids:
        return []
    rows = db.session.query(Alert.threat_type, Alert.severity, func.count(Alert.id).label('c'))\
                     .filter(Alert.id.in_(active_alert_ids))\
                     .group_by(Alert.threat_type, Alert.severity)\
                     .order_by(desc('c')).limit(10).all()
    return [{'threat_type': r.threat_type, 'severity': r.severity, 'count': r.c} for r in rows]


def _top_ips_active():
    active_alert_ids = _alert_ids_from_active_uploads()
    if not active_alert_ids:
        return []
    rows = db.session.query(Alert.source_ip, func.count(Alert.id).label('c'))\
                     .filter(Alert.id.in_(active_alert_ids), Alert.source_ip != None)\
                     .group_by(Alert.source_ip).order_by(desc('c')).limit(10).all()
    return [{'source_ip': r.source_ip, 'count': r.c, 'types': ''} for r in rows]


# ── Routes ────────────────────────────────────────────────────
@reports_bp.route('/')
@login_required
def index():
    reports = Report.query.order_by(desc(Report.created_at)).all()
    # Mark which reports still have their file on disk
    for r in reports:
        r.file_exists = r.file_path and os.path.exists(r.file_path)
    return render_template('reports/index.html', reports=reports)


@reports_bp.route('/generate', methods=['GET', 'POST'])
@login_required
def generate():
    if request.method == 'POST':
        report_type = request.form.get('report_type', 'pdf')

        stats      = _build_stats_active()
        top_threats = _top_threats_active()
        top_ips     = _top_ips_active()

        # Active upload info for report metadata
        active     = _active_upload_ids()
        uploads    = LogUpload.query.filter(LogUpload.id.in_(active)).all() if active else []
        upload_names = ', '.join(u.original_name for u in uploads) or 'N/A'

        data = {
            'stats':         stats,
            'date_from':     'All active uploads',
            'date_to':       datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC'),
            'organization':  current_user.organization or 'SOC Platform',
            'top_threats':   top_threats,
            'top_ips':       top_ips,
            'incidents':     [i.to_dict() for i in
                               Incident.query.order_by(desc(Incident.created_at)).limit(20).all()],
            'upload_sources': upload_names,
        }

        output_dir = current_app.config.get('REPORTS_FOLDER', 'reports_output')
        os.makedirs(output_dir, exist_ok=True)
        ts       = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        filename = f'soc_report_{ts}'

        if report_type == 'pdf':
            filepath = os.path.join(output_dir, f'{filename}.pdf')
            generate_pdf_report(data, filepath)
            mime, ext = 'application/pdf', '.pdf'
        else:
            filepath = os.path.join(output_dir, f'{filename}.csv')
            active_alert_ids = _alert_ids_from_active_uploads()
            alerts = Alert.query.filter(Alert.id.in_(active_alert_ids)).all() if active_alert_ids else []
            generate_csv_report([a.to_dict() for a in alerts], filepath)
            mime, ext = 'text/csv', '.csv'

        report_rec = Report(
            title        = f'SOC Report {datetime.utcnow().strftime("%Y-%m-%d %H:%M")}',
            report_type  = report_type,
            file_path    = filepath,
            generated_by = current_user.id,
            date_from    = datetime.utcnow(),
            date_to      = datetime.utcnow(),
        )
        db.session.add(report_rec)
        db.session.commit()

        return send_file(filepath, mimetype=mime, as_attachment=True,
                         download_name=f'soc_report_{ts}{ext}')

    # GET – show active upload summary
    active_ids = _active_upload_ids()
    uploads    = LogUpload.query.filter(LogUpload.id.in_(active_ids)).all() if active_ids else []
    stats      = _build_stats_active()
    return render_template('reports/generate.html', uploads=uploads, stats=stats)


@reports_bp.route('/download/<int:report_id>')
@login_required
def download(report_id):
    report = Report.query.get_or_404(report_id)
    if not report.file_path or not os.path.exists(report.file_path):
        flash('Report file not found on disk.', 'danger')
        return redirect(url_for('reports.index'))
    return send_file(report.file_path, as_attachment=True)


@reports_bp.route('/delete/<int:report_id>', methods=['POST'])
@login_required
def delete_report(report_id):
    report = Report.query.get_or_404(report_id)
    # Delete physical file if it exists
    if report.file_path and os.path.exists(report.file_path):
        try:
            os.remove(report.file_path)
        except Exception:
            pass
    db.session.delete(report)
    db.session.commit()
    flash(f'Report "{report.title}" deleted.', 'success')
    return redirect(url_for('reports.index'))
