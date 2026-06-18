"""Incidents blueprint – full incident management with CRUD and comments."""
import uuid
import json
from datetime import datetime
from flask import (Blueprint, render_template, request, redirect, url_for,
                   flash, jsonify)
from flask_login import login_required, current_user
from sqlalchemy import desc
from app.models.models import db, Incident, IncidentComment, Alert, User
from app.services import threat_intel_service

incidents_bp = Blueprint('incidents', __name__, url_prefix='/incidents')


@incidents_bp.route('/')
@login_required
def index():
    page     = request.args.get('page', 1, type=int)
    status   = request.args.get('status', '')
    severity = request.args.get('severity', '')
    search   = request.args.get('q', '')

    query = Incident.query
    if status:
        query = query.filter(Incident.status == status)
    if severity:
        query = query.filter(Incident.severity == severity)
    if search:
        query = query.filter(
            (Incident.title.contains(search)) | (Incident.source_ip.contains(search)) |
            (Incident.description.contains(search))
        )
    incidents = query.order_by(desc(Incident.created_at)).paginate(page=page, per_page=20, error_out=False)

    stats = {
        'total':        Incident.query.count(),
        'open':         Incident.query.filter_by(status='open').count(),
        'investigating': Incident.query.filter_by(status='investigating').count(),
        'critical':     Incident.query.filter_by(severity='critical').count(),
    }
    return render_template('incidents/index.html', incidents=incidents, stats=stats,
                           filters={'status': status, 'severity': severity, 'q': search})


@incidents_bp.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    if request.method == 'POST':
        inc = Incident(
            incident_id  = f'INC-{uuid.uuid4().hex[:8].upper()}',
            title        = request.form.get('title', ''),
            description  = request.form.get('description', ''),
            threat_type  = request.form.get('threat_type', ''),
            severity     = request.form.get('severity', 'medium'),
            source_ip    = request.form.get('source_ip', ''),
            target_asset = request.form.get('target_asset', ''),
            status       = 'open',
            analyst_id   = current_user.id,
        )
        db.session.add(inc)
        db.session.commit()
        flash(f'Incident {inc.incident_id} created.', 'success')
        return redirect(url_for('incidents.view', incident_id=inc.id))
    return render_template('incidents/create.html')


@incidents_bp.route('/<int:incident_id>')
@login_required
def view(incident_id):
    incident = Incident.query.get_or_404(incident_id)
    comments = IncidentComment.query.filter_by(incident_id=incident_id)\
                                     .order_by(IncidentComment.created_at).all()
    related_alerts = Alert.query.filter_by(incident_id=incident_id).all()

    timeline = []
    if incident.timeline:
        try:
            timeline = json.loads(incident.timeline)
        except Exception:
            pass

    mitre = {}
    if incident.mitre_mapping:
        try:
            mitre = json.loads(incident.mitre_mapping)
        except Exception:
            pass

    return render_template('incidents/view.html', incident=incident, comments=comments,
                           related_alerts=related_alerts, timeline=timeline, mitre=mitre)


@incidents_bp.route('/<int:incident_id>/update', methods=['POST'])
@login_required
def update(incident_id):
    incident = Incident.query.get_or_404(incident_id)
    incident.status       = request.form.get('status', incident.status)
    incident.severity     = request.form.get('severity', incident.severity)
    incident.analyst_notes = request.form.get('analyst_notes', incident.analyst_notes)
    incident.target_asset = request.form.get('target_asset', incident.target_asset)
    incident.updated_at   = datetime.utcnow()
    if incident.status in ('resolved', 'closed') and not incident.resolved_at:
        incident.resolved_at = datetime.utcnow()
    db.session.commit()
    flash('Incident updated.', 'success')
    return redirect(url_for('incidents.view', incident_id=incident_id))


@incidents_bp.route('/<int:incident_id>/comment', methods=['POST'])
@login_required
def add_comment(incident_id):
    Incident.query.get_or_404(incident_id)
    comment_text = request.form.get('comment', '').strip()
    if not comment_text:
        flash('Comment cannot be empty.', 'danger')
        return redirect(url_for('incidents.view', incident_id=incident_id))
    comment = IncidentComment(
        incident_id = incident_id,
        author_id   = current_user.id,
        comment     = comment_text,
    )
    db.session.add(comment)
    db.session.commit()
    flash('Comment added.', 'success')
    return redirect(url_for('incidents.view', incident_id=incident_id))


    

@incidents_bp.route('/api/list')
@login_required
def api_list():
    incidents = Incident.query.order_by(desc(Incident.created_at)).limit(50).all()
    return jsonify([i.to_dict() for i in incidents])
