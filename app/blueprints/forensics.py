"""Forensics blueprint – artifact collection, hash analysis, timeline."""
import hashlib
import os
from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required, current_user
from app.models.models import db, ForensicArtifact, Incident
from app.utils.helpers import compute_hashes

forensics_bp = Blueprint('forensics', __name__, url_prefix='/forensics')


@forensics_bp.route('/')
@login_required
def index():
    artifacts = ForensicArtifact.query.order_by(ForensicArtifact.collected_at.desc()).all()
    incidents = Incident.query.order_by(Incident.created_at.desc()).limit(20).all()
    return render_template('forensics/index.html', artifacts=artifacts, incidents=incidents)


@forensics_bp.route('/artifact/add', methods=['GET', 'POST'])
@login_required
def add_artifact():
    if request.method == 'POST':
        value = request.form.get('value', '')
        hashes = {}
        if value:
            hashes = compute_hashes(value.encode())

        artifact = ForensicArtifact(
            incident_id   = request.form.get('incident_id') or None,
            artifact_type = request.form.get('artifact_type', 'file'),
            name          = request.form.get('name', ''),
            value         = value,
            md5_hash      = hashes.get('md5', ''),
            sha1_hash     = hashes.get('sha1', ''),
            sha256_hash   = hashes.get('sha256', ''),
            notes         = request.form.get('notes', ''),
            collected_by  = current_user.id,
        )
        db.session.add(artifact)
        db.session.commit()
        flash('Artifact added.', 'success')
        return redirect(url_for('forensics.index'))
    incidents = Incident.query.order_by(Incident.created_at.desc()).limit(20).all()
    return render_template('forensics/add_artifact.html', incidents=incidents)


@forensics_bp.route('/hash-check', methods=['POST'])
@login_required
def hash_check():
    value = request.form.get('value', '') or (request.get_json() or {}).get('value', '')
    if not value:
        return jsonify({'error': 'No value provided'}), 400
    hashes = compute_hashes(value.encode('utf-8', errors='ignore'))
    return jsonify({'hashes': hashes, 'value': value[:100]})
