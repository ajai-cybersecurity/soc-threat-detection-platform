"""Threat Intelligence blueprint – IP/domain/hash lookups."""
from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for
from flask_login import login_required
from sqlalchemy import desc
from app.models.models import db, ThreatIntelligence
from app.intelligence.threat_intel import intel_client

intel_bp = Blueprint('intelligence', __name__, url_prefix='/intelligence')


@intel_bp.route('/')
@login_required
def index():
    records = ThreatIntelligence.query.order_by(desc(ThreatIntelligence.last_checked)).limit(50).all()
    return render_template('intelligence/index.html', records=records)


@intel_bp.route('/lookup', methods=['GET', 'POST'])
@login_required
def lookup():
    result = None
    if request.method == 'POST':
        indicator = request.form.get('indicator', '').strip()
        itype     = request.form.get('type', 'ip')
        if not indicator:
            flash('Please enter an indicator.', 'danger')
            return render_template('intelligence/lookup.html', result=None)

        results = intel_client.check_all(indicator, itype)

        if results:
            best = max(results, key=lambda r: r.get('reputation_score', 0))
            existing = ThreatIntelligence.query.filter_by(indicator=indicator).first()
            if existing:
                existing.reputation_score = best.get('reputation_score', 0)
                existing.is_malicious     = best.get('is_malicious', False)
                existing.source           = best.get('source', '')
                existing.country          = best.get('country', '')
                existing.tags             = best.get('tags', '')
                existing.last_checked     = __import__('datetime').datetime.utcnow()
                db.session.commit()
            else:
                ti = ThreatIntelligence(
                    indicator        = indicator,
                    indicator_type   = itype,
                    source           = best.get('source', ''),
                    reputation_score = best.get('reputation_score', 0),
                    is_malicious     = best.get('is_malicious', False),
                    country          = best.get('country', ''),
                    asn              = best.get('asn', ''),
                    tags             = best.get('tags', ''),
                    raw_response     = best.get('raw_response', ''),
                )
                db.session.add(ti)
                db.session.commit()
            result = {'indicator': indicator, 'type': itype, 'sources': results, 'best': best}
        else:
            result = {'indicator': indicator, 'type': itype, 'sources': [], 'error': 'No results or API keys not configured.'}

    return render_template('intelligence/lookup.html', result=result)


@intel_bp.route('/api/check/<indicator>')
@login_required
def api_check(indicator):
    itype = request.args.get('type', 'ip')
    existing = ThreatIntelligence.query.filter_by(indicator=indicator).first()
    if existing:
        return jsonify(existing.to_dict())
    return jsonify({'indicator': indicator, 'status': 'not_found'})
