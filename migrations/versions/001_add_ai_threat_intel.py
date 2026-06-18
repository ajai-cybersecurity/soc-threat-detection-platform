"""
Database Migration - Add AI and Threat Intel Enhancements

This migration adds:
- ThreatIntelCache for caching threat intelligence results
- AIExplanation for storing AI-generated alert explanations
- AIIncidentSummary for storing AI incident analysis
- CorrelationLink for alert correlation chains
- ThreatHuntingQuery for saved threat hunts
- IOCIndicator for indicator of compromise management

Run with: flask db upgrade
"""

from alembic import op
import sqlalchemy as sa


def upgrade():
    """Apply migration."""
    # ThreatIntelCache table
    op.create_table(
        'threat_intel_cache',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('indicator', sa.String(255), nullable=False, index=True, unique=True),
        sa.Column('indicator_type', sa.String(50)),
        sa.Column('malicious_score', sa.Float(), default=0.0),
        sa.Column('suspicious_score', sa.Float(), default=0.0),
        sa.Column('harmless_score', sa.Float(), default=0.0),
        sa.Column('reputation_score', sa.Float(), default=0.0),
        sa.Column('virustotal_data', sa.Text()),
        sa.Column('abuseipdb_data', sa.Text()),
        sa.Column('otx_data', sa.Text()),
        sa.Column('tags', sa.String(1000)),
        sa.Column('country', sa.String(100)),
        sa.Column('asn', sa.String(100)),
        sa.Column('isp', sa.String(255)),
        sa.Column('is_malicious', sa.Boolean(), default=False, index=True),
        sa.Column('cached_at', sa.DateTime()),
        sa.Column('expires_at', sa.DateTime()),
        sa.PrimaryKeyConstraint('id')
    )
    
    # AIExplanation table
    op.create_table(
        'ai_explanations',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('alert_id', sa.Integer(), sa.ForeignKey('alerts.id'), nullable=False, index=True),
        sa.Column('what_happened', sa.Text()),
        sa.Column('why_detected', sa.Text()),
        sa.Column('mitre_explanation', sa.Text()),
        sa.Column('risk_assessment', sa.Text()),
        sa.Column('impact_assessment', sa.Text()),
        sa.Column('threat_severity', sa.String(20)),
        sa.Column('recommended_actions', sa.Text()),
        sa.Column('analyst_notes', sa.Text()),
        sa.Column('true_positive_probability', sa.Float(), default=0.0),
        sa.Column('false_positive_probability', sa.Float(), default=0.0),
        sa.Column('confidence_score', sa.Float(), default=0.0),
        sa.Column('fp_reasoning', sa.Text()),
        sa.Column('ai_provider', sa.String(20), default='gemini'),
        sa.Column('model_used', sa.String(100)),
        sa.Column('tokens_used', sa.Integer(), default=0),
        sa.Column('generated_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.PrimaryKeyConstraint('id')
    )
    
    # AIIncidentSummary table
    op.create_table(
        'ai_incident_summaries',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('incident_id', sa.Integer(), sa.ForeignKey('incidents.id'), nullable=False, index=True, unique=True),
        sa.Column('executive_summary', sa.Text()),
        sa.Column('technical_summary', sa.Text()),
        sa.Column('root_cause_analysis', sa.Text()),
        sa.Column('affected_assets', sa.Text()),
        sa.Column('attack_progression', sa.Text()),
        sa.Column('containment_actions', sa.Text()),
        sa.Column('remediation_steps', sa.Text()),
        sa.Column('business_impact', sa.Text()),
        sa.Column('risk_assessment', sa.Text()),
        sa.Column('ai_provider', sa.String(20), default='gemini'),
        sa.Column('model_used', sa.String(100)),
        sa.Column('tokens_used', sa.Integer(), default=0),
        sa.Column('generated_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.PrimaryKeyConstraint('id')
    )
    
    # CorrelationLink table
    op.create_table(
        'correlation_links',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('source_alert_id', sa.Integer(), sa.ForeignKey('alerts.id'), index=True),
        sa.Column('target_alert_id', sa.Integer(), sa.ForeignKey('alerts.id'), index=True),
        sa.Column('correlation_type', sa.String(50)),
        sa.Column('confidence', sa.Float(), default=0.0),
        sa.Column('pattern', sa.String(255)),
        sa.Column('time_delta_seconds', sa.Integer()),
        sa.Column('sequence_order', sa.Integer()),
        sa.Column('created_at', sa.DateTime()),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_correlation_links_timeline', 'correlation_links',
                    ['source_alert_id', 'target_alert_id', 'sequence_order'])
    
    # ThreatHuntingQuery table
    op.create_table(
        'threat_hunting_queries',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('natural_language', sa.Text()),
        sa.Column('query_type', sa.String(50)),
        sa.Column('execution_query', sa.Text()),
        sa.Column('search_scope', sa.String(50)),
        sa.Column('result_count', sa.Integer(), default=0),
        sa.Column('first_result_at', sa.DateTime()),
        sa.Column('last_result_at', sa.DateTime()),
        sa.Column('target_indicator', sa.String(255), index=True),
        sa.Column('target_type', sa.String(50)),
        sa.Column('created_by', sa.Integer(), sa.ForeignKey('users.id')),
        sa.Column('created_at', sa.DateTime()),
        sa.Column('ai_generated', sa.Boolean(), default=False),
        sa.Column('ai_interpretation', sa.Text()),
        sa.PrimaryKeyConstraint('id')
    )
    
    # IOCIndicator table
    op.create_table(
        'ioc_indicators',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('indicator', sa.String(255), nullable=False, index=True),
        sa.Column('indicator_type', sa.String(50)),
        sa.Column('source', sa.String(100)),
        sa.Column('threat_type', sa.String(100)),
        sa.Column('severity', sa.String(20)),
        sa.Column('description', sa.Text()),
        sa.Column('mitre_techniques', sa.String(500)),
        sa.Column('occurrences_in_logs', sa.Integer(), default=0),
        sa.Column('occurrences_in_alerts', sa.Integer(), default=0),
        sa.Column('related_alerts_count', sa.Integer(), default=0),
        sa.Column('first_seen', sa.DateTime()),
        sa.Column('last_seen', sa.DateTime()),
        sa.Column('imported_at', sa.DateTime()),
        sa.Column('created_by', sa.Integer(), sa.ForeignKey('users.id')),
        sa.PrimaryKeyConstraint('id')
    )


def downgrade():
    """Revert migration."""
    op.drop_table('ioc_indicators')
    op.drop_table('threat_hunting_queries')
    op.drop_index('ix_correlation_links_timeline')
    op.drop_table('correlation_links')
    op.drop_table('ai_incident_summaries')
    op.drop_table('ai_explanations')
    op.drop_table('threat_intel_cache')
