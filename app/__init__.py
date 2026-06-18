"""
SOC Platform – Flask Application Factory
"""
import os
import logging
from datetime import datetime
from flask import Flask, render_template, jsonify
from flask_login import LoginManager

from config import config
from app.models.models import db, User

login_manager = LoginManager()


def create_app(config_name: str = 'default') -> Flask:
    app = Flask(__name__)
    app.config.from_object(config[config_name])

    # Ensure required directories exist
    for folder in ['UPLOAD_FOLDER', 'REPORTS_FOLDER']:
        path = app.config.get(folder, '')
        if path:
            os.makedirs(path, exist_ok=True)
    os.makedirs(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'instance'), exist_ok=True)

    # Extensions
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access SOC Platform.'
    login_manager.login_message_category = 'warning'

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # Blueprints
    from app.blueprints import (auth_bp, dashboard_bp, logs_bp, alerts_bp,
                                incidents_bp, reports_bp, intel_bp, forensics_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(logs_bp)
    app.register_blueprint(alerts_bp)
    app.register_blueprint(incidents_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(intel_bp)
    app.register_blueprint(forensics_bp)

    @app.context_processor
    def inject_globals():
        return {'now': datetime.utcnow(), 'platform': 'SOC Platform', 'version': '1.0.0'}

    @app.errorhandler(404)
    def not_found(e):
        return render_template('errors/404.html'), 404

    @app.errorhandler(403)
    def forbidden(e):
        return render_template('errors/403.html'), 403

    @app.errorhandler(500)
    def server_error(e):
        return render_template('errors/500.html'), 500

    @app.route('/health')
    def health():
        return jsonify({'status': 'ok', 'timestamp': datetime.utcnow().isoformat()})

    with app.app_context():
        db.create_all()
        _seed_admin_user()

    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
    return app


def _seed_admin_user():
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', email='admin@socplatform.local', role='admin',
                     organization='SOC Platform', department='Security Operations', is_active=True)
        admin.set_password('Admin@SOC2024!')
        db.session.add(admin)

        analyst = User(username='analyst', email='analyst@socplatform.local', role='analyst',
                       organization='SOC Platform', department='SOC', is_active=True)
        analyst.set_password('Analyst@SOC2024!')
        db.session.add(analyst)

        db.session.commit()
        print('[SOC] Default users created: admin / Admin@SOC2024! | analyst / Analyst@SOC2024!')
