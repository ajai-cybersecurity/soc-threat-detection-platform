"""Authentication blueprint – login, logout, registration, profile."""
import uuid
from datetime import datetime
from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from app.models.models import db, User, AuditLog

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        remember = bool(request.form.get('remember'))
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password) and user.is_active:
            login_user(user, remember=remember)
            user.last_login = datetime.utcnow()
            db.session.add(AuditLog(user_id=user.id, action='login',
                                     resource='auth', ip_address=request.remote_addr))
            db.session.commit()
            next_page = request.args.get('next', url_for('dashboard.index'))
            return redirect(next_page)
        flash('Invalid credentials or account disabled.', 'danger')
    return render_template('auth/login.html')


@auth_bp.route('/logout')
@login_required
def logout():
    db.session.add(AuditLog(user_id=current_user.id, action='logout',
                              resource='auth', ip_address=request.remote_addr))
    db.session.commit()
    logout_user()
    return redirect(url_for('auth.login'))


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email    = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        role     = request.form.get('role', 'analyst')
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
            return render_template('auth/register.html')
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'danger')
            return render_template('auth/register.html')
        user = User(username=username, email=email, role=role)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('Account created. Please login.', 'success')
        return redirect(url_for('auth.login'))
    return render_template('auth/register.html')


@auth_bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        current_user.email      = request.form.get('email', current_user.email)
        current_user.department = request.form.get('department', current_user.department)
        new_pass = request.form.get('new_password', '')
        if new_pass:
            if len(new_pass) < 8:
                flash('Password must be at least 8 characters.', 'danger')
                return render_template('auth/profile.html')
            current_user.set_password(new_pass)
        db.session.commit()
        flash('Profile updated.', 'success')
    return render_template('auth/profile.html')
