import os
from datetime import timedelta
from flask import Flask, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash
from cryptography.fernet import Fernet

db = SQLAlchemy()
csrf = CSRFProtect()

def create_app():
    app = Flask(__name__, instance_relative_config=True)
    os.makedirs(app.instance_path, exist_ok=True)
    app.config.update(
        SECRET_KEY=os.environ.get("FLASK_SECRET_KEY", "dev-only-change-this-secret"),
        SQLALCHEMY_DATABASE_URI=os.environ.get("DATABASE_URL", "sqlite:///cru_bank_v2.db"),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        MAX_CONTENT_LENGTH=int(os.environ.get("MAX_CONTENT_LENGTH", 10 * 1024 * 1024)),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "false").lower() == "true",
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=20),
        WTF_CSRF_TIME_LIMIT=None,
        UPLOAD_FOLDER=os.path.join(app.instance_path, "encrypted_documents"),
        DOCUMENT_ENCRYPTION_KEY=os.environ.get("DOCUMENT_ENCRYPTION_KEY", ""),
    )
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    if not app.config["DOCUMENT_ENCRYPTION_KEY"]:
        # Local dev convenience only. Generate and persist a stable key before use.
        app.config["DOCUMENT_ENCRYPTION_KEY"] = Fernet.generate_key().decode()
        app.logger.warning("Temporary document encryption key generated. Set DOCUMENT_ENCRYPTION_KEY in .env or uploaded files become unreadable after restart.")
    db.init_app(app)
    csrf.init_app(app)

    from . import models
    @app.context_processor
    def inject_lock_setting():
        setting = models.AppSetting.query.filter_by(key="screen_lock_minutes").first()
        return {"global_lock_minutes": int(setting.value) if setting else 5}
    from .routes import bp
    app.register_blueprint(bp)

    with app.app_context():
        db.create_all()
        if not models.User.query.filter_by(role="Administrator").first():
            username = os.environ.get("BOOTSTRAP_ADMIN_USERNAME", "admin")
            password = os.environ.get("BOOTSTRAP_ADMIN_PASSWORD", "ChangeThisImmediately!2026")
            admin = models.User(
                full_name="CRU Bank Administrator",
                username=username,
                password_hash=generate_password_hash(password, method="scrypt"),
                role="Administrator",
                active=True,
            )
            db.session.add(admin)
            db.session.commit()
            app.logger.warning("Bootstrap administrator created. Change the password immediately.")
    return app
