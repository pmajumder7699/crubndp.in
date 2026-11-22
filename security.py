import os, re, hashlib
from functools import wraps
from flask import current_app, session, redirect, url_for, flash, request, abort
from cryptography.fernet import Fernet
from .models import User, AuditLog
from . import db

ROLES = ["Administrator", "Branch Manager", "Assistant Manager", "Teller",
         "Customer Service", "Field Officer", "Accountant"]

def current_user():
    uid = session.get("user_id")
    return db.session.get(User, uid) if uid else None

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        u = current_user()
        if not u or not u.active:
            session.clear()
            flash("Please sign in to continue.", "warning")
            return redirect(url_for("main.login"))
        return fn(*args, **kwargs)
    return wrapper

def roles_required(*roles):
    def deco(fn):
        @wraps(fn)
        @login_required
        def wrapper(*args, **kwargs):
            u = current_user()
            if u.role not in roles:
                abort(403)
            return fn(*args, **kwargs)
        return wrapper
    return deco

def is_admin():
    u = current_user()
    return bool(u and u.role == "Administrator")

def cipher():
    key = current_app.config["DOCUMENT_ENCRYPTION_KEY"]
    return Fernet(key.encode() if isinstance(key, str) else key)

def encrypt_text(value):
    return cipher().encrypt(value.encode()).decode()

def audit(action, object_type, object_id="", details=""):
    u = current_user()
    db.session.add(AuditLog(
        actor_id=u.id if u else None, action=action, object_type=object_type,
        object_id=str(object_id), details=details[:1000],
        ip_address=request.headers.get("X-Forwarded-For", request.remote_addr)
    ))

def validate_aadhaar_format(value):
    return bool(re.fullmatch(r"[0-9]{12}", value))

def validate_pan_format(value):
    return bool(re.fullmatch(r"[A-Z]{5}[0-9]{4}[A-Z]", value.upper()))

def safe_filename(name):
    name = os.path.basename(name or "document")
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)[:180]

def file_sha256(data):
    return hashlib.sha256(data).hexdigest()
