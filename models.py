from datetime import datetime, timezone
from . import db

def utcnow():
    return datetime.now(timezone.utc)

class AppSetting(db.Model):
    key = db.Column(db.String(80), primary_key=True)
    value = db.Column(db.String(255), nullable=False)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(120), nullable=False)
    username = db.Column(db.String(60), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(40), nullable=False)
    active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)

class Customer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    customer_code = db.Column(db.String(30), unique=True, nullable=False, index=True)
    full_name = db.Column(db.String(120), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    branch = db.Column(db.String(100), nullable=False)
    kyc_status = db.Column(db.String(30), default="Pending", nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)

class BankAccount(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    account_number = db.Column(db.String(40), unique=True, nullable=False, index=True)
    customer_id = db.Column(db.Integer, db.ForeignKey("customer.id"), nullable=False)
    product = db.Column(db.String(40), nullable=False)
    opening_balance = db.Column(db.Numeric(14,2), nullable=False, default=0)
    status = db.Column(db.String(30), default="Pending KYC", nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)
    customer = db.relationship("Customer", backref="accounts")

class KycRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey("customer.id"), nullable=False)
    aadhaar_encrypted = db.Column(db.Text, nullable=False)
    pan_encrypted = db.Column(db.Text, nullable=False)
    address_ref_encrypted = db.Column(db.Text, nullable=False)
    aadhaar_last4 = db.Column(db.String(4), nullable=False)
    pan_masked = db.Column(db.String(10), nullable=False)
    status = db.Column(db.String(30), default="Pending Review", nullable=False)
    staff_note = db.Column(db.Text)
    submitted_by = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    reviewed_by = db.Column(db.Integer, db.ForeignKey("user.id"))
    reviewed_at = db.Column(db.DateTime(timezone=True))
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)

class StoredDocument(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey("customer.id"), nullable=False)
    kind = db.Column(db.String(40), nullable=False)
    original_name = db.Column(db.String(255), nullable=False)
    encrypted_path = db.Column(db.String(500), nullable=False)
    mime_type = db.Column(db.String(80), nullable=False)
    sha256 = db.Column(db.String(64), nullable=False)
    uploaded_by = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)

class Txn(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    reference = db.Column(db.String(40), unique=True, nullable=False)
    account_id = db.Column(db.Integer, db.ForeignKey("bank_account.id"), nullable=False)
    txn_type = db.Column(db.String(30), nullable=False)
    amount = db.Column(db.Numeric(14,2), nullable=False)
    narration = db.Column(db.String(255))
    status = db.Column(db.String(30), default="Pending Approval", nullable=False)
    signature_checked = db.Column(db.Boolean, default=False, nullable=False)
    entered_by = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    approved_by = db.Column(db.Integer, db.ForeignKey("user.id"))
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    actor_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    action = db.Column(db.String(100), nullable=False)
    object_type = db.Column(db.String(60), nullable=False)
    object_id = db.Column(db.String(60))
    details = db.Column(db.Text)
    ip_address = db.Column(db.String(64))
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)
