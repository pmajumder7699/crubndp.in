import os, uuid, mimetypes
from decimal import Decimal, InvalidOperation
from datetime import datetime, timezone
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, current_app, send_file, abort
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from cryptography.fernet import InvalidToken
from io import BytesIO
from . import db
from .models import User, Customer, BankAccount, KycRecord, StoredDocument, Txn, AuditLog, AppSetting
from .security import (current_user, login_required, roles_required, is_admin, ROLES,
                       encrypt_text, cipher, audit, validate_aadhaar_format,
                       validate_pan_format, safe_filename, file_sha256)

bp = Blueprint("main", __name__)
ALLOWED_EXT = {".pdf", ".png", ".jpg", ".jpeg"}
DOC_KINDS = ["Aadhaar", "PAN", "Address Proof", "Passport Photo", "Signature"]

@bp.app_context_processor
def inject_user():
    return {"logged_user": current_user(), "roles": ROLES}

@bp.route("/")
def index():
    return redirect(url_for("main.dashboard") if current_user() else url_for("main.login"))

@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter(db.func.lower(User.username) == username).first()
        if user and user.active and check_password_hash(user.password_hash, password):
            session.clear()
            session["user_id"] = user.id
            session.permanent = True
            audit("LOGIN", "User", user.id, "Successful login")
            db.session.commit()
            return redirect(url_for("main.dashboard"))
        flash("Invalid login or inactive account.", "danger")
    return render_template("login.html")

@bp.route("/logout", methods=["POST"])
@login_required
def logout():
    audit("LOGOUT", "User", current_user().id, "User signed out")
    db.session.commit()
    session.clear()
    flash("Signed out.", "success")
    return redirect(url_for("main.login"))

@bp.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html",
        customers=Customer.query.count(), accounts=BankAccount.query.count(),
        pending_kyc=KycRecord.query.filter_by(status="Pending Review").count(),
        pending_txns=Txn.query.filter_by(status="Pending Approval").count(),
        recent=AuditLog.query.order_by(AuditLog.created_at.desc()).limit(8).all())

@bp.route("/staff")
@roles_required("Administrator", "Branch Manager")
def staff():
    return render_template("staff.html", staff=User.query.order_by(User.id).all())

@bp.route("/staff/create", methods=["POST"])
@roles_required("Administrator")
def staff_create():
    name=request.form.get("full_name","").strip()
    username=request.form.get("username","").strip().lower()
    password=request.form.get("password","")
    role=request.form.get("role","")
    if not name or not username or len(password)<12 or role not in ROLES:
        flash("Enter all fields. New passwords must be at least 12 characters.", "danger")
    elif User.query.filter_by(username=username).first():
        flash("Username already exists.", "danger")
    else:
        u=User(full_name=name,username=username,password_hash=generate_password_hash(password,method="scrypt"),role=role,active=True)
        db.session.add(u); db.session.flush(); audit("STAFF_CREATED","User",u.id,f"Role={role}"); db.session.commit()
        flash("Staff account created.", "success")
    return redirect(url_for("main.staff"))

@bp.route("/staff/<int:user_id>/update", methods=["POST"])
@roles_required("Administrator")
def staff_update(user_id):
    u=db.session.get(User,user_id)
    if not u: abort(404)
    name=request.form.get("full_name","").strip()
    username=request.form.get("username","").strip().lower()
    role=request.form.get("role","")
    password=request.form.get("password","")
    active=request.form.get("active")=="yes"
    duplicate=User.query.filter(User.username==username,User.id!=u.id).first()
    if not name or not username or role not in ROLES or duplicate or (password and len(password)<12):
        flash("Invalid details, duplicate username, or password shorter than 12 characters.", "danger")
    else:
        u.full_name=name;u.username=username;u.role=role;u.active=active
        if password: u.password_hash=generate_password_hash(password,method="scrypt")
        audit("STAFF_UPDATED","User",u.id,"Profile, role, status and/or password updated")
        db.session.commit();flash("Staff account updated.", "success")
    return redirect(url_for("main.staff"))

@bp.route("/security", methods=["GET","POST"])
@roles_required("Administrator")
def security_settings():
    setting= db.session.get(AppSetting, "screen_lock_minutes")
    if request.method=="POST":
        mins=request.form.get("lock_minutes","5")
        try: mins=max(1,min(60,int(mins)))
        except ValueError: mins=5
        if setting is None:
            setting=AppSetting(key="screen_lock_minutes",value=str(mins));db.session.add(setting)
        else:
            setting.value=str(mins)
        audit("SCREEN_LOCK_POLICY_UPDATED","Settings","global",f"Idle lock minutes={mins}")
        db.session.commit()
        flash(f"Global screen-lock timeout set to {mins} minutes. Staff unlock with their own login password.", "success")
        return redirect(url_for("main.security_settings"))
    return render_template("security.html", minutes=int(setting.value) if setting else 5)

@bp.route("/unlock", methods=["POST"])
@login_required
def unlock():
    password=request.form.get("password","")
    u=current_user()
    if not check_password_hash(u.password_hash,password):
        flash("Incorrect password. Workspace remains locked.", "danger")
        return redirect(url_for("main.dashboard"))
    session.permanent=True
    audit("SESSION_UNLOCKED","User",u.id,"Re-authenticated with individual staff password")
    db.session.commit()
    flash("Workspace unlocked.", "success")
    return redirect(url_for("main.dashboard"))

@bp.route("/customers", methods=["GET","POST"])
@login_required
def customers():
    if request.method=="POST":
        name=request.form.get("full_name","").strip()
        phone=request.form.get("phone","").strip()
        branch=request.form.get("branch","BUNIADPUR BRANCH").strip()
        if not name or not phone:
            flash("Customer name and phone are required.","danger")
        else:
            code=f"CRU-C-{uuid.uuid4().hex[:8].upper()}"
            c=Customer(customer_code=code,full_name=name,phone=phone,branch=branch,created_by=current_user().id)
            db.session.add(c);db.session.flush();audit("CUSTOMER_CREATED","Customer",c.id,code);db.session.commit()
            flash("Customer record created.","success")
        return redirect(url_for("main.customers"))
    return render_template("customers.html", customers=Customer.query.order_by(Customer.created_at.desc()).all())

@bp.route("/accounts/open", methods=["GET","POST"])
@roles_required("Administrator","Branch Manager","Assistant Manager","Customer Service")
def open_account():
    if request.method=="POST":
        customer_id=request.form.get("customer_id",type=int)
        customer=db.session.get(Customer,customer_id)
        product=request.form.get("product","")
        try: amount=Decimal(request.form.get("opening_balance","0"))
        except InvalidOperation: amount=Decimal("-1")
        aad=request.form.get("aadhaar","").strip()
        pan=request.form.get("pan","").strip().upper()
        address_ref=request.form.get("address_ref","").strip()
        uploads={k:request.files.get(k) for k in ["aadhaar_file","pan_file","address_file","photo_file","signature_file"]}
        if not customer or product not in ["Savings","Current","Recurring Deposit"] or amount<0:
            flash("Check customer, product and opening balance.","danger")
            return redirect(url_for("main.open_account"))
        if not validate_aadhaar_format(aad) or not validate_pan_format(pan) or not address_ref:
            flash("Enter a 12-digit Aadhaar, valid PAN format and address-proof reference.","danger")
            return redirect(url_for("main.open_account"))
        if any(not f or not f.filename for f in uploads.values()):
            flash("All three document files, passport photo and signature specimen are mandatory.","danger")
            return redirect(url_for("main.open_account"))
        stored=[]
        for kind,key in zip(DOC_KINDS,uploads):
            f=uploads[key]; ext=os.path.splitext(f.filename.lower())[1]
            if ext not in ALLOWED_EXT:
                flash("Only PDF, JPG and PNG files are accepted.","danger")
                return redirect(url_for("main.open_account"))
            raw=f.read()
            if not raw or len(raw)>5*1024*1024:
                flash("Each upload must be between 1 byte and 5 MB.","danger")
                return redirect(url_for("main.open_account"))
            # Basic content signature checks to reject obvious extension spoofing.
            valid=(ext==".pdf" and raw.startswith(b"%PDF-")) or (ext in [".jpg",".jpeg"] and raw.startswith(b"\\xff\\xd8\\xff")) or (ext==".png" and raw.startswith(b"\\x89PNG\\r\\n\\x1a\\n"))
            if not valid:
                flash(f"{kind} file content does not match its extension.","danger")
                return redirect(url_for("main.open_account"))
            stored.append((kind,safe_filename(f.filename),ext,raw))
        account_no="CRU"+datetime.now().strftime("%y%m%d")+uuid.uuid4().hex[:6].upper()
        account=BankAccount(account_number=account_no,customer_id=customer.id,product=product,opening_balance=amount,status="Pending KYC")
        db.session.add(account)
        kyc=KycRecord(customer_id=customer.id,aadhaar_encrypted=encrypt_text(aad),pan_encrypted=encrypt_text(pan),
            address_ref_encrypted=encrypt_text(address_ref),aadhaar_last4=aad[-4:],pan_masked=pan[:2]+"*****"+pan[-2:],
            staff_note=request.form.get("staff_note","")[:1000],submitted_by=current_user().id)
        db.session.add(kyc);db.session.flush()
        for kind,filename,ext,raw in stored:
            encrypted=cipher().encrypt(raw)
            disk_name=f"{uuid.uuid4().hex}.enc"
            path=os.path.join(current_app.config["UPLOAD_FOLDER"],disk_name)
            with open(path,"wb") as out: out.write(encrypted)
            db.session.add(StoredDocument(customer_id=customer.id,kind=kind,original_name=filename,
                encrypted_path=disk_name,mime_type={".pdf":"application/pdf",".jpg":"image/jpeg",".jpeg":"image/jpeg",".png":"image/png"}[ext],
                sha256=file_sha256(raw),uploaded_by=current_user().id))
        audit("ACCOUNT_OPENING_SUBMITTED","BankAccount",account_no,"KYC files encrypted at rest; pending independent review")
        db.session.commit()
        flash(f"Account {account_no} submitted for KYC review. No live banking transaction was performed.","success")
        return redirect(url_for("main.accounts"))
    return render_template("open_account.html", customers=Customer.query.order_by(Customer.full_name).all())

@bp.route("/accounts")
@login_required
def accounts():
    return render_template("accounts.html", accounts=BankAccount.query.order_by(BankAccount.created_at.desc()).all())

@bp.route("/kyc")
@roles_required("Administrator","Branch Manager","Assistant Manager")
def kyc_queue():
    records=KycRecord.query.order_by(KycRecord.created_at.desc()).all()
    return render_template("kyc.html", records=records)

@bp.route("/kyc/<int:record_id>/review", methods=["POST"])
@roles_required("Administrator","Branch Manager","Assistant Manager")
def review_kyc(record_id):
    r=db.session.get(KycRecord,record_id)
    if not r: abort(404)
    decision=request.form.get("decision")
    if decision not in ["Approved","Rejected"]: abort(400)
    if r.submitted_by==current_user().id:
        flash("Maker-checker rule: the submitting staff member cannot approve their own KYC.","danger")
        return redirect(url_for("main.kyc_queue"))
    r.status=decision;r.reviewed_by=current_user().id;r.reviewed_at=datetime.now(timezone.utc)
    customer=db.session.get(Customer,r.customer_id);customer.kyc_status=decision
    for acc in customer.accounts: acc.status="Active" if decision=="Approved" else "Rejected"
    audit("KYC_"+decision.upper(),"KycRecord",r.id,"Independent reviewer decision")
    db.session.commit();flash(f"KYC {decision.lower()}.","success")
    return redirect(url_for("main.kyc_queue"))

@bp.route("/documents/<int:doc_id>")
@roles_required("Administrator","Branch Manager","Assistant Manager","Teller","Customer Service")
def document_view(doc_id):
    d=db.session.get(StoredDocument,doc_id)
    if not d: abort(404)
    path=os.path.join(current_app.config["UPLOAD_FOLDER"],d.encrypted_path)
    try:
        with open(path,"rb") as f: raw=cipher().decrypt(f.read())
    except (OSError,InvalidToken):
        abort(404)
    audit("DOCUMENT_VIEWED","StoredDocument",d.id,d.kind);db.session.commit()
    response=send_file(BytesIO(raw),mimetype=d.mime_type,download_name=d.original_name,as_attachment=False)
    response.headers["Cache-Control"]="no-store"
    response.headers["X-Content-Type-Options"]="nosniff"
    return response

@bp.route("/transactions", methods=["GET","POST"])
@roles_required("Administrator","Branch Manager","Assistant Manager","Teller","Accountant")
def transactions():
    if request.method=="POST":
        acc=db.session.get(BankAccount,request.form.get("account_id",type=int))
        kind=request.form.get("txn_type")
        try: amount=Decimal(request.form.get("amount","0"))
        except InvalidOperation: amount=Decimal("0")
        sig_checked=request.form.get("signature_checked")=="yes"
        if not acc or acc.status!="Active" or kind not in ["Deposit","Withdrawal","Cheque Withdrawal"] or amount<=0:
            flash("Only active accounts and valid positive amounts are allowed.","danger")
        elif kind in ["Withdrawal","Cheque Withdrawal"] and not sig_checked:
            flash("Staff must record that the signature was checked against the stored specimen.","danger")
        else:
            ref="CRU-T-"+uuid.uuid4().hex[:10].upper()
            t=Txn(reference=ref,account_id=acc.id,txn_type=kind,amount=amount,
                narration=request.form.get("narration","")[:255],signature_checked=sig_checked,
                entered_by=current_user().id,status="Pending Approval")
            db.session.add(t);db.session.flush();audit("TRANSACTION_ENTERED","Txn",t.id,f"{kind}; maker-checker approval required")
            db.session.commit();flash(f"Transaction {ref} queued for independent approval. It has not moved money.","success")
        return redirect(url_for("main.transactions"))
    return render_template("transactions.html", transactions=Txn.query.order_by(Txn.created_at.desc()).all(),
        accounts=BankAccount.query.filter_by(status="Active").all())

@bp.route("/transactions/<int:txn_id>/approve", methods=["POST"])
@roles_required("Administrator","Branch Manager","Assistant Manager")
def approve_txn(txn_id):
    t=db.session.get(Txn,txn_id)
    if not t: abort(404)
    if t.entered_by==current_user().id:
        flash("Maker-checker rule: you cannot approve your own transaction.","danger")
    elif t.status!="Pending Approval":
        flash("This item is no longer pending.","warning")
    else:
        t.status="Approved (Demo Only)";t.approved_by=current_user().id
        audit("TRANSACTION_APPROVED","Txn",t.id,"Approval is recorded for demonstration; no real funds moved")
        db.session.commit();flash("Approval recorded in demo ledger only.","success")
    return redirect(url_for("main.transactions"))

@bp.route("/audit")
@roles_required("Administrator","Branch Manager")
def audit_page():
    return render_template("audit.html", logs=AuditLog.query.order_by(AuditLog.created_at.desc()).limit(250).all())

@bp.app_errorhandler(403)
def forbidden(e):
    return render_template("error.html", code=403, message="You do not have permission to access this function."),403

@bp.app_errorhandler(413)
def too_large(e):
    flash("Upload too large. Maximum request size is 10 MB; each file is limited to 5 MB.","danger")
    return redirect(request.referrer or url_for("main.dashboard"))
