import os
import re
import secrets
import math
from datetime import datetime

from fastapi import FastAPI, Depends, HTTPException, Request, UploadFile, File, status
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from jinja2 import Environment, FileSystemLoader
from pydantic import BaseModel

from sqlalchemy import (
    create_engine, Column, Integer, BigInteger, String, 
    Boolean, DateTime, Numeric, desc, ForeignKey
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship

from dotenv import load_dotenv
load_dotenv()

# -------------------------------------------------------------
# 1. DATABASE & ENVIRONMENT CONFIGURATION
# -------------------------------------------------------------
DB_USER = os.environ.get("DB_USER")
DB_PASS = os.environ.get("DB_PASS")
DB_HOST = os.environ.get("DB_HOST")
DB_PORT = os.environ.get("DB_PORT", "3306")
DB_NAME = os.environ.get("DB_NAME")

missing_db_vars = [name for name, val in [
    ("DB_USER", DB_USER), ("DB_PASS", DB_PASS),
    ("DB_HOST", DB_HOST), ("DB_NAME", DB_NAME)
] if not val]
if missing_db_vars:
    raise RuntimeError(
        f"Missing required DB env vars: {', '.join(missing_db_vars)}. "
        f"Set them in .env — refusing to start."
    )

# Dual-Role Credentials (Developer & Admin)
DEV_USER = os.environ.get("DEV_USER", "dev_admin")
DEV_PASS = os.environ.get("DEV_PASS", "dev_secret_pass")

ADMIN_USER = os.environ.get("ADMIN_USER", "hr_admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "admin_secret_pass")

security = HTTPBasic()

# Access Control Guards
def verify_dev_access(credentials: HTTPBasicCredentials = Depends(security)):
    is_dev_user = secrets.compare_digest(credentials.username, DEV_USER)
    is_dev_pass = secrets.compare_digest(credentials.password, DEV_PASS)
    if not (is_dev_user and is_dev_pass):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Developer Access Denied: Invalid Developer Credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username


def verify_admin_access(credentials: HTTPBasicCredentials = Depends(security)):
    is_admin = (
        secrets.compare_digest(credentials.username, ADMIN_USER) and 
        secrets.compare_digest(credentials.password, ADMIN_PASS)
    )
    is_dev = (
        secrets.compare_digest(credentials.username, DEV_USER) and 
        secrets.compare_digest(credentials.password, DEV_PASS)
    )
    if not (is_admin or is_dev):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Admin Access Denied: Invalid Credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username


MYSQL_URL = f"mysql+pymysql://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

engine = create_engine(
    MYSQL_URL,
    pool_pre_ping=True,
    pool_recycle=3600
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# -------------------------------------------------------------
# 2. SQLALCHEMY MODELS
# -------------------------------------------------------------
class User(Base):
    __tablename__ = "users"

    id = Column(BigInteger, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True)
    full_name = Column(String(255))
    phone = Column(String(255))


class UserPayslip(Base):
    __tablename__ = "user_payslip"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(BigInteger, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    market = Column(String(50))
    ntid = Column(String(100), nullable=False, index=True)
    employee_name = Column(String(100), nullable=False)
    designation = Column(String(100))
    weekly_days = Column(Integer)
    payroll_days = Column(Integer)

    # As-Is String Columns for Excel Cycles
    attendance_cycle = Column(String(100), nullable=True)
    pay_cycle = Column(String(100), nullable=True)

    total_working_days = Column(Integer)
    base_salary = Column(Numeric(10, 2), default=0.00)
    commission = Column(Numeric(10, 2), default=0.00)
    bonus = Column(Numeric(10, 2), default=0.00)
    additional_pay = Column(Numeric(10, 2), default=0.00)
    total_earnings = Column(Numeric(10, 2), default=0.00)
    hourly_rate = Column(Numeric(10, 2), default=0.00)
    regular_hours = Column(Numeric(6, 2), default=0.00)
    ot_rate = Column(Numeric(10, 2), default=0.00)
    ot_hours = Column(Numeric(6, 2), default=0.00)
    net_salary = Column(Numeric(10, 2), default=0.00)
    adp_amount = Column(Numeric(10, 2), default=0.00)
    check_amount = Column(Numeric(10, 2), default=0.00)

    token = Column(String(100), unique=True, index=True)
    is_viewed = Column(Boolean, default=False)
    viewed_at = Column(DateTime, nullable=True)
    is_used = Column(Boolean, default=False)
    signature_text = Column(String(150), nullable=True)
    signed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.now)

    user = relationship("User", backref="payslips")


Base.metadata.create_all(bind=engine)

app = FastAPI(title="Payslip Management System")
jinja_env = Environment(loader=FileSystemLoader("templates"), autoescape=True)

MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # 10 MB
ALLOWED_UPLOAD_EXTENSIONS = (".xlsx", ".xls", ".csv")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def clean_num(value, default=0.0):
    if value is None:
        return default
    try:
        if isinstance(value, float) and math.isnan(value):
            return default
        val_str = str(value).replace('$', '').replace(',', '').strip()
        return float(val_str)
    except (TypeError, ValueError):
        return default


def clean_int(value):
    if value is None:
        return None
    try:
        if isinstance(value, float) and math.isnan(value):
            return None
        val_str = str(value).split('.')[0].strip()
        return int(val_str)
    except (ValueError, TypeError):
        return None


# -------------------------------------------------------------
# 3. LOGIN & PORTAL ROUTING
# -------------------------------------------------------------
@app.get("/login", response_class=HTMLResponse)
async def serve_login_page(request: Request):
    template = jinja_env.get_template("login.html")
    return HTMLResponse(content=template.render())


# Access Point A: Admin Dashboard
@app.get("/admin", response_class=HTMLResponse)
async def serve_admin_dashboard(request: Request, _user: str = Depends(verify_admin_access)):
    template = jinja_env.get_template("admin_dashboard.html")
    return HTMLResponse(content=template.render())


# Access Point B: Developer Control Panel (Dev Only)
@app.get("/dev/dashboard")
async def serve_dev_dashboard(user: str = Depends(verify_dev_access)):
    return {
        "portal": "Developer Console & System Debugger",
        "logged_in_as": user,
        "system_status": "Healthy",
        "db_connection": "Active",
        "allowed_actions": ["Read Raw System Metrics", "Audit Logs", "DB Query Execution"]
    }


# -------------------------------------------------------------
# 4. API: BULK EXCEL PROCESSING (ADMIN & DEV)
# -------------------------------------------------------------
@app.post("/api/v1/upload-payslips")
async def upload_payslips(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    _user: str = Depends(verify_admin_access),
):
    if not file.filename.lower().endswith(ALLOWED_UPLOAD_EXTENSIONS):
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type. Allowed: {', '.join(ALLOWED_UPLOAD_EXTENSIONS)}"
        )

    content = await file.read()

    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=400,
            detail=f"File too large. Max size is {MAX_UPLOAD_BYTES // (1024 * 1024)} MB."
        )

    try:
        import pandas as pd
        from io import BytesIO

        if file.filename.lower().endswith(('.xlsx', '.xls')):
            df = pd.read_excel(BytesIO(content))
        else:
            df = pd.read_csv(BytesIO(content))

        column_map = {
            'Market': 'market',
            'NTID': 'ntid',
            'Employee Name': 'employee_name',
            'Designation': 'designation',
            'Weekly Days': 'weekly_days',
            'Payroll Days': 'payroll_days',
            'Attendance cycle': 'attendance_cycle',
            'Pay Cycle': 'pay_cycle',
            'Salary': 'base_salary',
            'Commission': 'commission',
            'Bonus': 'bonus',
            'Additional Pay': 'additional_pay',
            'Total': 'total_earnings',
            'Total Working Day': 'total_working_days',
            'Hourly Rate': 'hourly_rate',
            'Hours': 'regular_hours',
            'OT Rate': 'ot_rate',
            'OT Hours': 'ot_hours',
            'Net Salary': 'net_salary',
            'ADP': 'adp_amount',
            'Check': 'check_amount'
        }

        df.columns = df.columns.str.strip()
        df = df.rename(columns=column_map)

        generated_links = []
        updated_count = 0
        inserted_count = 0
        skipped_count = 0

        for idx, row in df.iterrows():
            ntid_val = str(row.get('ntid')).strip()
            if not ntid_val or ntid_val.lower() in ['nan', 'none', '']:
                continue

            user_rec = db.query(User).filter(User.email == ntid_val).first()
            if not user_rec:
                skipped_count += 1
                continue

            # Extract exact string values from Excel
            att_cycle_val = str(row.get('attendance_cycle')).strip() if row.get('attendance_cycle') and str(row.get('attendance_cycle')).lower() != 'nan' else None
            pay_cycle_val = str(row.get('pay_cycle')).strip() if row.get('pay_cycle') and str(row.get('pay_cycle')).lower() != 'nan' else None

            field_values = dict(
                user_id=user_rec.id,
                market=str(row.get('market')) if row.get('market') and str(row.get('market')).lower() != 'nan' else None,
                employee_name=str(row.get('employee_name')),
                designation=str(row.get('designation')) if row.get('designation') and str(row.get('designation')).lower() != 'nan' else None,
                weekly_days=clean_int(row.get('weekly_days')),
                payroll_days=clean_int(row.get('payroll_days')),
                
                # Dynamic direct string mapping
                attendance_cycle=att_cycle_val,
                pay_cycle=pay_cycle_val,

                base_salary=clean_num(row.get('base_salary', 0.00)),
                commission=clean_num(row.get('commission', 0.00)),
                bonus=clean_num(row.get('bonus', 0.00)),
                additional_pay=clean_num(row.get('additional_pay', 0.00)),
                total_earnings=clean_num(row.get('total_earnings', 0.00)),
                total_working_days=clean_int(row.get('total_working_days')),
                hourly_rate=clean_num(row.get('hourly_rate', 0.00)),
                regular_hours=clean_num(row.get('regular_hours', 0.00)),
                ot_rate=clean_num(row.get('ot_rate', 0.00)),
                ot_hours=clean_num(row.get('ot_hours', 0.00)),
                net_salary=clean_num(row.get('net_salary', 0.00)),
                adp_amount=clean_num(row.get('adp_amount', 0.00)),
                check_amount=clean_num(row.get('check_amount', 0.00)),
            )

            existing = (
                db.query(UserPayslip)
                .filter(UserPayslip.ntid == ntid_val, UserPayslip.is_used == False)
                .first()
            )

            new_token = secrets.token_urlsafe(32)

            if existing:
                for key, val in field_values.items():
                    setattr(existing, key, val)
                existing.token = new_token
                existing.is_viewed = False
                existing.viewed_at = None
                updated_count += 1
                employee_name_out = existing.employee_name
            else:
                payslip = UserPayslip(
                    ntid=ntid_val,
                    token=new_token,
                    is_viewed=False,
                    is_used=False,
                    **field_values,
                )
                db.add(payslip)
                inserted_count += 1
                employee_name_out = field_values["employee_name"]

            generated_links.append({
                "ntid": ntid_val,
                "employee_name": employee_name_out,
                "token": new_token,
                "access_url": f"/payslip/view/{new_token}"
            })

        db.commit()
        return {
            "status": "success",
            "records_inserted": inserted_count,
            "records_updated": updated_count,
            "records_skipped": skipped_count,
            "links": generated_links
        }

    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Upload Failed: {str(e)}")


# -------------------------------------------------------------
# 5. EMPLOYEE & ADMIN VIEW ROUTES
# -------------------------------------------------------------
@app.get("/payslip/view/{token}", response_class=HTMLResponse)
async def view_payslip(token: str, request: Request, db: Session = Depends(get_db)):
    payslip = db.query(UserPayslip).filter(UserPayslip.token == token).first()

    if not payslip:
        return HTMLResponse("<h2>Invalid or Expired Link</h2>", status_code=404)

    if payslip.is_used:
        signed_time = payslip.signed_at.strftime('%Y-%m-%d %H:%M:%S') if payslip.signed_at else '-'
        return HTMLResponse(f"""
            <div style="text-align:center; padding:50px; font-family:Arial, sans-serif;">
                <h2 style="color:#d9534f;">Link Expired!</h2>
                <p>This payslip for <b>{payslip.employee_name}</b> (NTID: {payslip.ntid}) was already acknowledged and signed on <b>{signed_time}</b>.</p>
                <p style="color:#777;">Access has been permanently restricted.</p>
            </div>
        """, status_code=403)

    template = jinja_env.get_template("paystub.html")
    html_content = template.render(
        payslip=payslip,
        current_date=datetime.now().strftime("%b %d, %Y")
    )
    return HTMLResponse(content=html_content)


@app.get("/admin/payslip/{payslip_id}", response_class=HTMLResponse)
async def admin_view_payslip(
    payslip_id: int,
    db: Session = Depends(get_db),
    _user: str = Depends(verify_admin_access),
):
    payslip = db.query(UserPayslip).filter(UserPayslip.id == payslip_id).first()
    if not payslip:
        return HTMLResponse("<h2>Payslip not found</h2>", status_code=404)

    template = jinja_env.get_template("paystub.html")
    html_content = template.render(
        payslip=payslip,
        current_date=datetime.now().strftime("%b %d, %Y"),
        admin_view=True,
    )
    return HTMLResponse(content=html_content)


@app.post("/api/v1/payslip/mark-viewed/{token}")
async def mark_viewed(token: str, db: Session = Depends(get_db)):
    payslip = db.query(UserPayslip).filter(UserPayslip.token == token).first()
    if not payslip:
        raise HTTPException(status_code=404, detail="Invalid or expired link")

    if not payslip.is_viewed and not payslip.is_used:
        payslip.is_viewed = True
        payslip.viewed_at = datetime.now()
        db.commit()

    return {"status": "ok"}


# -------------------------------------------------------------
# 6. SIGNATURE SUBMISSION (WITHOUT LOCAL PDF DISK SAVE)
# -------------------------------------------------------------
class SignPayload(BaseModel):
    token: str
    signature_name: str


@app.post("/api/v1/payslip/sign")
async def sign_payslip(payload: SignPayload, db: Session = Depends(get_db)):
    token = payload.token
    sig_name = payload.signature_name.strip()

    if not sig_name:
        raise HTTPException(status_code=400, detail="Signature Name cannot be empty.")

    payslip = db.query(UserPayslip).filter(UserPayslip.token == token).first()

    if not payslip or payslip.is_used:
        raise HTTPException(status_code=400, detail="Link is either invalid or already locked.")

    now = datetime.now()
    payslip.signature_text = sig_name
    payslip.signed_at = now
    payslip.is_used = True
    db.commit()

    return {
        "status": "success",
        "message": "Payslip acknowledged and signed successfully. Record locked in database.",
        "pdf_generated": False
    }


# -------------------------------------------------------------
# 7. ADMIN DASHBOARD API
# -------------------------------------------------------------
@app.get("/api/v1/admin/dashboard")
async def get_admin_dashboard(db: Session = Depends(get_db), _user: str = Depends(verify_admin_access)):
    records = db.query(UserPayslip).order_by(desc(UserPayslip.id)).all()

    total = len(records)
    signed_count = sum(1 for r in records if r.is_used)
    viewed_not_signed = sum(1 for r in records if r.is_viewed and not r.is_used)
    not_viewed = sum(1 for r in records if not r.is_viewed)

    data = []
    for r in records:
        status = "Pending View"
        if r.is_used:
            status = "Signed & Expired"
        elif r.is_viewed:
            status = "Viewed (Pending Sign)"

        data.append({
            "id": r.id,
            "pay_cycle": r.pay_cycle or "-",  # Pay Cycle added for display
            "ntid": r.ntid,
            "employee_name": r.employee_name,
            "market": r.market,
            "net_salary": float(r.net_salary) if r.net_salary else 0.0,
            "status": status,
            "viewed_at": r.viewed_at.strftime("%Y-%m-%d %H:%M:%S") if r.viewed_at else "-",
            "signed_at": r.signed_at.strftime("%Y-%m-%d %H:%M:%S") if r.signed_at else "-",
            "signature_name": r.signature_text or "-",
            "access_url": f"/payslip/view/{r.token}",
            "admin_view_url": f"/admin/payslip/{r.id}"
        })

    return {
        "summary": {
            "total_payslips": total,
            "signed_count": signed_count,
            "viewed_not_signed_count": viewed_not_signed,
            "not_viewed_count": not_viewed
        },
        "records": data
    }