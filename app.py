
from datetime import datetime, date, time, timedelta
from enum import Enum
from typing import Optional
import hashlib
import hmac
import secrets

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import (
    create_engine, Column, Integer, String, Boolean, Date, Time,
    ForeignKey, Float, Text
)
from sqlalchemy.orm import declarative_base, sessionmaker, Session

# ============================================================
# BEACON OF HOPE HOSPITAL - PYTHON BACKEND
# FastAPI + SQLite
#
# Booking rule from the HTML system:
# Monday-Saturday, 08:00-17:00.
# Sunday is closed for bookable services.
# ============================================================

DATABASE_URL = "sqlite:///./beacon_of_hope.db"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

app = FastAPI(
    title="Beacon of Hope Hospital API",
    version="1.0.0",
    description="Backend API for Beacon of Hope Hospital (Ongata Rongai)"
)

security = HTTPBearer()
TOKENS = {}

BOOKING_OPEN = time(8, 0)
BOOKING_CLOSE = time(17, 0)
CONSULTATION_MINUTES = 45


# ============================================================
# DATABASE MODELS
# ============================================================

class Role(str, Enum):
    admin = "admin"
    doctor = "doctor"
    nurse = "nurse"
    pharmacist = "pharmacist"
    rider = "rider"
    patient = "patient"


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    name = Column(String(150), nullable=False)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    phone = Column(String(40), nullable=True)
    role = Column(String(30), nullable=False)
    specialty = Column(String(100), nullable=True)
    enabled = Column(Boolean, default=True)
    address = Column(Text, nullable=True)
    max_bookings_per_day = Column(Integer, default=10)
    home_service_provider = Column(Boolean, default=False)


class Appointment(Base):
    __tablename__ = "appointments"

    id = Column(Integer, primary_key=True)
    patient_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    doctor_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    appointment_date = Column(Date, nullable=False)
    appointment_time = Column(Time, nullable=False)
    consultation_type = Column(String(50), nullable=False)
    status = Column(String(50), default="Pending Payment")
    meet_link = Column(String(500), nullable=True)


class Service(Base):
    __tablename__ = "services"

    id = Column(Integer, primary_key=True)
    name = Column(String(200), nullable=False)
    category = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    price = Column(Float, nullable=False)
    active = Column(Boolean, default=True)


class InventoryItem(Base):
    __tablename__ = "inventory"

    id = Column(Integer, primary_key=True)
    name = Column(String(200), nullable=False)
    unit_price = Column(Float, nullable=False)
    quantity = Column(Integer, nullable=False)
    expiry = Column(Date, nullable=True)


class PharmacyOrder(Base):
    __tablename__ = "pharmacy_orders"

    id = Column(Integer, primary_key=True)
    patient_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    medicine_description = Column(Text, nullable=True)
    medicine_total = Column(Float, default=0)
    delivery_fee = Column(Float, default=0)
    delivery_location = Column(Text, nullable=True)
    status = Column(String(80), default="Prescription created")
    medicine_paid = Column(Boolean, default=False)
    delivery_paid = Column(Boolean, default=False)
    rider_id = Column(Integer, ForeignKey("users.id"), nullable=True)


class Payment(Base):
    __tablename__ = "payments"

    id = Column(Integer, primary_key=True)
    patient_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    reference = Column(String(100), unique=True, nullable=False)
    amount = Column(Float, nullable=False)
    payment_type = Column(String(50), nullable=False)
    status = Column(String(30), default="completed")
    created_at = Column(String(50), nullable=False)


class HomeService(Base):
    __tablename__ = "home_services"

    id = Column(Integer, primary_key=True)
    patient_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    service_id = Column(Integer, ForeignKey("services.id"), nullable=False)
    service_date = Column(Date, nullable=False)
    service_time = Column(Time, nullable=False)
    address = Column(Text, nullable=False)
    status = Column(String(60), default="Requested")
    provider_id = Column(Integer, ForeignKey("users.id"), nullable=True)


class Notification(Base):
    __tablename__ = "notifications"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    message = Column(Text, nullable=False)
    read = Column(Boolean, default=False)
    created_at = Column(String(50), nullable=False)


Base.metadata.create_all(bind=engine)


# ============================================================
# PASSWORD HELPERS
# ============================================================

def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt,
        120_000
    )
    return f"{salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, digest_hex = stored.split("$", 1)
        salt = bytes.fromhex(salt_hex)
        calculated = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode(),
            salt,
            120_000
        ).hex()
        return hmac.compare_digest(calculated, digest_hex)
    except Exception:
        return False


# ============================================================
# DATABASE DEPENDENCY
# ============================================================

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ============================================================
# AUTHENTICATION
# ============================================================

class LoginRequest(BaseModel):
    email: EmailStr
    password: str


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    token = credentials.credentials
    user_id = TOKENS.get(token)

    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired login session"
        )

    user = db.get(User, user_id)

    if not user or not user.enabled:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account disabled or not found"
        )

    return user


def require_roles(*roles):
    def checker(user: User = Depends(get_current_user)):
        if user.role not in [r.value if isinstance(r, Role) else r for r in roles]:
            raise HTTPException(
                status_code=403,
                detail="You do not have permission for this action"
            )
        return user
    return checker


# ============================================================
# STARTUP / DEMO DATA
# ============================================================

DEMO_USERS = [
    {
        "name": "Boniface Machogu",
        "email": "boniface@beaconafrica.org",
        "password": "DemoBoniface2026!",
        "phone": "0724741827",
        "role": "admin",
    },
    {
        "name": "Eunice Wanjiku Ngugi",
        "email": "eunice.ngugi@beaconhope.demo",
        "password": "DemoEunice2026!",
        "phone": "0700000101",
        "role": "doctor",
        "specialty": "Clinical Provider",
    },
    {
        "name": "George Keitany",
        "email": "george.keitany@beaconhope.demo",
        "password": "DemoGeorge2026!",
        "phone": "0700000102",
        "role": "doctor",
        "specialty": "Clinical Provider",
    },
    {
        "name": "Benard Onyinsi",
        "email": "benard.onyinsi@beaconhope.demo",
        "password": "DemoBenard2026!",
        "phone": "0700000103",
        "role": "doctor",
        "specialty": "Clinical Provider",
    },
    {
        "name": "Angela Mwangi",
        "email": "angela.mwangi@beaconhope.demo",
        "password": "DemoAngela2026!",
        "phone": "0700000104",
        "role": "doctor",
        "specialty": "Clinical Provider",
    },
    {
        "name": "Beatrice Gitamo",
        "email": "beatrice.gitamo@beaconhope.demo",
        "password": "DemoBeatrice2026!",
        "phone": "0700000201",
        "role": "nurse",
        "home_service_provider": True,
    },
    {
        "name": "Gerald Ragira",
        "email": "gerald.ragira@beaconhope.demo",
        "password": "DemoGerald2026!",
        "phone": "0700000202",
        "role": "nurse",
        "home_service_provider": True,
    },
    {
        "name": "Peter Miano",
        "email": "peter.miano@beaconhope.demo",
        "password": "DemoPeter2026!",
        "phone": "0700000301",
        "role": "pharmacist",
    },
    {
        "name": "Rajab Ziada",
        "email": "rajab.ziada@beaconhope.demo",
        "password": "DemoRajab2026!",
        "phone": "0700000302",
        "role": "pharmacist",
    },
    {
        "name": "Dancan Bande",
        "email": "dancan.bande@beaconhope.demo",
        "password": "DemoDancan2026!",
        "phone": "0700000401",
        "role": "rider",
    },
    {
        "name": "Demo Patient",
        "email": "patient@beaconhope.demo",
        "password": "Demo123!",
        "phone": "0700000005",
        "role": "patient",
        "address": "Rongai, Nairobi",
    },
]


def seed_database():
    db = SessionLocal()

    for item in DEMO_USERS:
        existing = db.query(User).filter(
            User.email == item["email"]
        ).first()

        if not existing:
            user = User(
                name=item["name"],
                email=item["email"],
                password_hash=hash_password(item["password"]),
                phone=item.get("phone"),
                role=item["role"],
                specialty=item.get("specialty"),
                address=item.get("address"),
                home_service_provider=item.get("home_service_provider", False),
            )
            db.add(user)

    if db.query(InventoryItem).count() == 0:
        db.add_all([
            InventoryItem(
                name="Amoxicillin 500mg",
                unit_price=25,
                quantity=100,
                expiry=date(2027, 12, 31)
            ),
            InventoryItem(
                name="Paracetamol 500mg",
                unit_price=10,
                quantity=200,
                expiry=date(2027, 12, 31)
            ),
            InventoryItem(
                name="Cetirizine 10mg",
                unit_price=20,
                quantity=80,
                expiry=date(2027, 12, 31)
            ),
        ])

    if db.query(Service).count() == 0:
        db.add_all([
            Service(
                name="NCD Home Monitoring & Follow-up",
                category="Home Services",
                description="Nurse/clinician visit; BP; blood sugar where indicated; medication/adherence review; lifestyle counselling.",
                price=1500
            ),
            Service(
                name="Home Nursing & Chronic Care",
                category="Home Services",
                description="Nursing assessment; vital signs; medication support; basic nursing care; caregiver education.",
                price=2000
            ),
            Service(
                name="Mobility & Rehabilitation Support",
                category="Home Services",
                description="Physiotherapy/mobility assessment; exercises; falls-risk assessment; caregiver guidance.",
                price=2000
            ),
            Service(
                name="Post-Hospital/Post-Procedure Home Care",
                category="Home Services",
                description="Clinical review; wound/recovery assessment; vital signs; medication review; referral where needed.",
                price=2000
            ),
            Service(
                name="Elderly & Dependent Patient Care",
                category="Home Services",
                description="Nursing assessment; mobility support; vital signs; caregiver education; care-plan follow-up.",
                price=2500
            ),
            Service(
                name="Consultation fee/follow-up fee",
                category="Telemedicine / Consultation",
                description="Telemedicine consultation or follow-up with a clinical provider.",
                price=500
            ),
            Service(
                name="Telemedicine + review of home BP/glucose readings",
                category="Telemedicine / Consultation",
                description="Virtual consultation including review of home BP or glucose readings.",
                price=500
            ),
            Service(
                name="Physiotherapy virtual follow-up",
                category="Telemedicine / Consultation",
                description="Virtual physiotherapy follow-up consultation.",
                price=750
            ),
            Service(
                name="Nursing/caregiver virtual consultation",
                category="Telemedicine / Consultation",
                description="Virtual nursing or caregiver consultation.",
                price=500
            ),
        ])

    db.commit()
    db.close()


seed_database()


# ============================================================
# BASIC ROUTES
# ============================================================

@app.get("/")
def root():
    return {
        "hospital": "Beacon of Hope Hospital",
        "location": "Ongata Rongai",
        "api": "running",
        "booking_hours": "Monday-Saturday, 08:00-17:00",
        "sunday": "closed"
    }


@app.get("/health")
def health():
    return {"status": "ok"}


# ============================================================
# AUTH ROUTES
# ============================================================

@app.post("/auth/login")
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(
        User.email == payload.email.lower()
    ).first()

    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if not user.enabled:
        raise HTTPException(status_code=403, detail="Account is disabled")

    token = secrets.token_urlsafe(32)
    TOKENS[token] = user.id

    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "name": user.name,
            "email": user.email,
            "role": user.role,
            "phone": user.phone
        }
    }


class PatientRegistration(BaseModel):
    name: str = Field(min_length=2, max_length=150)
    email: EmailStr
    password: str = Field(min_length=6)
    phone: str
    address: str


@app.post("/auth/register")
def register_patient(
    payload: PatientRegistration,
    db: Session = Depends(get_db)
):
    existing = db.query(User).filter(User.email == payload.email.lower()).first()

    if existing:
        raise HTTPException(status_code=400, detail="Email already exists")

    user = User(
        name=payload.name,
        email=payload.email.lower(),
        password_hash=hash_password(payload.password),
        phone=payload.phone,
        role="patient",
        address=payload.address,
        enabled=True
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    return {
        "message": "Patient account created successfully",
        "patient_id": user.id,
        "patient_number": f"BOH-{user.id:06d}"
    }


# ============================================================
# BOOKING VALIDATION
# ============================================================

def validate_booking_window(
    booking_date: date,
    booking_time: time
):
    # Python weekday(): Monday=0 ... Sunday=6
    if booking_date.weekday() == 6:
        raise HTTPException(
            status_code=400,
            detail="There are no services available on Sunday. Please select Monday to Saturday."
        )

    if booking_time < BOOKING_OPEN or booking_time > BOOKING_CLOSE:
        raise HTTPException(
            status_code=400,
            detail="There are no services available at this time. Services are available from 8:00 AM to 5:00 PM, Monday to Saturday."
        )


def appointment_end(start: time) -> time:
    dt = datetime.combine(date.today(), start)
    end = dt + timedelta(minutes=CONSULTATION_MINUTES)
    return end.time()


def overlaps(start1: time, end1: time, start2: time, end2: time) -> bool:
    return start1 < end2 and start2 < end1


def doctor_is_available(
    db: Session,
    doctor_id: int,
    appointment_date: date,
    appointment_time: time
):
    end = appointment_end(appointment_time)

    # A 45-minute consultation cannot finish after 5 PM.
    if end > BOOKING_CLOSE:
        return False

    appointments = db.query(Appointment).filter(
        Appointment.doctor_id == doctor_id,
        Appointment.appointment_date == appointment_date,
        Appointment.status.in_(["Pending Payment", "Confirmed"])
    ).all()

    for a in appointments:
        existing_end = appointment_end(a.appointment_time)
        if overlaps(
            appointment_time, end,
            a.appointment_time, existing_end
        ):
            return False

    return True


class AppointmentCreate(BaseModel):
    doctor_id: int
    appointment_date: date
    appointment_time: time
    consultation_type: str = "Video Consultation"


@app.post("/appointments")
def create_appointment(
    payload: AppointmentCreate,
    current: User = Depends(require_roles("patient")),
    db: Session = Depends(get_db)
):
    validate_booking_window(
        payload.appointment_date,
        payload.appointment_time
    )

    doctor = db.get(User, payload.doctor_id)

    if not doctor or doctor.role != "doctor" or not doctor.enabled:
        raise HTTPException(status_code=404, detail="Doctor not available")

    if not doctor_is_available(
        db,
        doctor.id,
        payload.appointment_date,
        payload.appointment_time
    ):
        raise HTTPException(
            status_code=409,
            detail="Occupied. The doctor already has a consultation during that time."
        )

    daily_count = db.query(Appointment).filter(
        Appointment.doctor_id == doctor.id,
        Appointment.appointment_date == payload.appointment_date,
        Appointment.status.in_(["Pending Payment", "Confirmed"])
    ).count()

    if daily_count >= (doctor.max_bookings_per_day or 10):
        raise HTTPException(
            status_code=409,
            detail="The doctor has reached the maximum bookings for this day."
        )

    appointment = Appointment(
        patient_id=current.id,
        doctor_id=doctor.id,
        appointment_date=payload.appointment_date,
        appointment_time=payload.appointment_time,
        consultation_type=payload.consultation_type,
        status="Pending Payment"
    )

    db.add(appointment)
    db.commit()
    db.refresh(appointment)

    return {
        "message": "Appointment created",
        "appointment_id": appointment.id,
        "status": appointment.status,
        "doctor_status": "Occupied",
        "duration_minutes": 45
    }


@app.get("/appointments/availability/{doctor_id}")
def check_doctor_availability(
    doctor_id: int,
    appointment_date: date,
    appointment_time: time,
    current: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    validate_booking_window(appointment_date, appointment_time)

    doctor = db.get(User, doctor_id)

    if not doctor or doctor.role != "doctor":
        raise HTTPException(status_code=404, detail="Doctor not found")

    available = doctor_is_available(
        db,
        doctor_id,
        appointment_date,
        appointment_time
    )

    return {
        "doctor": doctor.name,
        "date": appointment_date,
        "time": appointment_time,
        "status": "Available" if available else "Occupied"
    }


@app.get("/appointments")
def list_appointments(
    current: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    query = db.query(Appointment)

    if current.role == "patient":
        query = query.filter(Appointment.patient_id == current.id)

    elif current.role == "doctor":
        query = query.filter(Appointment.doctor_id == current.id)

    return query.order_by(
        Appointment.appointment_date,
        Appointment.appointment_time
    ).all()


# ============================================================
# DOCTOR CONFIRMATION / GOOGLE MEET LINK
# ============================================================

@app.post("/appointments/{appointment_id}/confirm")
def confirm_appointment(
    appointment_id: int,
    current: User = Depends(require_roles("doctor")),
    db: Session = Depends(get_db)
):
    appointment = db.get(Appointment, appointment_id)

    if not appointment:
        raise HTTPException(status_code=404, detail="Appointment not found")

    if appointment.doctor_id != current.id:
        raise HTTPException(
            status_code=403,
            detail="Doctors can only manage their own patients"
        )

    appointment.status = "Confirmed"

    # Placeholder Meet URL. For production, connect Google Calendar API.
    appointment.meet_link = (
        f"https://meet.google.com/beacon-hope-{appointment.id}"
    )

    db.commit()

    return {
        "message": "Appointment confirmed",
        "status": appointment.status,
        "meet_link": appointment.meet_link
    }


# ============================================================
# SERVICES
# ============================================================

@app.get("/services")
def services(
    category: Optional[str] = None,
    db: Session = Depends(get_db)
):
    query = db.query(Service).filter(Service.active == True)

    if category:
        query = query.filter(Service.category == category)

    return query.all()


# ============================================================
# HOME SERVICES
# Existing patients only, unless a separate assessment process
# is added later.
# ============================================================

class HomeServiceCreate(BaseModel):
    service_id: int
    service_date: date
    service_time: time
    address: str


def is_returning_patient(db: Session, patient_id: int) -> bool:
    completed_appointment = db.query(Appointment).filter(
        Appointment.patient_id == patient_id,
        Appointment.status == "Completed"
    ).first()

    completed_home = db.query(HomeService).filter(
        HomeService.patient_id == patient_id,
        HomeService.status == "Completed"
    ).first()

    return bool(completed_appointment or completed_home)


@app.post("/home-services")
def create_home_service(
    payload: HomeServiceCreate,
    current: User = Depends(require_roles("patient")),
    db: Session = Depends(get_db)
):
    if not is_returning_patient(db, current.id):
        raise HTTPException(
            status_code=403,
            detail="Home services are available only to existing/returning Beacon of Hope patients."
        )

    validate_booking_window(
        payload.service_date,
        payload.service_time
    )

    service = db.get(Service, payload.service_id)

    if not service or not service.active:
        raise HTTPException(status_code=404, detail="Service not available")

    if service.category != "Home Services":
        raise HTTPException(status_code=400, detail="This is not a home service")

    home = HomeService(
        patient_id=current.id,
        service_id=service.id,
        service_date=payload.service_date,
        service_time=payload.service_time,
        address=payload.address
    )

    db.add(home)
    db.commit()
    db.refresh(home)

    return {
        "message": "Home service request created",
        "home_service_id": home.id,
        "status": home.status,
        "price": service.price
    }


# ============================================================
# INVENTORY
# ============================================================

@app.get("/inventory")
def inventory(
    current: User = Depends(require_roles("admin", "pharmacist")),
    db: Session = Depends(get_db)
):
    return db.query(InventoryItem).all()


# ============================================================
# PHARMACY ORDERS
# ============================================================

class PharmacyOrderCreate(BaseModel):
    medicine_description: Optional[str] = None
    medicine_total: float = Field(ge=0)


@app.post("/pharmacy/orders")
def create_pharmacy_order(
    payload: PharmacyOrderCreate,
    current: User = Depends(require_roles("patient")),
    db: Session = Depends(get_db)
):
    order = PharmacyOrder(
        patient_id=current.id,
        medicine_description=payload.medicine_description,
        medicine_total=payload.medicine_total,
        status="Prescription created"
    )

    db.add(order)
    db.commit()
    db.refresh(order)

    return {
        "order_id": order.id,
        "status": order.status,
        "medicine_total": order.medicine_total
    }


@app.get("/pharmacy/orders")
def pharmacy_orders(
    current: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    query = db.query(PharmacyOrder)

    if current.role == "patient":
        query = query.filter(PharmacyOrder.patient_id == current.id)

    return query.order_by(PharmacyOrder.id.desc()).all()


# ============================================================
# PHARMACY DELIVERY WORKFLOW
# GPS is intentionally not used here.
# ============================================================

class DeliveryFeeRequest(BaseModel):
    delivery_location: str
    delivery_fee: float = Field(ge=0)


@app.post("/pharmacy/orders/{order_id}/delivery-fee")
def set_delivery_fee(
    order_id: int,
    payload: DeliveryFeeRequest,
    current: User = Depends(require_roles("pharmacist", "admin")),
    db: Session = Depends(get_db)
):
    order = db.get(PharmacyOrder, order_id)

    if not order:
        raise HTTPException(status_code=404, detail="Order not found")

    order.delivery_location = payload.delivery_location
    order.delivery_fee = payload.delivery_fee

    if order.medicine_paid:
        order.status = "Payment completed"

    db.commit()

    return {
        "message": "Delivery fee confirmed",
        "delivery_fee": order.delivery_fee,
        "location": order.delivery_location
    }


# ============================================================
# PAYMENTS
# ============================================================

class PaymentRequest(BaseModel):
    amount: float = Field(gt=0)
    payment_type: str


@app.post("/payments")
def make_payment(
    payload: PaymentRequest,
    current: User = Depends(require_roles("patient")),
    db: Session = Depends(get_db)
):
    reference = f"BOH-{secrets.token_hex(6).upper()}"

    payment = Payment(
        patient_id=current.id,
        reference=reference,
        amount=payload.amount,
        payment_type=payload.payment_type,
        status="completed",
        created_at=datetime.utcnow().isoformat()
    )

    db.add(payment)
    db.commit()

    return {
        "message": "Payment recorded",
        "reference": reference,
        "amount": payload.amount,
        "status": "completed"
    }


@app.get("/payments")
def payments(
    current: User = Depends(require_roles("admin")),
    db: Session = Depends(get_db)
):
    return db.query(Payment).order_by(Payment.id.desc()).all()


# ============================================================
# DELIVERY STATUS
# Fixed workflow; no live GPS tracking.
# ============================================================

DELIVERY_STATUSES = [
    "Prescription created",
    "Pharmacy received",
    "Medicine confirmed",
    "Payment completed",
    "Preparing medicine",
    "Assigned to rider",
    "Rider picked up",
    "Out for delivery",
    "Delivered"
]


class DeliveryStatusRequest(BaseModel):
    status: str


@app.patch("/pharmacy/orders/{order_id}/status")
def update_delivery_status(
    order_id: int,
    payload: DeliveryStatusRequest,
    current: User = Depends(require_roles("pharmacist", "admin", "rider")),
    db: Session = Depends(get_db)
):
    if payload.status not in DELIVERY_STATUSES:
        raise HTTPException(
            status_code=400,
            detail="Invalid delivery status"
        )

    order = db.get(PharmacyOrder, order_id)

    if not order:
        raise HTTPException(status_code=404, detail="Order not found")

    order.status = payload.status
    db.commit()

    return {
        "order_id": order.id,
        "status": order.status,
        "gps_tracking": "disabled"
    }


# ============================================================
# RIDER ASSIGNMENT
# ============================================================

class RiderAssignment(BaseModel):
    rider_id: int


@app.post("/pharmacy/orders/{order_id}/assign-rider")
def assign_rider(
    order_id: int,
    payload: RiderAssignment,
    current: User = Depends(require_roles("pharmacist", "admin")),
    db: Session = Depends(get_db)
):
    order = db.get(PharmacyOrder, order_id)
    rider = db.get(User, payload.rider_id)

    if not order:
        raise HTTPException(status_code=404, detail="Order not found")

    if not rider or rider.role != "rider" or not rider.enabled:
        raise HTTPException(status_code=404, detail="Rider not available")

    if not order.delivery_paid:
        raise HTTPException(
            status_code=400,
            detail="Delivery fee must be paid before assigning the rider."
        )

    order.rider_id = rider.id
    order.status = "Assigned to rider"

    db.commit()

    return {
        "message": "Rider assigned",
        "rider": rider.name,
        "patient_phone_available_to_rider": True
    }


@app.get("/rider/orders")
def rider_orders(
    current: User = Depends(require_roles("rider")),
    db: Session = Depends(get_db)
):
    orders = db.query(PharmacyOrder).filter(
        PharmacyOrder.rider_id == current.id
    ).all()

    result = []

    for order in orders:
        patient = db.get(User, order.patient_id)

        result.append({
            "order_id": order.id,
            "patient_name": patient.name if patient else None,
            "patient_phone": patient.phone if patient else None,
            "delivery_location": order.delivery_location,
            "status": order.status
        })

    return result


# ============================================================
# ADMIN USER MANAGEMENT
# ============================================================

@app.get("/users")
def users(
    current: User = Depends(require_roles("admin")),
    db: Session = Depends(get_db)
):
    return db.query(User).all()


@app.patch("/users/{user_id}/disable")
def disable_user(
    user_id: int,
    current: User = Depends(require_roles("admin")),
    db: Session = Depends(get_db)
):
    user = db.get(User, user_id)

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.enabled = False
    db.commit()

    return {"message": "User disabled"}


# ============================================================
# DOCTOR PATIENT PRIVACY
# ============================================================

@app.get("/doctor/patients")
def doctor_patients(
    current: User = Depends(require_roles("doctor")),
    db: Session = Depends(get_db)
):
    patient_ids = [
        row[0]
        for row in db.query(Appointment.patient_id)
        .filter(Appointment.doctor_id == current.id)
        .distinct()
        .all()
    ]

    patients = []

    for patient_id in patient_ids:
        patient = db.get(User, patient_id)
        if patient:
            patients.append({
                "id": patient.id,
                "name": patient.name,
                "phone": patient.phone,
                "email": patient.email
            })

    return patients


# ============================================================
# GOOGLE MEET NOTE
# ============================================================

@app.get("/integrations/google-meet")
def google_meet_status(
    current: User = Depends(require_roles("admin"))
):
    return {
        "configured": False,
        "message": (
            "The appointment endpoint currently creates a placeholder "
            "Meet URL. For real Google Meet links, connect Google "
            "Calendar API/OAuth in production."
        )
    }


# ============================================================
# RUN:
# uvicorn app:app --reload
# ============================================================
