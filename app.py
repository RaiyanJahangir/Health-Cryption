import base64
import binascii
import os
import time
from datetime import datetime
from typing import Optional, List, Literal

from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Form, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from sqlalchemy import (
    create_engine, Column, Integer, String, LargeBinary, DateTime, ForeignKey, Text,
    Enum, UniqueConstraint
)
from sqlalchemy.orm import sessionmaker, declarative_base, relationship, Session
from passlib.hash import bcrypt
import jwt

# Crypto
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from nacl.public import PrivateKey as X25519PrivateKey, PublicKey as X25519PublicKey, SealedBox

# =========================
# Config
# =========================
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-change-me")
JWT_ALG = "HS256"
ACCESS_TOKEN_TTL_MIN = 120
DB_URL = "sqlite:///./secure_health.db"

# =========================
# DB setup
# =========================
engine = create_engine(DB_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

# =========================
# DB Models
# =========================
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    # "user_id" for login -> we'll use email_or_username
    email_or_username = Column(String, unique=True, nullable=False, index=True)
    role = Column(Enum("patient", "doctor", name="role"), nullable=False)
    password_hash = Column(String, nullable=False)

    # X25519 keypair (private key encrypted with password)
    public_key = Column(LargeBinary, nullable=False)
    enc_private_key = Column(LargeBinary, nullable=False)
    enc_private_key_nonce = Column(LargeBinary, nullable=False)
    enc_private_key_salt = Column(LargeBinary, nullable=False)

    patient_profile = relationship("Patient", uselist=False, back_populates="owner_user")


class Patient(Base):
    __tablename__ = "patients"
    id = Column(Integer, primary_key=True)

    owner_user_id = Column(Integer, ForeignKey("users.id"), unique=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Your separate patient_id (string OK)
    patient_identifier = Column(String, unique=True, nullable=False, index=True)
    age = Column(Integer, nullable=True)

    owner_user = relationship("User", back_populates="patient_profile")
    records = relationship("Record", back_populates="patient", cascade="all, delete-orphan")
    shared_keys = relationship("PatientKey", back_populates="patient", cascade="all, delete-orphan")


class PatientKey(Base):
    __tablename__ = "patient_keys"
    id = Column(Integer, primary_key=True)
    patient_id = Column(Integer, ForeignKey("patients.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    enc_data_key = Column(LargeBinary, nullable=False)  # sealed to user's public key
    created_at = Column(DateTime, default=datetime.utcnow)

    patient = relationship("Patient", back_populates="shared_keys")
    user = relationship("User")
    __table_args__ = (UniqueConstraint("patient_id", "user_id", name="uq_patient_user"),)


class Record(Base):
    __tablename__ = "records"
    id = Column(Integer, primary_key=True)
    patient_id = Column(Integer, ForeignKey("patients.id"), nullable=False)
    created_by_user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    mime_type = Column(String, nullable=False)
    aead_nonce = Column(LargeBinary, nullable=False)
    ciphertext = Column(LargeBinary, nullable=False)
    aad = Column(LargeBinary, nullable=True)

    laterality = Column(Enum("L", "R", name="laterality"), nullable=True)
    view_position = Column(Enum("CC", "MLO", name="viewpos"), nullable=True)

    patient = relationship("Patient", back_populates="records")
    author = relationship("User")

Base.metadata.create_all(engine)

# =========================
# Crypto helpers
# =========================
def kdf_scrypt(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(password.encode("utf-8"))

def aesgcm_encrypt(key32: bytes, plaintext: bytes, aad: Optional[bytes] = None):
    aes = AESGCM(key32)
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, plaintext, aad)
    return nonce, ct

def aesgcm_decrypt(key32: bytes, nonce: bytes, ciphertext: bytes, aad: Optional[bytes] = None) -> bytes:
    aes = AESGCM(key32)
    return aes.decrypt(nonce, ciphertext, aad)

def generate_user_keypair():
    priv = X25519PrivateKey.generate()
    pub = priv.public_key
    return priv, pub

def seal_for_pubkey(pubkey_bytes: bytes, data: bytes) -> bytes:
    sealed = SealedBox(X25519PublicKey(pubkey_bytes))
    return sealed.encrypt(data)

def open_with_privkey(privkey: X25519PrivateKey, sealed_bytes: bytes) -> bytes:
    opened = SealedBox(privkey)
    return opened.decrypt(sealed_bytes)

def protect_private_key_with_password(priv: X25519PrivateKey, password: str):
    raw = bytes(priv)  # 32 bytes
    salt = os.urandom(16)
    key = kdf_scrypt(password, salt)
    nonce, ct = aesgcm_encrypt(key, raw)
    return salt, nonce, ct

def unprotect_private_key_with_password(enc_priv: bytes, nonce: bytes, salt: bytes, password: str) -> X25519PrivateKey:
    key = kdf_scrypt(password, salt)
    raw = aesgcm_decrypt(key, nonce, enc_priv)
    return X25519PrivateKey(raw)

# =========================
# Auth helpers
# =========================
def jwt_issue(user_id: int, role: str) -> str:
    now = int(time.time())
    payload = {"sub": str(user_id), "role": role, "iat": now, "exp": now + ACCESS_TOKEN_TTL_MIN * 60}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

def jwt_verify(token: str):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

auth_bearer = HTTPBearer()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def current_user(creds: HTTPAuthorizationCredentials = Depends(auth_bearer), db: Session = Depends(get_db)) -> User:
    payload = jwt_verify(creds.credentials)
    uid = int(payload["sub"])
    user = db.query(User).get(uid)
    if not user:
        raise HTTPException(status_code=401, detail="Unknown user")
    return user

# =========================
# Schemas
# =========================
class RegisterIn(BaseModel):
    user_id: str           # login id (email/username)
    password: str
    role: Literal["patient", "doctor"]
    # If registering a patient:
    patient_identifier: Optional[str] = None
    age: Optional[int] = None

class LoginIn(BaseModel):
    user_id: str
    password: str

class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"

class RecordOut(BaseModel):
    id: int
    mime_type: str
    created_at: datetime
    ciphertext_b64: str

class PatientUpdateIn(BaseModel):
    patient_identifier: Optional[str] = None
    age: Optional[int] = None

class TextRecordUpdateIn(BaseModel):
    new_text: str

# =========================
# FastAPI app
# =========================
app = FastAPI(title="Encrypted Health Store (Client-side AEAD, No-UI)")

def _validate_laterality_view(l: Optional[str], v: Optional[str]):
    if l is not None and l not in ("L", "R"):
        raise HTTPException(400, "laterality must be 'L' or 'R'")
    if v is not None and v not in ("CC", "MLO"):
        raise HTTPException(400, "view_position must be 'CC' or 'MLO'")

def _ensure_can_view_or_edit_patient(db: Session, patient_id: int, me: User):
    patient = db.query(Patient).get(patient_id)
    if not patient:
        raise HTTPException(404, "Patient not found")
    if me.role == "patient" and patient.owner_user_id != me.id:
        raise HTTPException(403, "Patients can only act on their own record")
    return patient

def _get_patient_data_key_for_user(db: Session, patient_id: int, me: User, my_password: str) -> bytes:
    pk = db.query(PatientKey).filter_by(patient_id=patient_id, user_id=me.id).first()
    if not pk:
        raise HTTPException(403, "Not authorized for this patient")
    try:
        priv = unprotect_private_key_with_password(
            me.enc_private_key, me.enc_private_key_nonce, me.enc_private_key_salt, my_password
        )
    except Exception:
        raise HTTPException(401, "Invalid password for unwrapping your private key")
    return open_with_privkey(priv, pk.enc_data_key)

# -------- Registration / Login --------
@app.post("/register", response_model=TokenOut)
def register(body: RegisterIn, db: Session = Depends(get_db)):
    if db.query(User).filter_by(email_or_username=body.user_id).first():
        raise HTTPException(400, "user_id already registered")

    priv, pub = generate_user_keypair()
    salt, nonce, enc_priv = protect_private_key_with_password(priv, body.password)

    user = User(
        email_or_username=body.user_id,
        role=body.role,
        password_hash=bcrypt.hash(body.password),
        public_key=bytes(pub),
        enc_private_key=enc_priv,
        enc_private_key_nonce=nonce,
        enc_private_key_salt=salt,
    )
    db.add(user)
    db.flush()

    # If role=patient, create patient card immediately
    if body.role == "patient":
        if not body.patient_identifier:
            raise HTTPException(400, "patient_identifier is required for patient accounts")
        patient = Patient(
            owner_user_id=user.id,
            patient_identifier=body.patient_identifier,
            age=body.age,
        )
        db.add(patient)
        db.flush()
        data_key = os.urandom(32)
        enc_for_user = seal_for_pubkey(user.public_key, data_key)
        db.add(PatientKey(patient_id=patient.id, user_id=user.id, enc_data_key=enc_for_user))

    db.commit()
    return TokenOut(access_token=jwt_issue(user.id, user.role))

@app.post("/login", response_model=TokenOut)
def login(body: LoginIn, db: Session = Depends(get_db)):
    user = db.query(User).filter_by(email_or_username=body.user_id).first()
    if not user or not bcrypt.verify(body.password, user.password_hash):
        raise HTTPException(401, "Bad credentials")
    # Prove we can decrypt private key (integrity check of user's secret)
    _ = unprotect_private_key_with_password(
        user.enc_private_key, user.enc_private_key_nonce, user.enc_private_key_salt, body.password
    )
    return TokenOut(access_token=jwt_issue(user.id, user.role))

@app.get("/logout")
def logout():
    # JWT is stateless; client just discards it
    return {"ok": True, "message": "Client should discard the token locally."}

@app.get("/me")
def whoami(me: User = Depends(current_user), db: Session = Depends(get_db)):
    patient_id = None
    patient_identifier = None
    if me.role == "patient":
        p = db.query(Patient).filter_by(owner_user_id=me.id).first()
        if p:
            patient_id = p.id
            patient_identifier = p.patient_identifier
    return {
        "user_id": me.email_or_username,
        "role": me.role,
        "patient_row_id": patient_id,
        "patient_identifier": patient_identifier,
        "public_key_b64": base64.b64encode(me.public_key).decode(),
    }

# -------- Doctor creates patient user (if needed) --------
class DoctorCreatePatientIn(BaseModel):
    patient_user_id: str              # the login id for patient
    patient_password: str
    patient_identifier: str
    age: Optional[int] = None

@app.post("/doctor/create_patient_user")
def doctor_creates_patient_user(
    body: DoctorCreatePatientIn, me: User = Depends(current_user), db: Session = Depends(get_db)
):
    if me.role != "doctor":
        raise HTTPException(403, "Only doctors can create patient accounts")

    existing_user = db.query(User).filter_by(email_or_username=body.patient_user_id).first()
    if existing_user:
        raise HTTPException(400, "That patient user_id already exists")

    priv, pub = generate_user_keypair()
    salt, nonce, enc_priv = protect_private_key_with_password(priv, body.patient_password)

    user = User(
        email_or_username=body.patient_user_id,
        role="patient",
        password_hash=bcrypt.hash(body.patient_password),
        public_key=bytes(pub),
        enc_private_key=enc_priv,
        enc_private_key_nonce=nonce,
        enc_private_key_salt=salt,
    )
    db.add(user)
    db.flush()

    patient = Patient(
        owner_user_id=user.id,
        patient_identifier=body.patient_identifier,
        age=body.age,
    )
    db.add(patient)
    db.flush()

    data_key = os.urandom(32)
    enc_for_user = seal_for_pubkey(user.public_key, data_key)
    db.add(PatientKey(patient_id=patient.id, user_id=user.id, enc_data_key=enc_for_user))
    db.commit()
    return {"ok": True, "created_patient_user_id": body.patient_user_id, "patient_row_id": patient.id}

# -------- Sharing patient key to a doctor (access) --------
@app.post("/patients/{patient_id}/share_to_doctor")
def share_to_doctor(
    patient_id: int,
    doctor_user_id: str = Form(...),
    my_password: str = Form(...),  # password of caller to unwrap key
    me: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    patient = _ensure_can_view_or_edit_patient(db, patient_id, me)
    # Patients can share their own; doctors could also re-share if policy allows—here allow both
    doctor = db.query(User).filter_by(email_or_username=doctor_user_id, role="doctor").first()
    if not doctor:
        raise HTTPException(404, "Target doctor user not found")

    existing_pk = db.query(PatientKey).filter_by(patient_id=patient.id, user_id=me.id).first()
    if not existing_pk:
        raise HTTPException(403, "You are not authorized to share this patient")

    # unwrap with caller's private key
    caller_priv = unprotect_private_key_with_password(
        me.enc_private_key, me.enc_private_key_nonce, me.enc_private_key_salt, my_password
    )
    data_key = open_with_privkey(caller_priv, existing_pk.enc_data_key)

    # re-wrap to doctor pubkey
    enc_for_target = seal_for_pubkey(doctor.public_key, data_key)
    pk = db.query(PatientKey).filter_by(patient_id=patient.id, user_id=doctor.id).first()
    if pk:
        pk.enc_data_key = enc_for_target
    else:
        db.add(PatientKey(patient_id=patient.id, user_id=doctor.id, enc_data_key=enc_for_target))
    db.commit()
    return {"ok": True, "shared_to_doctor": doctor_user_id}

# -------- Patient card edits --------
@app.patch("/patients/{patient_id}")
def update_patient(
    patient_id: int,
    body: PatientUpdateIn,
    me: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    patient = _ensure_can_view_or_edit_patient(db, patient_id, me)
    if body.patient_identifier is not None:
        patient.patient_identifier = body.patient_identifier
    if body.age is not None:
        patient.age = body.age
    db.commit()
    return {"ok": True, "patient_id": patient_id, "age": patient.age, "patient_identifier": patient.patient_identifier}

# -------- Add / Replace images --------
@app.post("/records/image/{patient_id}", response_model=RecordOut)
def add_image_record(
    patient_id: int,
    my_password: str = Form(...),
    laterality: str = Form(...),          # "L" or "R"
    view_position: str = Form(...),       # "CC" or "MLO"
    file: UploadFile = File(...),
    me: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    _validate_laterality_view(laterality, view_position)
    patient = _ensure_can_view_or_edit_patient(db, patient_id, me)

    data_key = _get_patient_data_key_for_user(db, patient_id, me, my_password)
    blob = file.file.read()
    mime_type = file.content_type or "application/octet-stream"
    aad = f"patient:{patient_id}|mime:{mime_type}|lat:{laterality}|view:{view_position}".encode()
    nonce, ct = aesgcm_encrypt(data_key, blob, aad=aad)

    rec = Record(
        patient_id=patient_id,
        created_by_user_id=me.id,
        mime_type=mime_type,
        aead_nonce=nonce,
        ciphertext=ct,
        aad=aad,
        laterality=laterality,
        view_position=view_position,
    )
    db.add(rec)
    db.commit()
    return RecordOut(id=rec.id, mime_type=rec.mime_type, created_at=rec.created_at,
                     ciphertext_b64=base64.b64encode(ct).decode())

@app.put("/records/image/{patient_id}/{laterality}/{view_position}", response_model=RecordOut)
def replace_image_record(
    patient_id: int,
    laterality: str,
    view_position: str,
    my_password: str = Form(...),
    file: UploadFile = File(...),
    me: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    _validate_laterality_view(laterality, view_position)
    patient = _ensure_can_view_or_edit_patient(db, patient_id, me)

    data_key = _get_patient_data_key_for_user(db, patient_id, me, my_password)
    blob = file.file.read()
    mime_type = file.content_type or "application/octet-stream"
    aad = f"patient:{patient_id}|mime:{mime_type}|lat:{laterality}|view:{view_position}".encode()
    nonce, ct = aesgcm_encrypt(data_key, blob, aad=aad)

    db.query(Record).filter_by(
        patient_id=patient_id, laterality=laterality, view_position=view_position
    ).delete(synchronize_session=False)

    rec = Record(
        patient_id=patient_id,
        created_by_user_id=me.id,
        mime_type=mime_type,
        aead_nonce=nonce,
        ciphertext=ct,
        aad=aad,
        laterality=laterality,
        view_position=view_position,
    )
    db.add(rec)
    db.commit()
    return RecordOut(id=rec.id, mime_type=rec.mime_type, created_at=rec.created_at,
                     ciphertext_b64=base64.b64encode(ct).decode())

# -------- Text notes (optional) --------
@app.post("/records/text/{patient_id}", response_model=RecordOut)
def add_text_record(
    patient_id: int,
    text: str = Form(...),
    my_password: str = Form(...),
    me: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    patient = _ensure_can_view_or_edit_patient(db, patient_id, me)
    data_key = _get_patient_data_key_for_user(db, patient_id, me, my_password)
    mime_type = "text/plain"
    aad = f"patient:{patient_id}|mime:{mime_type}".encode()
    nonce, ct = aesgcm_encrypt(data_key, text.encode("utf-8"), aad=aad)
    rec = Record(
        patient_id=patient_id,
        created_by_user_id=me.id,
        mime_type=mime_type,
        aead_nonce=nonce,
        ciphertext=ct,
        aad=aad,
    )
    db.add(rec)
    db.commit()
    return RecordOut(id=rec.id, mime_type=rec.mime_type, created_at=rec.created_at,
                     ciphertext_b64=base64.b64encode(ct).decode())

@app.patch("/records/text/{record_id}", response_model=RecordOut)
def edit_text_record(
    record_id: int,
    body: TextRecordUpdateIn,
    my_password: str = Form(...),
    me: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    rec = db.query(Record).get(record_id)
    if not rec:
        raise HTTPException(404, "Record not found")
    if not rec.mime_type.startswith("text/"):
        raise HTTPException(400, "This endpoint edits text records only")

    patient = db.query(Patient).get(rec.patient_id)
    if me.role == "patient" and patient.owner_user_id != me.id:
        raise HTTPException(403, "Patients can only edit their own records")

    data_key = _get_patient_data_key_for_user(db, rec.patient_id, me, my_password)
    nonce, ct = aesgcm_encrypt(data_key, body.new_text.encode("utf-8"), aad=rec.aad)
    rec.aead_nonce = nonce
    rec.ciphertext = ct
    db.commit()
    return RecordOut(id=rec.id, mime_type=rec.mime_type, created_at=rec.created_at,
                     ciphertext_b64=base64.b64encode(ct).decode())

# -------- Listing / selective decrypted view --------
@app.get("/records/{patient_id}")
def list_records(
    patient_id: int,
    me: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    patient = _ensure_can_view_or_edit_patient(db, patient_id, me)
    recs = db.query(Record).filter_by(patient_id=patient_id).order_by(Record.created_at.desc()).all()
    out = []
    for r in recs:
        out.append({
            "id": r.id,
            "mime_type": r.mime_type,
            "laterality": r.laterality,
            "view_position": r.view_position,
            "created_at": r.created_at,
            "ciphertext_len": len(r.ciphertext),
        })
    return out

class SelectiveFields(BaseModel):
    # which fields to decrypt/return: "age", "images", "notes"
    want_age: bool = True
    want_images: bool = True
    want_notes: bool = True

@app.post("/patient/{patient_id}/view_selective")
def view_selective(
    patient_id: int,
    my_password: str = Form(...),
    want_age: bool = Form(True),
    want_images: bool = Form(True),
    want_notes: bool = Form(True),
    me: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    patient = _ensure_can_view_or_edit_patient(db, patient_id, me)
    result = {"patient_identifier": patient.patient_identifier}

    if want_age:
        result["age"] = patient.age

    if want_images or want_notes:
        data_key = _get_patient_data_key_for_user(db, patient_id, me, my_password)
        if want_images:
            imgs = db.query(Record).filter(
                Record.patient_id == patient_id,
                Record.mime_type.like("image/%")
            ).all()
            img_out = []
            for r in imgs:
                try:
                    pt = aesgcm_decrypt(data_key, r.aead_nonce, r.ciphertext, aad=r.aad)
                    img_out.append({
                        "record_id": r.id,
                        "laterality": r.laterality,
                        "view_position": r.view_position,
                        "mime_type": r.mime_type,
                        "image_b64": base64.b64encode(pt).decode(),
                    })
                except Exception as e:
                    img_out.append({"record_id": r.id, "error": "integrity check failed"})
            result["images"] = img_out

        if want_notes:
            notes = db.query(Record).filter(
                Record.patient_id == patient_id,
                Record.mime_type.like("text/%")
            ).all()
            note_out = []
            for r in notes:
                try:
                    pt = aesgcm_decrypt(data_key, r.aead_nonce, r.ciphertext, aad=r.aad)
                    note_out.append({
                        "record_id": r.id,
                        "mime_type": r.mime_type,
                        "text": pt.decode("utf-8", errors="replace"),
                    })
                except Exception:
                    note_out.append({"record_id": r.id, "error": "integrity check failed"})
            result["notes"] = note_out

    return result

# -------- Decrypt single record --------
@app.post("/records/decrypt/{record_id}")
def decrypt_record(
    record_id: int,
    my_password: str = Form(...),
    me: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    rec = db.query(Record).get(record_id)
    if not rec:
        raise HTTPException(404, "Record not found")
    patient = db.query(Patient).get(rec.patient_id)
    if me.role == "patient" and patient.owner_user_id != me.id:
        raise HTTPException(403, "Patients can only view their own records")

    data_key = _get_patient_data_key_for_user(db, rec.patient_id, me, my_password)
    pt = aesgcm_decrypt(data_key, rec.aead_nonce, rec.ciphertext, aad=rec.aad)
    return {
        "id": rec.id,
        "mime_type": rec.mime_type,
        "laterality": rec.laterality,
        "view_position": rec.view_position,
        "plaintext_b64": base64.b64encode(pt).decode(),
    }

# -------- Delete record --------
@app.delete("/records/{record_id}")
def delete_record(
    record_id: int,
    me: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    rec = db.query(Record).get(record_id)
    if not rec:
        raise HTTPException(404, "Record not found")
    patient = db.query(Patient).get(rec.patient_id)
    if me.role == "patient" and patient.owner_user_id != me.id:
        raise HTTPException(403, "Patients can only delete their own records")
    db.delete(rec)
    db.commit()
    return {"ok": True, "deleted_record_id": record_id}

# =========================
# Proof of Confidentiality & Integrity
# =========================
@app.get("/proof/confidentiality")
def proof_confidentiality(patient_id: int, limit: int = 4, db: Session = Depends(get_db)):
    """
    Shows hexdumps of ciphertext and nonces only; demonstrates data-at-rest is not plaintext.
    """
    recs = db.query(Record).filter_by(patient_id=patient_id).order_by(Record.created_at.desc()).limit(limit).all()
    out = []
    for r in recs:
        out.append({
            "record_id": r.id,
            "mime_type": r.mime_type,
            "laterality": r.laterality,
            "view_position": r.view_position,
            "nonce_hex": binascii.hexlify(r.aead_nonce).decode(),
            "ciphertext_sample_hex": binascii.hexlify(r.ciphertext[:32]).decode(),
            "ciphertext_len": len(r.ciphertext)
        })
    return {"ciphertexts": out, "note": "These are AEAD ciphertext bytes; plaintext is never stored."}

@app.post("/proof/integrity/tamper_then_try_decrypt/{record_id}")
def proof_integrity_tamper(record_id: int, my_password: str = Form(...), me: User = Depends(current_user), db: Session = Depends(get_db)):
    """
    Flips a byte in the ciphertext in DB, then attempts to decrypt -> should fail with integrity error.
    DO NOT use in production; this is just to show GCM integrity enforcement.
    """
    rec = db.query(Record).get(record_id)
    if not rec:
        raise HTTPException(404, "Record not found")
    patient = db.query(Patient).get(rec.patient_id)
    if me.role == "patient" and patient.owner_user_id != me.id:
        raise HTTPException(403, "Patients can only test their own records")

    # Tamper: flip 1 bit
    if len(rec.ciphertext) == 0:
        raise HTTPException(400, "Empty ciphertext?")
    tampered = bytearray(rec.ciphertext)
    tampered[0] ^= 0x01
    rec.ciphertext = bytes(tampered)
    db.commit()

    data_key = _get_patient_data_key_for_user(db, rec.patient_id, me, my_password)
    try:
        _ = aesgcm_decrypt(data_key, rec.aead_nonce, rec.ciphertext, aad=rec.aad)
        return {"unexpected": "decryption succeeded (GCM integrity should have failed)"}
    except Exception as e:
        return {"ok": True, "integrity_enforced": True, "error_type": type(e).__name__, "message": "Tampering detected; decryption failed as expected."}
