"""
Sync helpers that keep the plaintext SQLite database in lockstep with the
encrypted store. All create/update/delete operations should go through these
helpers so both datasets stay consistent.
"""
from typing import Optional
from sqlalchemy.orm import Session
from models import PlainPatient, PlainDoctor

IMG_SLOT_ATTRS = {
    "a": ("l_cc_img", "l_cc_img_mime"),
    "b": ("l_mlo_img", "l_mlo_img_mime"),
    "c": ("r_cc_img", "r_cc_img_mime"),
    "d": ("r_mlo_img", "r_mlo_img_mime"),
}


def ensure_plain_patient(
    plain_db: Session,
    *,
    patient_id: str,
    user_id: Optional[str] = None,
    name: Optional[str] = None,
    age: Optional[str] = None,
    password_hash: Optional[str] = None,
    secure_id: Optional[int] = None,
) -> PlainPatient:
    row = plain_db.query(PlainPatient).filter_by(patient_id=patient_id).first()
    if not row:
        if user_id is None or name is None or password_hash is None:
            raise ValueError("patient creation requires user_id, name, and password_hash")
        row = PlainPatient(
            patient_id=patient_id,
            user_id=user_id,
            name=name,
            age=age,
            password_hash=password_hash,
            secure_id=secure_id,
        )
        plain_db.add(row)
    else:
        if user_id is not None:
            row.user_id = user_id
        if name is not None:
            row.name = name
        if age is not None:
            row.age = age
        if password_hash is not None:
            row.password_hash = password_hash
        if secure_id is not None:
            row.secure_id = secure_id
    plain_db.commit()
    return row


def update_plain_patient_fields(
    plain_db: Session,
    *,
    patient_id: str,
    name: Optional[str] = None,
    age: Optional[str] = None,
    birads: Optional[str] = None,
    breast_density: Optional[str] = None,
    findings: Optional[str] = None,
):
    row = plain_db.query(PlainPatient).filter_by(patient_id=patient_id).first()
    if not row:
        return
    if name is not None:
        row.name = name
    if age is not None:
        row.age = age
    if birads is not None:
        row.birads = birads
    if breast_density is not None:
        row.breast_density = breast_density
    if findings is not None:
        row.findings = findings
    plain_db.commit()


def set_plain_patient_image(
    plain_db: Session,
    *,
    patient_id: str,
    slot: str,
    blob: Optional[bytes],
    mime: Optional[str],
):
    row = plain_db.query(PlainPatient).filter_by(patient_id=patient_id).first()
    if not row:
        return
    attrs = IMG_SLOT_ATTRS.get(slot)
    if not attrs:
        raise ValueError("Invalid image slot")
    setattr(row, attrs[0], blob)
    setattr(row, attrs[1], mime)
    plain_db.commit()


def clear_plain_patient_image(plain_db: Session, *, patient_id: str, slot: str):
    set_plain_patient_image(plain_db, patient_id=patient_id, slot=slot, blob=None, mime=None)


def delete_plain_patient(plain_db: Session, patient_id: str):
    row = plain_db.query(PlainPatient).filter_by(patient_id=patient_id).first()
    if row:
        plain_db.delete(row)
        plain_db.commit()


def ensure_plain_doctor(
    plain_db: Session,
    *,
    doctor_id: str,
    user_id: Optional[str] = None,
    name: Optional[str] = None,
    age: Optional[int] = None,
    password_hash: Optional[str] = None,
    role: Optional[str] = "doctor",
    secure_id: Optional[int] = None,
) -> PlainDoctor:
    row = plain_db.query(PlainDoctor).filter_by(doctor_id=doctor_id).first()
    if not row:
        if None in (user_id, name, age, password_hash):
            raise ValueError("doctor creation requires user_id, name, age, password_hash")
        row = PlainDoctor(
            doctor_id=doctor_id,
            user_id=user_id,
            name=name,
            age=age,
            password_hash=password_hash,
            role=role or "doctor",
            secure_id=secure_id,
        )
        plain_db.add(row)
    else:
        if user_id is not None:
            row.user_id = user_id
        if name is not None:
            row.name = name
        if age is not None:
            row.age = age
        if password_hash is not None:
            row.password_hash = password_hash
        if role is not None:
            row.role = role
        if secure_id is not None:
            row.secure_id = secure_id
    plain_db.commit()
    return row


def delete_plain_doctor(plain_db: Session, doctor_id: str):
    row = plain_db.query(PlainDoctor).filter_by(doctor_id=doctor_id).first()
    if row:
        plain_db.delete(row)
        plain_db.commit()
