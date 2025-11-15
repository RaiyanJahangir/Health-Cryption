from sqlalchemy import Column, Integer, String, LargeBinary, DateTime, ForeignKey, UniqueConstraint
from sqlalchemy.orm import relationship
from datetime import datetime
from db import Base, PlainBase

class Patient(Base):
    __tablename__ = "patients"

    id = Column(Integer, primary_key=True)

    # Identity & login (stored encrypted; mirror_id links to plaintext DB)
    plain_id = Column(Integer, unique=True, nullable=False)
    patient_id_ct = Column(LargeBinary, nullable=False)
    patient_id_nonce = Column(LargeBinary, nullable=False)
    user_id_ct = Column(LargeBinary, nullable=False)
    user_id_nonce = Column(LargeBinary, nullable=False)
    password_hash_ct = Column(LargeBinary, nullable=False)
    password_hash_nonce = Column(LargeBinary, nullable=False)
    name_ct = Column(LargeBinary, nullable=True)
    name_nonce = Column(LargeBinary, nullable=True)

    # Per-patient AES-256 key, wrapped for the patient (password-derived)
    enc_data_key_for_patient = Column(LargeBinary, nullable=False)
    enc_data_key_for_patient_nonce = Column(LargeBinary, nullable=False)
    enc_data_key_for_patient_salt = Column(LargeBinary, nullable=False)

    # Encrypted clinical fields
    age_ct = Column(LargeBinary, nullable=True)
    age_nonce = Column(LargeBinary, nullable=True)

    birads_ct = Column(LargeBinary, nullable=True)
    birads_nonce = Column(LargeBinary, nullable=True)

    breast_density_ct = Column(LargeBinary, nullable=True)
    breast_density_nonce = Column(LargeBinary, nullable=True)

    findings_ct = Column(LargeBinary, nullable=True)
    findings_nonce = Column(LargeBinary, nullable=True)

    # Four mammogram images (ciphertext/nonce/mime) + tags
    l_cc_img_ct = Column(LargeBinary, nullable=True)
    l_cc_img_nonce = Column(LargeBinary, nullable=True)
    l_cc_img_mime = Column(String, nullable=True)
    l_cc_laterality = Column(String, default="L")
    l_cc_view = Column(String, default="CC")

    l_mlo_img_ct = Column(LargeBinary, nullable=True)
    l_mlo_img_nonce = Column(LargeBinary, nullable=True)
    l_mlo_img_mime = Column(String, nullable=True)
    l_mlo_laterality = Column(String, default="L")
    l_mlo_view = Column(String, default="MLO")

    r_cc_img_ct = Column(LargeBinary, nullable=True)
    r_cc_img_nonce = Column(LargeBinary, nullable=True)
    r_cc_img_mime = Column(String, nullable=True)
    r_cc_laterality = Column(String, default="R")
    r_cc_view = Column(String, default="CC")

    r_mlo_img_ct = Column(LargeBinary, nullable=True)
    r_mlo_img_nonce = Column(LargeBinary, nullable=True)
    r_mlo_img_mime = Column(String, nullable=True)
    r_mlo_laterality = Column(String, default="R")
    r_mlo_view = Column(String, default="MLO")

    # access grants (sealed patient key for each doctor)
    accesses = relationship("PatientDoctorAccess", back_populates="patient", cascade="all, delete-orphan")


class Doctor(Base):
    __tablename__ = "doctors"

    id = Column(Integer, primary_key=True)
    plain_id = Column(Integer, unique=True, nullable=False)
    doctor_id_ct = Column(LargeBinary, nullable=False)
    doctor_id_nonce = Column(LargeBinary, nullable=False)
    user_id_ct = Column(LargeBinary, nullable=False)
    user_id_nonce = Column(LargeBinary, nullable=False)
    password_hash_ct = Column(LargeBinary, nullable=False)
    password_hash_nonce = Column(LargeBinary, nullable=False)
    name_ct = Column(LargeBinary, nullable=False)
    name_nonce = Column(LargeBinary, nullable=False)
    age_ct = Column(LargeBinary, nullable=False)
    age_nonce = Column(LargeBinary, nullable=False)
    profile_salt = Column(LargeBinary, nullable=False)

    # X25519: public clear; private encrypted with doctor's password
    public_key = Column(LargeBinary, nullable=False)
    enc_private_key = Column(LargeBinary, nullable=False)
    enc_private_key_nonce = Column(LargeBinary, nullable=False)
    enc_private_key_salt = Column(LargeBinary, nullable=False)

    accesses = relationship("PatientDoctorAccess", back_populates="doctor", cascade="all, delete-orphan")


class PatientDoctorAccess(Base):
    """
    Patient -> sealed AES key for this doctor (X25519 SealedBox to doctor's public key).
    """
    __tablename__ = "patient_doctor_access"

    id = Column(Integer, primary_key=True)
    patient_id = Column(Integer, ForeignKey("patients.id"), nullable=False)
    doctor_id = Column(Integer, ForeignKey("doctors.id"), nullable=False)
    enc_data_key_for_doctor = Column(LargeBinary, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    patient = relationship("Patient", back_populates="accesses")
    doctor = relationship("Doctor", back_populates="accesses")

    __table_args__ = (UniqueConstraint("patient_id", "doctor_id", name="uq_patient_doctor"),)


class PlainPatient(PlainBase):
    """
    Plaintext mirror of patients for auditing/legacy interoperability.
    """
    __tablename__ = "plain_patients"

    id = Column(Integer, primary_key=True)
    patient_id = Column(String, unique=True, nullable=False, index=True)
    user_id = Column(String, unique=True, nullable=False, index=True)
    name = Column(String, nullable=False)
    age = Column(String, nullable=True)
    birads = Column(String, nullable=True)
    breast_density = Column(String, nullable=True)
    findings = Column(String, nullable=True)
    password_hash = Column(String, nullable=False)
    secure_id = Column(Integer, unique=True, nullable=True)

    l_cc_img = Column(LargeBinary, nullable=True)
    l_cc_img_mime = Column(String, nullable=True)
    l_cc_laterality = Column(String, default="L")
    l_cc_view = Column(String, default="CC")

    l_mlo_img = Column(LargeBinary, nullable=True)
    l_mlo_img_mime = Column(String, nullable=True)
    l_mlo_laterality = Column(String, default="L")
    l_mlo_view = Column(String, default="MLO")

    r_cc_img = Column(LargeBinary, nullable=True)
    r_cc_img_mime = Column(String, nullable=True)
    r_cc_laterality = Column(String, default="R")
    r_cc_view = Column(String, default="CC")

    r_mlo_img = Column(LargeBinary, nullable=True)
    r_mlo_img_mime = Column(String, nullable=True)
    r_mlo_laterality = Column(String, default="R")
    r_mlo_view = Column(String, default="MLO")


class PlainDoctor(PlainBase):
    """
    Plaintext mirror of doctors.
    """
    __tablename__ = "plain_doctors"

    id = Column(Integer, primary_key=True)
    doctor_id = Column(String, unique=True, nullable=False, index=True)
    user_id = Column(String, unique=True, nullable=False, index=True)
    name = Column(String, nullable=False)
    age = Column(Integer, nullable=False)
    password_hash = Column(String, nullable=False)
    role = Column(String, nullable=False, default="doctor")
    secure_id = Column(Integer, unique=True, nullable=True)
