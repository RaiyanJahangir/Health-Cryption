#!/usr/bin/env python3
"""
Doctor view/export helper (run from project root):
- Prompts for doctor user_id & password (always doctor role).
- Prompts for patient_id.
- Prints decrypted text fields (age, BIRADS, density, findings).
- Saves any available images (L-CC, L-MLO, R-CC, R-MLO) as PNGs in the CWD.

Usage:
    python doctor_dump_patient.py
"""

import getpass
import io
import sys
from pathlib import Path

from PIL import Image
from sqlalchemy.orm import Session
from passlib.hash import argon2

from db import SessionLocal, PlainSessionLocal
from models import Patient, Doctor, PatientDoctorAccess, PlainPatient, PlainDoctor
from crypto import (
    aesgcm_decrypt,
    unprotect_privkey_with_password,
    sealed_box_decrypt,
)

# AAD map must match what you used when encrypting
AAD_MAP = {
    "a": "img:L-CC",
    "b": "img:L-MLO",
    "c": "img:R-CC",
    "d": "img:R-MLO",
}

def get_img_triplet(p: Patient, slot: str):
    if slot == "a":
        return p.l_cc_img_nonce, p.l_cc_img_ct, p.l_cc_img_mime
    if slot == "b":
        return p.l_mlo_img_nonce, p.l_mlo_img_ct, p.l_mlo_img_mime
    if slot == "c":
        return p.r_cc_img_nonce, p.r_cc_img_ct, p.r_cc_img_mime
    if slot == "d":
        return p.r_mlo_img_nonce, p.r_mlo_img_ct, p.r_mlo_img_mime
    raise ValueError("slot must be one of a,b,c,d")

def decrypt_text_field(patient_key: bytes, nonce, ct, aad_key: str):
    if not nonce or not ct:
        return None
    try:
        pt = aesgcm_decrypt(patient_key, nonce, ct, aad=aad_key.encode())
        return pt.decode("utf-8", errors="replace")
    except Exception:
        return None

def save_png(img_bytes: bytes, out_path: Path):
    out_path = out_path.with_suffix(".png") if out_path.suffix == "" else out_path
    img = Image.open(io.BytesIO(img_bytes))
    img.save(out_path)
    return out_path

def main():
    print("=== Doctor quick viewer/export ===")
    doctor_uid = input("Doctor user_id: ").strip()
    doctor_pw  = getpass.getpass("Doctor password: ").strip()

    patient_id = input("Patient ID to open: ").strip()

    with SessionLocal() as db, PlainSessionLocal() as plain_db:
        # find doctor & patient
        plain_doc = plain_db.query(PlainDoctor).filter_by(user_id=doctor_uid).first()
        if not plain_doc or plain_doc.secure_id is None:
            print("Doctor not found."); sys.exit(1)
        if not argon2.verify(doctor_pw, plain_doc.password_hash):
            print("Invalid doctor credentials."); sys.exit(1)
        d = db.query(Doctor).filter_by(id=plain_doc.secure_id).first()
        if not d:
            print("Doctor secure record missing."); sys.exit(1)

        plain_patient = plain_db.query(PlainPatient).filter_by(patient_id=patient_id).first()
        if not plain_patient or plain_patient.secure_id is None:
            print("Patient not found."); sys.exit(1)
        p = db.query(Patient).filter_by(id=plain_patient.secure_id).first()
        if not p:
            print("Patient secure record missing."); sys.exit(1)

        # unlock doctor's private key (X25519)
        try:
            doctor_priv = unprotect_privkey_with_password(
                d.enc_private_key, d.enc_private_key_nonce, d.enc_private_key_salt, doctor_pw
            )
        except Exception:
            print("Wrong doctor password or key corrupted."); sys.exit(1)

        # find sealed patient key for this doctor
        access = db.query(PatientDoctorAccess).filter_by(patient_id=p.id, doctor_id=d.id).first()
        if not access:
            print("No sealed key for this doctor/patient yet.")
            print("If this is a legacy patient (created before this doctor), create the grant by re-saving the patient or via your main CLI first.")
            sys.exit(1)

        # open the patient's AES key
        try:
            patient_key = sealed_box_decrypt(doctor_priv, access.enc_data_key_for_doctor)
        except Exception:
            print("Failed to open sealed patient key."); sys.exit(1)

        # Decrypt and print text fields
        age            = decrypt_text_field(patient_key, p.age_nonce,            p.age_ct,            "age")
        birads         = decrypt_text_field(patient_key, p.birads_nonce,         p.birads_ct,         "birads")
        breast_density = decrypt_text_field(patient_key, p.breast_density_nonce, p.breast_density_ct, "breast_density")
        findings       = decrypt_text_field(patient_key, p.findings_nonce,       p.findings_ct,       "findings")

        pid_plain = decrypt_text_field(patient_key, p.patient_id_nonce, p.patient_id_ct, "patient_id")
        uid_plain = decrypt_text_field(patient_key, p.user_id_nonce, p.user_id_ct, "user_id")
        print("\n=== Decrypted Patient Data ===")
        print(f"patient_id: {pid_plain} (login: {uid_plain or plain_patient.user_id})")
        print(f"Age:             {age!r}")
        print(f"BIRADS:          {birads!r}")
        print(f"Breast Density:  {breast_density!r}")
        print(f"Findings:        {findings!r}")

        # Decrypt and save any available images
        saved_any = False
        for slot, tag in AAD_MAP.items():
            nonce, ct, mime = get_img_triplet(p, slot)
            if not nonce or not ct:
                continue
            try:
                img_bytes = aesgcm_decrypt(patient_key, nonce, ct, aad=tag.encode())
            except Exception:
                print(f"[{tag}] decryption failed (tampered or wrong key).")
                continue
            outfile = Path(f"{pid_plain}_{tag.replace('img:','').replace('-','_')}.png")
            outpath = save_png(img_bytes, outfile)
            print(f"[{tag}] saved -> {outpath}")
            saved_any = True

        if not saved_any:
            print("No images were stored for this patient.")

        print("\nDone.")

if __name__ == "__main__":
    main()
