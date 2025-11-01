#!/usr/bin/env python3
import argparse
import getpass
import io
import os
from pathlib import Path

from PIL import Image
from sqlalchemy.orm import Session

# import your app modules
from db import SessionLocal
from models import Patient, Doctor, PatientDoctorAccess
from crypto import (
    scrypt_kdf, aesgcm_decrypt,
    unprotect_privkey_with_password, sealed_box_decrypt
)

AAD_MAP = {"a": "img:L-CC", "b": "img:L-MLO", "c": "img:R-CC", "d": "img:R-MLO"}

def pick_slot(slot_str: str):
    s = slot_str.lower().strip()
    if s not in AAD_MAP:
        raise ValueError("slot must be one of: a (L-CC), b (L-MLO), c (R-CC), d (R-MLO)")
    return s

def unwrap_patient_key_as_patient(p: Patient, patient_password: str) -> bytes:
    k = scrypt_kdf(patient_password, p.enc_data_key_for_patient_salt, 32)
    return aesgcm_decrypt(k, p.enc_data_key_for_patient_nonce, p.enc_data_key_for_patient)

def get_patient_img_triplet(p: Patient, slot: str):
    # returns (nonce, ct, mime)
    if slot == "a":
        return p.l_cc_img_nonce, p.l_cc_img_ct, p.l_cc_img_mime
    if slot == "b":
        return p.l_mlo_img_nonce, p.l_mlo_img_ct, p.l_mlo_img_mime
    if slot == "c":
        return p.r_cc_img_nonce, p.r_cc_img_ct, p.r_cc_img_mime
    if slot == "d":
        return p.r_mlo_img_nonce, p.r_mlo_img_ct, p.r_mlo_img_mime

def show_or_save(img_bytes: bytes, mime: str, outpath: str | None, title: str):
    # Try to infer format for saving
    pil = Image.open(io.BytesIO(img_bytes))
    if outpath:
        # Pick extension/format
        fmt = None
        if outpath.lower().endswith((".png", ".jpg", ".jpeg", ".tif", ".tiff", ".bmp")):
            pil.save(outpath)
        else:
            # default to PNG if no extension
            out = Path(outpath)
            if out.suffix == "":
                out = out.with_suffix(".png")
            pil.save(out)
            outpath = str(out)
        print(f"Decrypted image saved to: {outpath}")
    else:
        # Opens in default image viewer (works on Win/Linux/macOS)
        try:
            pil.show(title=title)
            print("Opened image in your default viewer.")
        except Exception as e:
            # Fallback: write a temp file
            tmp = Path("./decrypted_output.png").resolve()
            pil.save(tmp)
            print(f"Could not open viewer; wrote {tmp}")

def doctor_open_patient_key(db: Session, d: Doctor, doctor_password: str, p: Patient) -> bytes:
    # unlock doctor's private key
    priv = unprotect_privkey_with_password(
        d.enc_private_key, d.enc_private_key_nonce, d.enc_private_key_salt, doctor_password
    )
    # require sealed grant to this doctor
    access = db.query(PatientDoctorAccess).filter_by(patient_id=p.id, doctor_id=d.id).first()
    if not access:
        raise RuntimeError("No sealed key grant for this patient/doctor. (This is auto-created on new patient creation.)")
    # open sealed patient key
    return sealed_box_decrypt(priv, access.enc_data_key_for_doctor)

def main():
    ap = argparse.ArgumentParser(description="Decrypt & view/save a patient's mammogram image")
    ap.add_argument("--as-role", choices=["patient", "doctor"], required=True, help="Authenticate as patient or doctor")
    ap.add_argument("--user-id", required=True, help="Login user_id (patient's or doctor's)")
    ap.add_argument("--patient-id", required=True, help="Patient ID to open")
    ap.add_argument("--slot", required=True, help="Image slot: a=L-CC, b=L-MLO, c=R-CC, d=R-MLO")
    ap.add_argument("--out", default=None, help="Optional path to save the decrypted image (e.g., out.png)")
    args = ap.parse_args()

    slot = pick_slot(args.slot)

    with SessionLocal() as db:
        p = db.query(Patient).filter_by(patient_id=args.patient_id).first()
        if not p:
            raise SystemExit("Patient not found.")

        if args.as_role == "patient":
            # user-id must match patient
            if p.user_id != args.user_id:
                raise SystemExit("As patient, user_id must match the patient's login user_id.")
            pw = getpass.getpass("Enter patient password: ").strip()
            try:
                patient_key = unwrap_patient_key_as_patient(p, pw)
            except Exception:
                raise SystemExit("Wrong patient password or integrity error.")
        else:
            d = db.query(Doctor).filter_by(user_id=args.user_id).first()
            if not d:
                raise SystemExit("Doctor not found.")
            pw = getpass.getpass("Enter doctor password: ").strip()
            try:
                patient_key = doctor_open_patient_key(db, d, pw, p)
            except Exception as e:
                raise SystemExit(f"Cannot open patient key as doctor: {e}")

        nonce, ct, mime = get_patient_img_triplet(p, slot)
        if not ct or not nonce:
            raise SystemExit("No image stored in that slot.")

        aad = AAD_MAP[slot].encode()
        try:
            img_bytes = aesgcm_decrypt(patient_key, nonce, ct, aad=aad)
        except Exception:
            raise SystemExit("Decryption failed (tampered or wrong keys).")

        show_or_save(img_bytes, mime or "application/octet-stream",
                     args.out, title=f"{p.patient_id} {AAD_MAP[slot]}")

if __name__ == "__main__":
    main()
