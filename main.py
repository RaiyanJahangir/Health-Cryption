import os
import sys
import getpass
from pathlib import Path
from typing import Optional
import mimetypes

try:
    import requests
except ImportError:
    requests = None

from passlib.hash import argon2
from sqlalchemy.orm import Session

from db import SessionLocal
from models import Patient, Doctor, PatientDoctorAccess
from crypto import (
    scrypt_kdf, aesgcm_encrypt, aesgcm_decrypt, random_key32,
    x25519_generate, protect_privkey_with_password, unprotect_privkey_with_password,
    sealed_box_encrypt, sealed_box_decrypt
)

# ---------- basic io ----------
def input_safe(prompt: str) -> str:
    return input(prompt)

def input_password(prompt: str) -> str:
    return getpass.getpass(prompt)

def fetch_bytes_from_link(link: str) -> bytes:
    p = Path(link)
    if p.exists() and p.is_file():
        return p.read_bytes()
    if link.lower().startswith("http://") or link.lower().startswith("https://"):
        if requests is None:
            raise RuntimeError("requests is not installed. pip install requests")
        resp = requests.get(link, timeout=30)
        resp.raise_for_status()
        return resp.content
    raise FileNotFoundError(f"Not a file or URL: {link}")

def mime_from_link(link: str) -> str:
    mt, _ = mimetypes.guess_type(link)
    return mt or "application/octet-stream"

# ---------- per-patient key wrapping ----------
def wrap_patient_key_for_patient(patient_key: bytes, password: str):
    salt = os.urandom(16)
    k = scrypt_kdf(password, salt, 32)
    nonce, ct = aesgcm_encrypt(k, patient_key)
    return salt, nonce, ct

def unwrap_patient_key_as_patient(p: Patient, password: str) -> bytes:
    k = scrypt_kdf(password, p.enc_data_key_for_patient_salt, 32)
    return aesgcm_decrypt(k, p.enc_data_key_for_patient_nonce, p.enc_data_key_for_patient)

# ---------- auto-grants ----------
def grant_patient_to_all_doctors(db: Session, p: Patient, patient_key: bytes):
    doctors = db.query(Doctor).all()
    for d in doctors:
        sealed = sealed_box_encrypt(d.public_key, patient_key)
        existing = db.query(PatientDoctorAccess).filter_by(patient_id=p.id, doctor_id=d.id).first()
        if existing:
            existing.enc_data_key_for_doctor = sealed
        else:
            db.add(PatientDoctorAccess(patient_id=p.id, doctor_id=d.id, enc_data_key_for_doctor=sealed))
    db.commit()

# For brand-new doctors we cannot unwrap patients' keys here (no patient pw, no other doctor's privkey).
# We'll lazily create missing grants the first time the doctor opens a legacy patient (see doctor_session).

# ---------- encrypt/decrypt helpers ----------
def encrypt_field(patient_key: bytes, plaintext_str: Optional[str], aad: str):
    if plaintext_str is None or plaintext_str == "":
        return None, None
    nonce, ct = aesgcm_encrypt(patient_key, plaintext_str.encode("utf-8"), aad=aad.encode())
    return nonce, ct

def decrypt_field(patient_key: bytes, nonce: Optional[bytes], ct: Optional[bytes], aad: str) -> Optional[str]:
    if nonce is None or ct is None:
        return None
    pt = aesgcm_decrypt(patient_key, nonce, ct, aad=aad.encode())
    return pt.decode("utf-8", errors="replace")

def img_slot_menu() -> str:
    print("Which image? a)L-CC  b)L-MLO  c)R-CC  d)R-MLO")
    return input_safe("Choose: ").strip().lower()

def set_image_on_patient(p: Patient, slot: str, nonce, ct, mime):
    if slot == "a":
        p.l_cc_img_nonce, p.l_cc_img_ct, p.l_cc_img_mime = nonce, ct, mime
    elif slot == "b":
        p.l_mlo_img_nonce, p.l_mlo_img_ct, p.l_mlo_img_mime = nonce, ct, mime
    elif slot == "c":
        p.r_cc_img_nonce, p.r_cc_img_ct, p.r_cc_img_mime = nonce, ct, mime
    elif slot == "d":
        p.r_mlo_img_nonce, p.r_mlo_img_ct, p.r_mlo_img_mime = nonce, ct, mime
    else:
        raise ValueError("Invalid image slot")

def clear_image_on_patient(p: Patient, slot: str):
    if slot == "a":
        p.l_cc_img_ct = p.l_cc_img_nonce = p.l_cc_img_mime = None
    elif slot == "b":
        p.l_mlo_img_ct = p.l_mlo_img_nonce = p.l_mlo_img_mime = None
    elif slot == "c":
        p.r_cc_img_ct = p.r_cc_img_nonce = p.r_cc_img_mime = None
    elif slot == "d":
        p.r_mlo_img_ct = p.r_mlo_img_nonce = p.r_mlo_img_mime = None
    else:
        raise ValueError("Invalid image slot")

def view_patient_decrypted(p: Patient, patient_key: bytes, selective=False):
    show_age = show_birads = show_density = show_findings = show_images = True
    if selective:
        def yn(q): 
            return input_safe(q + " [y/N]: ").strip().lower().startswith("y")
        show_age = yn("Show age?")
        show_birads = yn("Show BIRADS?")
        show_density = yn("Show breast density?")
        show_findings = yn("Show findings?")
        show_images = yn("Show images (showing cipher length/mime/tags only)?")

    print("\n=== Decrypted View ===")
    print(f"Patient ID: {p.patient_id} | Login user_id: {p.user_id}")
    if show_age:
        print("Age:", decrypt_field(patient_key, p.age_nonce, p.age_ct, aad="age"))
    if show_birads:
        print("BIRADS:", decrypt_field(patient_key, p.birads_nonce, p.birads_ct, aad="birads"))
    if show_density:
        print("Breast Density:", decrypt_field(patient_key, p.breast_density_nonce, p.breast_density_ct, aad="breast_density"))
    if show_findings:
        print("Findings:", decrypt_field(patient_key, p.findings_nonce, p.findings_ct, aad="findings"))

    if show_images:
        def img_info(ct, mime, lat, view):
            if ct is None:
                return "None"
            return f"cipher_len={len(ct)} mime={mime or '?'} tags=({lat},{view})"
        print("L-CC:", img_info(p.l_cc_img_ct, p.l_cc_img_mime, p.l_cc_laterality, p.l_cc_view))
        print("L-MLO:", img_info(p.l_mlo_img_ct, p.l_mlo_img_mime, p.l_mlo_laterality, p.l_mlo_view))
        print("R-CC:", img_info(p.r_cc_img_ct, p.r_cc_img_mime, p.r_cc_laterality, p.r_cc_view))
        print("R-MLO:", img_info(p.r_mlo_img_ct, p.r_mlo_img_mime, p.r_mlo_laterality, p.r_mlo_view))
    print("======================\n")

# ---------- account creation ----------
def create_patient_account(db: Session):
    print("\n-- Create Patient Account --")
    patient_id = input_safe("Enter unique patient_id: ").strip()
    user_id = input_safe("Choose your login user_id: ").strip()
    password = input_password("Choose a password: ").strip()

    if db.query(Patient).filter_by(user_id=user_id).first():
        print("A patient with that user_id already exists.")
        return
    if db.query(Patient).filter_by(patient_id=patient_id).first():
        print("That patient_id already exists.")
        return

    # per-patient data key wrapped to patient's password
    patient_key = random_key32()
    salt_p = os.urandom(16)
    k_p = scrypt_kdf(password, salt_p, 32)
    nonce_p, ct_p = aesgcm_encrypt(k_p, patient_key)

    row = Patient(
        patient_id=patient_id,
        user_id=user_id,
        password_hash=argon2.hash(password),
        role="patient",
        enc_data_key_for_patient=ct_p,
        enc_data_key_for_patient_nonce=nonce_p,
        enc_data_key_for_patient_salt=salt_p,
    )
    db.add(row)
    db.commit()

    # AUTO-GRANT to all existing doctors (we have the patient's key now)
    grant_patient_to_all_doctors(db, row, patient_key)
    print("Patient account created (granted to all doctors).")

def create_doctor_account(db: Session):
    print("\n-- Create Doctor Account --")
    user_id = input_safe("Choose doctor user_id: ").strip()
    password = input_password("Choose a password: ").strip()
    if db.query(Doctor).filter_by(user_id=user_id).first():
        print("A doctor with that user_id already exists.")
        return

    # X25519 keypair; encrypt private key with password
    priv, pub = x25519_generate()
    salt, nonce, enc_priv = protect_privkey_with_password(priv, password)

    row = Doctor(
        user_id=user_id,
        password_hash=argon2.hash(password),
        role="doctor",
        public_key=bytes(pub),
        enc_private_key=enc_priv,
        enc_private_key_nonce=nonce,
        enc_private_key_salt=salt,
    )
    db.add(row)
    db.commit()

    print("Doctor account created (patients will be accessible; missing grants created on first access if needed).")

# ---------- sessions ----------
def patient_session(db: Session, p: Patient):
    print(f"\nWelcome, patient {p.user_id}")
    while True:
        print("1) View my data (selectively)")
        print("2) Add/Update demographics (age, BIRADS, density, findings)")
        print("3) Add/Update images by link (L-CC/L-MLO/R-CC/R-MLO)")
        print("4) Remove an image")
        print("5) Logout")
        choice = input_safe("Choose: ").strip()

        if choice == "1":
            pw = input_password("Enter your password to decrypt: ").strip()
            try:
                patient_key = unwrap_patient_key_as_patient(p, pw)
            except Exception:
                print("Wrong password or integrity error.")
                continue
            selective = input_safe("Selective view? [y/N]: ").strip().lower().startswith("y")
            view_patient_decrypted(p, patient_key, selective=selective)

        elif choice == "2":
            pw = input_password("Enter your password to encrypt updates: ").strip()
            try:
                patient_key = unwrap_patient_key_as_patient(p, pw)
            except Exception:
                print("Wrong password or integrity error.")
                continue
            age = input_safe("Age (blank=skip): ").strip()
            birads = input_safe("BIRADS (blank=skip): ").strip()
            density = input_safe("Breast density (blank=skip): ").strip()
            findings = input_safe("Findings (blank=skip): ").strip()
            if age:
                p.age_nonce, p.age_ct = aesgcm_encrypt(patient_key, age.encode(), aad=b"age")
            if birads:
                p.birads_nonce, p.birads_ct = aesgcm_encrypt(patient_key, birads.encode(), aad=b"birads")
            if density:
                p.breast_density_nonce, p.breast_density_ct = aesgcm_encrypt(patient_key, density.encode(), aad=b"breast_density")
            if findings:
                p.findings_nonce, p.findings_ct = aesgcm_encrypt(patient_key, findings.encode(), aad=b"findings")
            db.commit()
            print("Updated.")

        elif choice == "3":
            pw = input_password("Enter your password to encrypt image: ").strip()
            try:
                patient_key = unwrap_patient_key_as_patient(p, pw)
            except Exception:
                print("Wrong password or integrity error.")
                continue
            slot = img_slot_menu()
            link = input_safe("Enter file path or URL: ").strip()
            try:
                blob = fetch_bytes_from_link(link)
            except Exception as e:
                print(f"Error: {e}")
                continue
            mime = mime_from_link(link)
            aad_map = {"a": "img:L-CC", "b": "img:L-MLO", "c": "img:R-CC", "d": "img:R-MLO"}
            if slot not in aad_map:
                print("Invalid choice."); continue
            nonce, ct = aesgcm_encrypt(patient_key, blob, aad=aad_map[slot].encode())
            set_image_on_patient(p, slot, nonce, ct, mime)
            db.commit()
            print("Image saved (encrypted).")

        elif choice == "4":
            slot = img_slot_menu()
            try:
                clear_image_on_patient(p, slot)
            except Exception:
                print("Invalid choice.")
                continue
            db.commit()
            print("Removed.")

        elif choice == "5":
            print("Logged out.")
            return
        else:
            print("Invalid choice.")

def doctor_session(db: Session, d: Doctor):
    print(f"\nWelcome, Dr. {d.user_id}")
    doctor_priv = None  # cache private key for session
    while True:
        print("1) List patients I can access")
        print("2) View a patient (decrypt)")
        print("3) Update a patient’s fields (encrypt)")
        print("4) Add/Update a patient image by link")
        print("5) Remove a patient image")
        print("6) Logout")
        choice = input_safe("Choose: ").strip()

        if choice == "1":
            accesses = db.query(PatientDoctorAccess).filter_by(doctor_id=d.id).all()
            if not accesses:
                print("No sealed entries yet (new doctor). You can still open patients; missing grants will be created on first access.")
            pats = db.query(Patient).all()
            for p in pats:
                flag = "[✓]" if db.query(PatientDoctorAccess).filter_by(patient_id=p.id, doctor_id=d.id).first() else "[ ]"
                print(f"{flag} patient_id={p.patient_id} (login={p.user_id})")

        elif choice in {"2","3","4","5"}:
            pid = input_safe("Enter patient_id: ").strip()
            p = db.query(Patient).filter_by(patient_id=pid).first()
            if not p:
                print("Not found."); continue

            # unlock doctor's private key if needed
            if doctor_priv is None:
                pw = input_password("Enter your password to unlock your private key: ").strip()
                try:
                    doctor_priv = unprotect_privkey_with_password(
                        d.enc_private_key, d.enc_private_key_nonce, d.enc_private_key_salt, pw
                    )
                except Exception:
                    print("Wrong password or integrity error.")
                    doctor_priv = None
                    continue

            # ensure a sealed key exists for this doctor, lazily backfilling if needed
            access = db.query(PatientDoctorAccess).filter_by(patient_id=p.id, doctor_id=d.id).first()
            if not access:
                print("(First access) This patient has no sealed key for you yet.")
                patpw = input_password("If you know the patient's password, enter it now to enable future access (or leave blank to skip): ").strip()
                if patpw:
                    try:
                        patient_key_tmp = unwrap_patient_key_as_patient(p, patpw)
                        sealed = sealed_box_encrypt(bytes(doctor_priv.public_key), patient_key_tmp)
                        newacc = PatientDoctorAccess(patient_id=p.id, doctor_id=d.id, enc_data_key_for_doctor=sealed)
                        db.add(newacc); db.commit()
                        access = newacc
                        print("Access grant created for you.")
                    except Exception:
                        print("Could not unwrap with that password. Continuing without grant.")
                        access = None

            if not access:
                print("Access not available for this patient yet (try again later or on next patient creation).")
                continue

            try:
                patient_key = sealed_box_decrypt(doctor_priv, access.enc_data_key_for_doctor)
            except Exception:
                print("Failed to open sealed patient key."); continue

            if choice == "2":
                selective = input_safe("Selective view? [y/N]: ").strip().lower().startswith("y")
                view_patient_decrypted(p, patient_key, selective=selective)

            elif choice == "3":
                age = input_safe("Age (blank=skip): ").strip()
                birads = input_safe("BIRADS (blank=skip): ").strip()
                density = input_safe("Breast density (blank=skip): ").strip()
                findings = input_safe("Findings (blank=skip): ").strip()
                if age: p.age_nonce, p.age_ct = aesgcm_encrypt(patient_key, age.encode(), aad=b"age")
                if birads: p.birads_nonce, p.birads_ct = aesgcm_encrypt(patient_key, birads.encode(), aad=b"birads")
                if density: p.breast_density_nonce, p.breast_density_ct = aesgcm_encrypt(patient_key, density.encode(), aad=b"breast_density")
                if findings: p.findings_nonce, p.findings_ct = aesgcm_encrypt(patient_key, findings.encode(), aad=b"findings")
                db.commit(); print("Updated.")

            elif choice == "4":
                slot = img_slot_menu()
                link = input_safe("Enter file path or URL: ").strip()
                try:
                    blob = fetch_bytes_from_link(link)
                except Exception as e:
                    print(f"Error: {e}"); continue
                mime = mime_from_link(link)
                aad_map = {"a": "img:L-CC", "b": "img:L-MLO", "c": "img:R-CC", "d": "img:R-MLO"}
                if slot not in aad_map:
                    print("Invalid choice."); continue
                nonce, ct = aesgcm_encrypt(patient_key, blob, aad=aad_map[slot].encode())
                set_image_on_patient(p, slot, nonce, ct, mime)
                db.commit(); print("Image saved (encrypted).")

            elif choice == "5":
                slot = img_slot_menu()
                try:
                    clear_image_on_patient(p, slot)
                except Exception:
                    print("Invalid choice."); continue
                db.commit(); print("Removed.")

        elif choice == "6":
            print("Logged out.")
            return
        else:
            print("Invalid choice.")

# ---------- main ----------
def main():
    print("=== Secure CLI (SQLite + AES-GCM + per-doctor X25519) ===")
    print(f"DB path: {Path(os.getcwd()) / 'data' / 'secure_health.db'}")
    while True:
        print("\n1) Login")
        print("2) Create patient account")
        print("3) Create doctor account")
        print("4) Exit")
        cmd = input_safe("Choose: ").strip()

        if cmd == "1":
            with SessionLocal() as db:
                uid = input_safe("user_id: ").strip()
                pw = input_password("password: ").strip()

                p = db.query(Patient).filter_by(user_id=uid).first()
                if p and argon2.verify(pw, p.password_hash):
                    patient_session(db, p); continue

                d = db.query(Doctor).filter_by(user_id=uid).first()
                if d and argon2.verify(pw, d.password_hash):
                    doctor_session(db, d); continue

                print("Invalid credentials.")

        elif cmd == "2":
            with SessionLocal() as db:
                create_patient_account(db)

        elif cmd == "3":
            with SessionLocal() as db:
                create_doctor_account(db)

        elif cmd == "4":
            print("Goodbye."); sys.exit(0)
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()
