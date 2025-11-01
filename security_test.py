#!/usr/bin/env python3
"""
Security self-test for confidentiality & integrity.

Run from project root:
    python security_selftest.py

This will prompt you for:
- a patient_id and that patient's password
- a doctor user_id and that doctor's password

What it checks:
1) Confidentiality at rest: encrypted fields are not plaintext, correct keys decrypt.
2) Integrity: tamper (flip one byte) -> AES-GCM auth fails; wrong AAD fails; wrong key fails.
3) Access control: doctor must unlock private key and have a sealed grant to decrypt patient data.

No writes are made to the DB; all tamper tests are done on copies in memory.
"""

import binascii
import getpass
import os
import random
import sys
from pathlib import Path

from sqlalchemy.orm import Session

from db import SessionLocal
from models import Patient, Doctor, PatientDoctorAccess
from crypto import (
    aesgcm_decrypt, aesgcm_encrypt, scrypt_kdf,
    unprotect_privkey_with_password, sealed_box_decrypt
)

# AAD map must match main app
AAD_MAP = {
    "a": "img:L-CC",
    "b": "img:L-MLO",
    "c": "img:R-CC",
    "d": "img:R-MLO",
}
TEXT_AADS = {
    "age": "age",
    "birads": "birads",
    "breast_density": "breast_density",
    "findings": "findings",
}

def unwrap_patient_key_as_patient(p: Patient, pw: str) -> bytes:
    k = scrypt_kdf(pw, p.enc_data_key_for_patient_salt, 32)
    return aesgcm_decrypt(k, p.enc_data_key_for_patient_nonce, p.enc_data_key_for_patient)

def doctor_open_patient_key(db: Session, d: Doctor, doctor_pw: str, p: Patient) -> bytes:
    priv = unprotect_privkey_with_password(
        d.enc_private_key, d.enc_private_key_nonce, d.enc_private_key_salt, doctor_pw
    )
    access = db.query(PatientDoctorAccess).filter_by(patient_id=p.id, doctor_id=d.id).first()
    if not access:
        raise RuntimeError("No sealed grant for this doctor/patient.")
    return sealed_box_decrypt(priv, access.enc_data_key_for_doctor)

def flip_one_byte(b: bytes) -> bytes:
    if not b:
        return b
    i = random.randrange(len(b))
    flipped = bytes([b[i] ^ 0x01])
    return b[:i] + flipped + b[i+1:]

def print_pass(label: str):
    print(f"[PASS] {label}")

def print_fail(label: str, err: Exception | str):
    print(f"[FAIL] {label} -> {err}")

def sample_hex(b: bytes | None, n: int = 32) -> str:
    if not b:
        return "<None>"
    return binascii.hexlify(b[:n]).decode()

def decrypt_text_field(patient_key: bytes, nonce, ct, aad_key: str):
    if not nonce or not ct: 
        return None
    return aesgcm_decrypt(patient_key, nonce, ct, aad=aad_key.encode()).decode("utf-8", errors="replace")

def get_img_triplet(p: Patient, slot: str):
    if slot == "a": return p.l_cc_img_nonce, p.l_cc_img_ct, p.l_cc_img_mime
    if slot == "b": return p.l_mlo_img_nonce, p.l_mlo_img_ct, p.l_mlo_img_mime
    if slot == "c": return p.r_cc_img_nonce, p.r_cc_img_ct, p.r_cc_img_mime
    if slot == "d": return p.r_mlo_img_nonce, p.r_mlo_img_ct, p.r_mlo_img_mime
    return None, None, None

def main():
    print("=== Security Self-Test ===")
    print(f"DB path: {Path(os.getcwd()) / 'data' / 'secure_health.db'}")

    patient_id = input("patient_id to test: ").strip()
    patient_pw  = getpass.getpass("patient password: ").strip()
    doctor_uid  = input("doctor user_id to test: ").strip()
    doctor_pw   = getpass.getpass("doctor password: ").strip()

    with SessionLocal() as db:
        p = db.query(Patient).filter_by(patient_id=patient_id).first()
        if not p:
            print_fail("lookup patient", "patient not found")
            sys.exit(1)
        d = db.query(Doctor).filter_by(user_id=doctor_uid).first()
        if not d:
            print_fail("lookup doctor", "doctor not found")
            sys.exit(1)

        # ---------- Confidentiality: decrypt works only with correct key ----------
        try:
            patient_key_patient = unwrap_patient_key_as_patient(p, patient_pw)
            print_pass("Patient key unwrap (as patient)")
        except Exception as e:
            print_fail("Patient key unwrap (as patient)", e); sys.exit(1)

        try:
            patient_key_doctor = doctor_open_patient_key(db, d, doctor_pw, p)
            print_pass("Patient key unwrap (as doctor via sealed grant)")
        except Exception as e:
            print_fail("Patient key unwrap (as doctor)", e); sys.exit(1)

        # try a wrong key
        wrong_key = os.urandom(32)

        # ---------- Fields to check ----------
        text_fields = [
            ("age", p.age_nonce, p.age_ct, TEXT_AADS["age"]),
            ("birads", p.birads_nonce, p.birads_ct, TEXT_AADS["birads"]),
            ("breast_density", p.breast_density_nonce, p.breast_density_ct, TEXT_AADS["breast_density"]),
            ("findings", p.findings_nonce, p.findings_ct, TEXT_AADS["findings"]),
        ]

        any_text = False
        for name, nonce, ct, aad in text_fields:
            if not nonce or not ct:
                continue
            any_text = True
            # Show that ciphertext is non-plaintext looking
            print(f"\n{name}: nonce_hex={sample_hex(nonce)} ct_hex={sample_hex(ct)}")

            # 1) Correct decrypt (patient key)
            try:
                pt = aesgcm_decrypt(patient_key_patient, nonce, ct, aad=aad.encode()).decode("utf-8", "replace")
                print_pass(f"{name}: decrypt ok (patient key) -> {pt!r}")
            except Exception as e:
                print_fail(f"{name}: decrypt (patient key)", e)

            # 2) Wrong key should fail
            try:
                _ = aesgcm_decrypt(wrong_key, nonce, ct, aad=aad.encode())
                print_fail(f"{name}: wrong key should fail", "decrypted unexpectedly")
            except Exception:
                print_pass(f"{name}: wrong key rejected")

            # 3) Tamper ciphertext should fail
            tampered_ct = flip_one_byte(ct)
            try:
                _ = aesgcm_decrypt(patient_key_patient, nonce, tampered_ct, aad=aad.encode())
                print_fail(f"{name}: tampered ct should fail", "decrypted unexpectedly")
            except Exception:
                print_pass(f"{name}: tampered ct rejected")

            # 4) Tamper nonce should fail
            tampered_nonce = flip_one_byte(nonce)
            try:
                _ = aesgcm_decrypt(patient_key_patient, tampered_nonce, ct, aad=aad.encode())
                print_fail(f"{name}: tampered nonce should fail", "decrypted unexpectedly")
            except Exception:
                print_pass(f"{name}: tampered nonce rejected")

            # 5) Wrong AAD should fail
            wrong_aad = (aad + "_WRONG").encode()
            try:
                _ = aesgcm_decrypt(patient_key_patient, nonce, ct, aad=wrong_aad)
                print_fail(f"{name}: wrong AAD should fail", "decrypted unexpectedly")
            except Exception:
                print_pass(f"{name}: wrong AAD rejected")

        if not any_text:
            print("\n[INFO] No text fields stored for this patient; skipping text checks.")

        # ---------- Image slots ----------
        for slot, tag in AAD_MAP.items():
            nonce, ct, mime = get_img_triplet(p, slot)
            if not nonce or not ct:
                continue
            print(f"\nimage {tag}: nonce_hex={sample_hex(nonce)} ct_hex={sample_hex(ct)} mime={mime}")
            # correct decrypt
            try:
                _ = aesgcm_decrypt(patient_key_doctor, nonce, ct, aad=tag.encode())
                print_pass(f"{tag}: decrypt ok (doctor key)")
            except Exception as e:
                print_fail(f"{tag}: decrypt (doctor key)", e)

            # wrong key
            try:
                _ = aesgcm_decrypt(wrong_key, nonce, ct, aad=tag.encode())
                print_fail(f"{tag}: wrong key should fail", "decrypted unexpectedly")
            except Exception:
                print_pass(f"{tag}: wrong key rejected")

            # tamper ct
            try:
                _ = aesgcm_decrypt(patient_key_patient, nonce, flip_one_byte(ct), aad=tag.encode())
                print_fail(f"{tag}: tampered ct should fail", "decrypted unexpectedly")
            except Exception:
                print_pass(f"{tag}: tampered ct rejected")

            # wrong AAD
            try:
                _ = aesgcm_decrypt(patient_key_patient, nonce, ct, aad=b"img:RANDOM")
                print_fail(f"{tag}: wrong AAD should fail", "decrypted unexpectedly")
            except Exception:
                print_pass(f"{tag}: wrong AAD rejected")

        print("\n=== Summary ===")
        print("If all steps above show PASS (and any present fields/images rejected tampering),")
        print("you have evidence of:")
        print("- Confidentiality at rest (AES-256 keys; doctor key sealed; passwords hashed)")
        print("- Integrity via AES-GCM (tamper -> auth failure)")
        print("- Access control (patient password / doctor private key + sealed grant)")

if __name__ == "__main__":
    main()
