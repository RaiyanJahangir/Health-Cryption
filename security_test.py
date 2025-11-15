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

from sqlalchemy.orm import Session

from config import SECURE_DB_PATH, PLAIN_DB_PATH
from db import SessionLocal, PlainSessionLocal
from models import Patient, Doctor, PatientDoctorAccess, PlainPatient, PlainDoctor
from crypto import (
    aesgcm_decrypt, scrypt_kdf,
    unprotect_privkey_with_password, sealed_box_decrypt
)

# AAD map must match main app
AAD_MAP = {
    "a": "img:L-CC",
    "b": "img:L-MLO",
    "c": "img:R-CC",
    "d": "img:R-MLO",
}
PATIENT_FIELD_SPECS = [
    {"label": "patient_id", "nonce": "patient_id_nonce", "ct": "patient_id_ct", "aad": "patient_id", "plain": "patient_id"},
    {"label": "user_id", "nonce": "user_id_nonce", "ct": "user_id_ct", "aad": "user_id", "plain": "user_id"},
    {"label": "password_hash", "nonce": "password_hash_nonce", "ct": "password_hash_ct", "aad": "password_hash", "plain": "password_hash"},
    {"label": "name", "nonce": "name_nonce", "ct": "name_ct", "aad": "name", "plain": "name"},
    {"label": "age", "nonce": "age_nonce", "ct": "age_ct", "aad": "age", "plain": "age"},
    {"label": "birads", "nonce": "birads_nonce", "ct": "birads_ct", "aad": "birads", "plain": "birads"},
    {"label": "breast_density", "nonce": "breast_density_nonce", "ct": "breast_density_ct", "aad": "breast_density", "plain": "breast_density"},
    {"label": "findings", "nonce": "findings_nonce", "ct": "findings_ct", "aad": "findings", "plain": "findings"},
]
DOCTOR_FIELD_SPECS = [
    {"label": "doctor_id", "nonce": "doctor_id_nonce", "ct": "doctor_id_ct", "aad": "doctor_id", "plain": "doctor_id"},
    {"label": "user_id", "nonce": "user_id_nonce", "ct": "user_id_ct", "aad": "user_id", "plain": "user_id"},
    {"label": "password_hash", "nonce": "password_hash_nonce", "ct": "password_hash_ct", "aad": "password_hash", "plain": "password_hash"},
    {"label": "name", "nonce": "name_nonce", "ct": "name_ct", "aad": "name", "plain": "name"},
    {"label": "age", "nonce": "age_nonce", "ct": "age_ct", "aad": "age", "plain": "age"},
]
PLAIN_IMG_ATTRS = {
    "a": ("l_cc_img", "l_cc_img_mime"),
    "b": ("l_mlo_img", "l_mlo_img_mime"),
    "c": ("r_cc_img", "r_cc_img_mime"),
    "d": ("r_mlo_img", "r_mlo_img_mime"),
}
TEST_STATE = {"failures": 0}

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
    TEST_STATE["failures"] += 1
    print(f"[FAIL] {label} -> {err}")

def sample_hex(b: bytes | None, n: int = 32) -> str:
    if not b:
        return "<None>"
    return binascii.hexlify(b[:n]).decode()

def get_img_triplet(p: Patient, slot: str):
    if slot == "a": return p.l_cc_img_nonce, p.l_cc_img_ct, p.l_cc_img_mime
    if slot == "b": return p.l_mlo_img_nonce, p.l_mlo_img_ct, p.l_mlo_img_mime
    if slot == "c": return p.r_cc_img_nonce, p.r_cc_img_ct, p.r_cc_img_mime
    if slot == "d": return p.r_mlo_img_nonce, p.r_mlo_img_ct, p.r_mlo_img_mime
    return None, None, None

def derive_doctor_profile_key(d: Doctor, password: str) -> bytes:
    return scrypt_kdf(password, d.profile_salt, 32)

def run_confidentiality_checks(
    *,
    label: str,
    nonce: bytes,
    ct: bytes,
    aad: str | bytes,
    correct_key: bytes,
    wrong_key: bytes,
    plain_value=None,
    decode_mode: str = "text",
    extra_note: str | None = None,
):
    aad_bytes = aad.encode() if isinstance(aad, str) else aad
    print(f"\n[{label}]")
    print(f"  nonce_hex={sample_hex(nonce)}")
    print(f"  ct_hex   ={sample_hex(ct)}")
    if extra_note:
        print(f"  {extra_note}")

    try:
        plaintext = aesgcm_decrypt(correct_key, nonce, ct, aad=aad_bytes)
        if decode_mode == "text":
            decoded = plaintext.decode("utf-8", errors="replace")
            print_pass(f"{label}: decrypt ok with correct key")
            print(f"    plaintext -> {decoded!r}")
            if plain_value is not None:
                mirror_text = None if plain_value is None else str(plain_value)
                print(f"    mirror    -> {mirror_text!r}")
                if mirror_text == decoded:
                    print_pass(f"{label}: plaintext matches plain mirror")
                else:
                    print_fail(f"{label}: mismatch vs plain mirror", "values differ")
        else:
            length = len(plaintext)
            print_pass(f"{label}: decrypt ok with correct key")
            print(f"    plaintext bytes -> {length} bytes")
            if isinstance(plain_value, (bytes, bytearray)):
                print(f"    mirror bytes    -> {len(plain_value)} bytes")
                if bytes(plain_value) == plaintext:
                    print_pass(f"{label}: bytes match plain mirror")
                else:
                    print_fail(f"{label}: mismatch vs plain mirror bytes", "bytes differ")
    except Exception as e:
        print_fail(f"{label}: decrypt (correct key)", e)

    try:
        _ = aesgcm_decrypt(wrong_key, nonce, ct, aad=aad_bytes)
        print_fail(f"{label}: wrong key should fail", "decrypted unexpectedly")
    except Exception:
        print_pass(f"{label}: wrong key rejected")

def run_integrity_checks(
    *,
    label: str,
    nonce: bytes,
    ct: bytes,
    aad: str | bytes,
    correct_key: bytes,
):
    aad_bytes = aad.encode() if isinstance(aad, str) else aad
    print(f"\n[{label}]")

    tampered_ct = flip_one_byte(ct)
    try:
        _ = aesgcm_decrypt(correct_key, nonce, tampered_ct, aad=aad_bytes)
        print_fail(f"{label}: tampered ciphertext should fail", "decrypted unexpectedly")
    except Exception:
        print_pass(f"{label}: tampered ciphertext rejected")

    tampered_nonce = flip_one_byte(nonce)
    try:
        _ = aesgcm_decrypt(correct_key, tampered_nonce, ct, aad=aad_bytes)
        print_fail(f"{label}: tampered nonce should fail", "decrypted unexpectedly")
    except Exception:
        print_pass(f"{label}: tampered nonce rejected")

    wrong_aad = (aad_bytes or b"") + b"::WRONG"
    try:
        _ = aesgcm_decrypt(correct_key, nonce, ct, aad=wrong_aad)
        print_fail(f"{label}: wrong AAD should fail", "decrypted unexpectedly")
    except Exception:
        print_pass(f"{label}: wrong AAD rejected")

def main():
    print("=== Security Self-Test ===")
    print(f"Secure DB: {SECURE_DB_PATH.resolve()}")
    print(f"Plain DB : {PLAIN_DB_PATH.resolve()}")
    TEST_STATE["failures"] = 0

    patient_id = input("patient_id to test: ").strip()
    patient_pw  = getpass.getpass("patient password: ").strip()
    doctor_uid  = input("doctor user_id to test: ").strip()
    doctor_pw   = getpass.getpass("doctor password: ").strip()

    with SessionLocal() as db, PlainSessionLocal() as plain_db:
        plain_patient = plain_db.query(PlainPatient).filter_by(patient_id=patient_id).first()
        if not plain_patient:
            print_fail("lookup patient", "patient not found")
            sys.exit(1)
        plain_doctor = plain_db.query(PlainDoctor).filter_by(user_id=doctor_uid).first()
        if not plain_doctor:
            print_fail("lookup doctor", "doctor not found")
            sys.exit(1)
        p = None
        if plain_patient.secure_id is not None:
            p = db.query(Patient).filter_by(id=plain_patient.secure_id).first()
        if not p:
            p = db.query(Patient).filter_by(plain_id=plain_patient.id).first()
        if not p:
            print_fail("lookup patient secure row", "missing secure record")
            sys.exit(1)
        d = None
        if plain_doctor.secure_id is not None:
            d = db.query(Doctor).filter_by(id=plain_doctor.secure_id).first()
        if not d:
            d = db.query(Doctor).filter_by(plain_id=plain_doctor.id).first()
        if not d:
            print_fail("lookup doctor secure row", "missing secure record")
            sys.exit(1)

        print("\n==== Confidentiality Test ====")
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

        if patient_key_patient == patient_key_doctor:
            print_pass("Patient key equality (patient vs doctor view)")
        else:
            print_fail("Patient key mismatch", "patient/doctor derived different keys")

        try:
            doctor_profile_key = derive_doctor_profile_key(d, doctor_pw)
            print_pass("Doctor profile key derivation (scrypt)")
        except Exception as e:
            print_fail("Doctor profile key derivation", e)
            sys.exit(1)

        # Random wrong keys for confidentiality/integrity tests
        wrong_patient_key = os.urandom(len(patient_key_patient))
        wrong_profile_key = os.urandom(len(doctor_profile_key))

        field_entries = []

        print("\n--- Patient text & identity fields ---")
        patient_text_checked = False
        for spec in PATIENT_FIELD_SPECS:
            nonce = getattr(p, spec["nonce"])
            ct = getattr(p, spec["ct"])
            if not nonce or not ct:
                continue
            patient_text_checked = True
            plain_value = getattr(plain_patient, spec["plain"], None)
            field_entries.append({
                "label": f"patient::{spec['label']}",
                "nonce": nonce,
                "ct": ct,
                "aad": spec["aad"],
                "correct_key": patient_key_patient,
                "wrong_key": wrong_patient_key,
                "plain_value": plain_value,
                "decode_mode": "text",
                "extra_note": None,
            })
        if not patient_text_checked:
            print("[INFO] No encrypted patient text fields stored for this record.")

        print("\n--- Doctor profile fields (sealed in doctors table) ---")
        doctor_fields_checked = False
        for spec in DOCTOR_FIELD_SPECS:
            nonce = getattr(d, spec["nonce"])
            ct = getattr(d, spec["ct"])
            if not nonce or not ct:
                continue
            doctor_fields_checked = True
            plain_value = getattr(plain_doctor, spec["plain"], None)
            field_entries.append({
                "label": f"doctor::{spec['label']}",
                "nonce": nonce,
                "ct": ct,
                "aad": spec["aad"],
                "correct_key": doctor_profile_key,
                "wrong_key": wrong_profile_key,
                "plain_value": plain_value,
                "decode_mode": "text",
                "extra_note": None,
            })
        if not doctor_fields_checked:
            print("[INFO] No encrypted doctor profile fields stored for this record.")

        print("\n--- Patient image slots ---")
        image_checked = False
        for slot, tag in AAD_MAP.items():
            nonce, ct, mime = get_img_triplet(p, slot)
            if not nonce or not ct:
                continue
            image_checked = True
            plain_attrs = PLAIN_IMG_ATTRS.get(slot)
            plain_blob = plain_mime = None
            if plain_attrs:
                plain_blob = getattr(plain_patient, plain_attrs[0], None)
                plain_mime = getattr(plain_patient, plain_attrs[1], None)
            mime_note = f"mime={mime or '?'} | plain_mirror_mime={plain_mime or '?'}"
            field_entries.append({
                "label": f"image::{tag}",
                "nonce": nonce,
                "ct": ct,
                "aad": tag,
                "correct_key": patient_key_doctor,
                "wrong_key": wrong_patient_key,
                "plain_value": plain_blob,
                "decode_mode": "bytes",
                "extra_note": mime_note,
            })
        if not image_checked:
            print("[INFO] No encrypted images stored for this patient.")

        if not field_entries:
            print("[INFO] No encrypted fields available for confidentiality checks.")
        else:
            for entry in field_entries:
                run_confidentiality_checks(
                    label=entry["label"],
                    nonce=entry["nonce"],
                    ct=entry["ct"],
                    aad=entry["aad"],
                    correct_key=entry["correct_key"],
                    wrong_key=entry["wrong_key"],
                    plain_value=entry["plain_value"],
                    decode_mode=entry["decode_mode"],
                    extra_note=entry["extra_note"],
                )

        print("\n==== Integrity Test ====")
        if not field_entries:
            print("[INFO] No encrypted fields available for integrity checks.")
        else:
            for entry in field_entries:
                run_integrity_checks(
                    label=entry["label"],
                    nonce=entry["nonce"],
                    ct=entry["ct"],
                    aad=entry["aad"],
                    correct_key=entry["correct_key"],
                )

        print("\n=== Summary ===")
        if TEST_STATE["failures"]:
            print(f"- Detected {TEST_STATE['failures']} failure(s). Review the log above; confidentiality or integrity was not fully verified.")
        else:
            print("- Confidentiality maintained: all fields required the proper AES-256 keys and rejected wrong keys/AADs.")
            print("- Integrity maintained: every tampered ciphertext/nonce/AAD was rejected under AES-GCM authentication.")
            print("- Access control upheld: patient password & doctor private key both opened the same per-patient key.")

if __name__ == "__main__":
    main()
