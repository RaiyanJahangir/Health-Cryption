#!/usr/bin/env python3
"""
Bulk auto-registration of patients from a folder tree.

- Scans: data/images_png/<study_id>/<four_pngs>
- Looks up:
    data/breast-level-annotations.csv   -> breast_birads, breast_density (by study_id)
    data/finding_annotations.csv        -> finding_categories (by study_id)
    data/metadata.csv                   -> "SOP Instance UID" == filename (stem) -> Patient's Age, Image Laterality, View Position
- Creates a patient per subfolder (if not already present) with:
    user_id = patient{counter}, password = pass{counter}   (counter starts at 1 and increments per new patient)
- Encrypts and stores age/birads/density/findings, and all images with correct laterality & view (L/R, CC/MLO)
- Auto-grants all doctors by sealing the patient key to each doctor's public key
- Logs created credentials to data/auto_patient_credentials.csv

Run:
    python auto_patient_register.py
"""

import os
import re
import sys
from pathlib import Path
from typing import Dict, Optional, Tuple

import pandas as pd
from passlib.hash import argon2
from sqlalchemy.orm import Session
from sqlalchemy import func

from db import SessionLocal
from models import Patient, Doctor, PatientDoctorAccess
from crypto import (
    scrypt_kdf, aesgcm_encrypt, random_key32,
    sealed_box_encrypt,
)

# ---------- CONFIG PATHS ----------
ROOT = Path(".").resolve()
IMG_ROOT = ROOT / "data" / "images_png"
BREAST_CSV = ROOT / "data" / "breast-level_annotations.csv"
FINDING_CSV = ROOT / "data" / "finding_annotations.csv"
META_CSV = ROOT / "data" / "metadata.csv"
CRED_LOG = ROOT / "data" / "auto_patient_credentials.csv"

# ---------- HELPERS ----------

USER_RE = re.compile(r"^patient(\d+)$")

def get_next_patient_counter(db: Session) -> int:
    """
    Scan existing patient user_ids of the form 'patientN' and return max(N)+1, or 1 if none.
    """
    # Pull all user_ids to avoid dialect-dependent regex support
    rows = db.query(Patient.user_id).all()
    max_n = 0
    for (uid,) in rows:
        if not uid:
            continue
        m = USER_RE.match(uid)
        if m:
            try:
                n = int(m.group(1))
                if n > max_n:
                    max_n = n
            except ValueError:
                pass
    return max_n + 1

def next_free_user_id(db: Session, start_n: int) -> tuple[str, int]:
    """
    Starting from start_n, find the first 'patient{n}' not used. Return (user_id, n).
    """
    n = start_n
    while True:
        uid = f"patient{n}"
        exists = db.query(Patient).filter_by(user_id=uid).first()
        if not exists:
            return uid, n
        n += 1
        
        
        
def normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    df.columns = [c.strip() for c in df.columns]
    return df

def read_csv_safe(path: Path) -> pd.DataFrame:
    if not path.exists():
        raise FileNotFoundError(f"CSV not found: {path}")
    # dtype=str to avoid numeric parsing issues; keep whitespace, then strip columns
    df = pd.read_csv(path, dtype=str, keep_default_na=False)
    return normalize_columns(df)

def extract_birads_num(birads_str: str) -> Optional[str]:
    # find a digit 1..5
    if not birads_str:
        return None
    m = re.search(r"[1-5]", birads_str)
    return m.group(0) if m else None

def extract_density_letter(density_str: str) -> Optional[str]:
    # take the last A-D letter
    if not density_str:
        return None
    m = re.findall(r"[A-D]", density_str.upper())
    return m[-1] if m else None

def extract_age_from_meta(age_str: str) -> Optional[str]:
    # examples: "053Y" -> "53"
    if not age_str:
        return None
    m = re.search(r"(\d+)", age_str)
    return m.group(1).lstrip("0") or "0" if m else None

def get_slot_from_tags(laterality: str, view: str) -> Optional[str]:
    """
    laterality: 'L' or 'R'
    view: 'CC' or 'MLO'
    returns slot key: 'a','b','c','d' for L-CC, L-MLO, R-CC, R-MLO
    """
    L = (laterality or "").upper().strip()
    V = (view or "").upper().strip()
    if L == "L" and V == "CC":
        return "a"
    if L == "L" and V == "MLO":
        return "b"
    if L == "R" and V == "CC":
        return "c"
    if L == "R" and V == "MLO":
        return "d"
    return None

def set_image_on_patient(p: Patient, slot: str, nonce: bytes, ct: bytes, mime: str):
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

def encrypt_field(patient_key: bytes, text: Optional[str], aad: str) -> Tuple[Optional[bytes], Optional[bytes]]:
    if text is None or text == "":
        return None, None
    nonce, ct = aesgcm_encrypt(patient_key, text.encode("utf-8"), aad=aad.encode())
    return nonce, ct

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

def load_annotation_indexes():
    # breast-level annotations: index by study_id
    breast_df = read_csv_safe(BREAST_CSV)
    if "study_id" not in breast_df.columns:
        raise KeyError(f"'study_id' column missing in {BREAST_CSV}")
    breast_df["study_id"] = breast_df["study_id"].astype(str).str.strip()
    breast_idx = breast_df.set_index("study_id")

    # finding annotations: index by study_id
    finding_df = read_csv_safe(FINDING_CSV)
    if "study_id" not in finding_df.columns:
        raise KeyError(f"'study_id' column missing in {FINDING_CSV}")
    finding_df["study_id"] = finding_df["study_id"].astype(str).str.strip()
    finding_idx = finding_df.set_index("study_id")

    # metadata: strip column names; make a dict keyed by SOP Instance UID (strip ext from filenames)
    meta_df = read_csv_safe(META_CSV)
    # Normalize critical column names (strip whitespace)
    # Some datasets have trailing space after 'Image Laterality '
    colmap = {c: c.strip() for c in meta_df.columns}
    meta_df.rename(columns=colmap, inplace=True)

    required = ["SOP Instance UID", "Patient's Age", "Image Laterality", "View Position"]
    for col in required:
        if col not in meta_df.columns:
            # try to fix common trailing-space issue
            candidates = [c for c in meta_df.columns if c.replace(" ", "") == col.replace(" ", "")]
            if candidates:
                meta_df.rename(columns={candidates[0]: col}, inplace=True)
            else:
                raise KeyError(f"Column '{col}' missing in {META_CSV}")

    meta_df["SOP Instance UID"] = meta_df["SOP Instance UID"].astype(str).str.strip()
    meta_idx = meta_df.set_index("SOP Instance UID")

    return breast_idx, finding_idx, meta_idx

def fetch_meta_for_filename(meta_idx: pd.DataFrame, filename: str) -> Optional[Dict[str, str]]:
    """
    filename: like '12345.png' => lookup by '12345'
    returns dict with Patient's Age, Image Laterality, View Position
    """
    stem = Path(filename).stem
    if stem in meta_idx.index:
        row = meta_idx.loc[stem]
        if isinstance(row, pd.DataFrame):
            # if duplicates, take the first
            row = row.iloc[0]
        return {
            "age": extract_age_from_meta(str(row.get("Patient's Age", "")).strip()),
            "laterality": str(row.get("Image Laterality", "")).strip(),
            "view": str(row.get("View Position", "")).strip(),
        }
    return None

def main():
    print("=== Auto Patient Register ===")
    print(f"Scanning: {IMG_ROOT}")

    if not IMG_ROOT.exists():
        print(f"Folder not found: {IMG_ROOT}")
        sys.exit(1)

    try:
        breast_idx, finding_idx, meta_idx = load_annotation_indexes()
    except Exception as e:
        print(f"Failed loading CSV indexes: {e}")
        sys.exit(1)

    created_creds = []  # list of (patient_id, user_id, password)
    with SessionLocal() as db_probe:
        counter = get_next_patient_counter(db_probe)


    with SessionLocal() as db:
        # Iterate subfolders (study_id)
        for study_dir in sorted(IMG_ROOT.iterdir()):
            if not study_dir.is_dir():
                continue
            study_id = study_dir.name.strip()
            # Skip if patient already exists
            if db.query(Patient).filter_by(patient_id=study_id).first():
                print(f"[SKIP] patient_id already exists: {study_id}")
                continue

            # Gather the 4 PNGs (or whatever is present)
            pngs = sorted([p for p in study_dir.iterdir() if p.is_file() and p.suffix.lower() == ".png"])
            if not pngs:
                print(f"[WARN] no PNGs found in {study_id}, skipping.")
                continue

            # Pull annotations by study_id
            birads = density = findings = None
            if study_id in breast_idx.index:
                brow = breast_idx.loc[study_id]
                if isinstance(brow, pd.DataFrame):
                    brow = brow.iloc[0]
                birads = extract_birads_num(str(brow.get("breast_birads", "")).strip())
                density = extract_density_letter(str(brow.get("breast_density", "")).strip())
            else:
                print(f"[WARN] study_id not in breast-level-annotations: {study_id}")

            if study_id in finding_idx.index:
                frow = finding_idx.loc[study_id]
                if isinstance(frow, pd.DataFrame):
                    frow = frow.iloc[0]
                findings = str(frow.get("finding_categories", "")).strip() or None
            else:
                # Optional; some datasets might not have findings for all studies
                findings = None

            # Create patient account with generated creds
            user_id, counter = next_free_user_id(db, counter)
            password = f"pass{counter}"

            patient_key = random_key32()
            salt_p = os.urandom(16)
            k_p = scrypt_kdf(password, salt_p, 32)
            nonce_p, ct_p = aesgcm_encrypt(k_p, patient_key)

            p_row = Patient(
                patient_id=study_id,
                user_id=user_id,
                password_hash=argon2.hash(password),
                role="patient",
                enc_data_key_for_patient=ct_p,
                enc_data_key_for_patient_nonce=nonce_p,
                enc_data_key_for_patient_salt=salt_p,
            )
            db.add(p_row)
            try:
                db.commit()  # obtain p_row.id
            except Exception:
                db.rollback()
                # Extremely unlikely race/collision—try the next free id once more
                user_id, counter = next_free_user_id(db, counter + 1)
                password = f"pass{counter}"
                p_row.user_id = user_id
                p_row.password_hash = argon2.hash(password)
                db.add(p_row)
                db.commit()

            # Fill textual fields (age will be taken from image metadata; if inconsistent across 4 images, first non-null wins)
            decided_age = None

            # Process images: read bytes, map slot via metadata laterality/view, encrypt and set
            slots_set = set()
            for img_path in pngs:
                meta = fetch_meta_for_filename(meta_idx, img_path.name)
                if not meta:
                    print(f"[WARN] metadata not found for file: {img_path.name} (study {study_id}); skipping this image.")
                    continue
                if decided_age is None and meta.get("age"):
                    decided_age = meta["age"]

                slot = get_slot_from_tags(meta.get("laterality"), meta.get("view"))
                if not slot:
                    print(f"[WARN] could not determine slot (L/R, CC/MLO) for {img_path.name}; skipping.")
                    continue

                try:
                    blob = img_path.read_bytes()
                except Exception as e:
                    print(f"[WARN] cannot read {img_path}: {e}")
                    continue

                # Encrypt with AAD binding e.g., "img:L-CC"
                aad_map = {"a": "img:L-CC", "b": "img:L-MLO", "c": "img:R-CC", "d": "img:R-MLO"}
                nonce_img, ct_img = aesgcm_encrypt(patient_key, blob, aad=aad_map[slot].encode())
                set_image_on_patient(p_row, slot, nonce_img, ct_img, mime="image/png")
                slots_set.add(slot)

            # Encrypt text fields using patient_key
            if decided_age:
                p_row.age_nonce, p_row.age_ct = encrypt_field(patient_key, decided_age, "age")
            if birads:
                p_row.birads_nonce, p_row.birads_ct = encrypt_field(patient_key, birads, "birads")
            if density:
                p_row.breast_density_nonce, p_row.breast_density_ct = encrypt_field(patient_key, density, "breast_density")
            if findings:
                p_row.findings_nonce, p_row.findings_ct = encrypt_field(patient_key, findings, "findings")

            db.commit()

            # Auto-grant to all doctors
            grant_patient_to_all_doctors(db, p_row, patient_key)

            print(f"[OK] Created patient: patient_id={study_id} user_id={user_id} images_set={sorted(slots_set)}")
            created_creds.append((study_id, user_id, password))
            counter += 1  # increment ONLY when we actually created a new patient

    # Save credentials log
    if created_creds:
        CRED_LOG.parent.mkdir(parents=True, exist_ok=True)
        df_log = pd.DataFrame(created_creds, columns=["patient_id", "user_id", "password"])
        if CRED_LOG.exists():
            # append without headers
            df_log.to_csv(CRED_LOG, mode="a", index=False, header=False)
        else:
            df_log.to_csv(CRED_LOG, index=False)
        print(f"\nWrote credentials for {len(created_creds)} new patients -> {CRED_LOG}")
    else:
        print("\nNo new patients created.")

if __name__ == "__main__":
    main()
