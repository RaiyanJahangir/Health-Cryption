from db import engine, Base, plain_engine, PlainBase
from models import Patient, Doctor, PatientDoctorAccess, PlainPatient, PlainDoctor
from config import DB_URL, PLAIN_DB_URL

def main():
    print(f"Initializing encrypted database at: {DB_URL}")
    Base.metadata.create_all(engine)
    print("Encrypted tables created: patients, doctors, patient_doctor_access")

    print(f"Initializing plaintext database at: {PLAIN_DB_URL}")
    PlainBase.metadata.create_all(plain_engine)
    print("Plaintext tables created: plain_patients, plain_doctors")

if __name__ == "__main__":
    main()
