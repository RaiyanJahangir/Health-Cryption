from db import engine, Base
from models import Patient, Doctor, PatientDoctorAccess
from config import DB_URL

def main():
    print(f"Initializing database at: {DB_URL}")
    Base.metadata.create_all(engine)
    print("Tables created: patients, doctors, patient_doctor_access")

if __name__ == "__main__":
    main()
