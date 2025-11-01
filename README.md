# Health-Cryption
This README provides instructions on setting up and running the Health-Cryption App

## 1) Pre-installations needed in your system
Install the following softwares and verify if they are properly installed in your system.

- Install [Python 3.11.7](https://www.python.org/downloads/release/python-3117/) 

- Install [Git](https://git-scm.com/downloads) 

## 2) Clone the git repository
Run the following commands in your command prompt
```
git clone https://github.com/RaiyanJahangir/Health-Cryption.git
```

## 3) Go to the root directory of the project
```
cd Dataset-Recommender
```

## 4) Create a directory to store the data
```
mkdir data
```

## 5) Download and prepare the dataset

- Download the Vindr-Mammo dataset from [Kaggle](https://www.kaggle.com/datasets/shantanughosh/vindr-mammogram-dataset-dicom-to-png).
- Download the metadata.csv from [here](https://physionet.org/content/vindr-mammo/1.0.0/).
- Store the dataset in the following way inside the project directory:

Health-Cryption/
├─ data/
│  ├─ images_png/...
│  ├─ metadata.csv
│  ├─ breast-level_annotations.csv
│  └─ finding_annotations.csv 
│  
├─ Other Python Codes
├─ .gitignore
├─ requirements.txt
└─ README.md  

## 6) Create a virtual environment (myenv)
You may rename the virtual environment as anything you like.

For Windows
```
py -3.11 -m venv myenv  
```

For Linux
```
python3.11 -m venv myenv 
```

## 7) Activate the virtual environment 

For Windows
```
myenv/Scripts/activate
```

For Linux
```
source myenv/bin/activate
```

## 8) Install all the necessary packages and libraries
```
pip install -r requirements.txt
```

## 9) Prepare the SQLite database
For Windows
```
python init_db.py
```

For Linux
```
python3 init_db.py
```

## 10) Run the Main App and test manually
For Windows
```
python main.py
```

For Linux
```
python3 main.py
```
Open the SQLite database and check if the information inserted is encrypted or not.

## 11) For automatically inserting a large amount of data into the database
For Windows
```
python auto_patient_register.py
```

For Linux
```
python3 auto_patient_register.py
```

## 12) Check if the text and image data are properly decrypted
For Windows
```
python doctor_check_patient.py
```

For Linux
```
python3 doctor_check_patient.py
```

## 13) Check if the system maintains Confidentiality and Integrity
For Windows
```
python security_test.py
```

For Linux
```
python3 security_test.py
```

## 14) Deactivate the virtual environment and wrap up
```
deactivate
```
