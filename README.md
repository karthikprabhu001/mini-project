---

# SecureVault - Secure Data Storage & Transmission using Cryptography

## Overview
SecureVault is a secure data storage and transmission system built using Python and Flask. It implements modern cryptographic techniques to protect sensitive user data during transmission and storage. The project ensures data confidentiality, integrity, and authenticity using encryption, secure transmission, and digital signatures.

---

## Features
- Secure Transmission of Data over HTTPS (TLS)
- AES Encryption for Secure Data Storage using Fernet
- RSA Digital Signature Generation & Verification
- Encrypted Storage of Messages & Signatures
- Secure Retrieval & Display of Stored Messages
- Flask Web Application for User Interaction
- SQLite Database for Note Storage
- Password Protected Access (optional bcrypt hashing)

---

## Project Architecture

```
Client (User) → HTTPS → Flask Server
      |
      |--- Encrypts & Signs Data
      |
      → Stores Encrypted Data & Signature in Secure File
```

---

## Technologies Used
| Technology         | Purpose                                  |
|-------------------|------------------------------------------|
| Python            | Backend Programming                      |
| Flask             | Web Framework                             |
| Cryptography      | AES Encryption (Fernet) & RSA Signing     |
| SQLite            | Database for Storing Notes                |
| SSL/TLS (ssl)     | Secure HTTPS Communication                |
| HTML & CSS        | Frontend UI                               |

---

## Installation & Setup

1. Clone the Repository:
```
git clone <your-repo-link>
cd SecureVault
```

2. Install Required Python Libraries:
```
pip install -r requirements.txt
```

3. Generate RSA Keys:
```
python generate_keys.py
```

4. Generate Fernet Key:
```
python generate_fernet_key.py
```

5. Run the Flask App with SSL:
```
python app.py
```

6. Open Browser:
```
https://localhost:5000/
```

---

## Folder Structure
```
SecureVault/
│
├── app.py                  → Main Flask Application
├── templates/              → HTML Templates
├── static/                 → CSS & Other Static Files
├── storage.key             → Fernet Key
├── private.pem            → RSA Private Key
├── public.pem             → RSA Public Key
├── secure_storage.txt     → Encrypted Messages
├── requirements.txt        → Python Dependencies
├── generate_keys.py        → Generate RSA Keys
├── generate_fernet_key.py  → Generate AES Key
└── README.md               → Project Documentation
```

---

## Usage
1. Enter a secure message in the web interface.
2. Message will be:
   - Encrypted using AES (Fernet)
   - Signed using RSA Digital Signature
   - Stored securely in `secure_storage.txt`
3. View Stored Messages with Decryption and Signature Display.

---

## Results
- Secure Transmission of Messages over HTTPS.
- AES Encrypted Storage of Data and Digital Signatures.
- Successful Signing & Verification using RSA.
- User-friendly Web Interface for Sending & Retrieving Data.

---

## References
- Flask Documentation → https://flask.palletsprojects.com/
- Python Cryptography Library → https://cryptography.io/en/latest/
- RSA & Fernet Encryption → https://cryptography.io/en/latest/fernet/
- SSL/TLS in Python → https://docs.python.org/3/library/ssl.html

---

## Developed By
> Name: *Karthik Prabhu*  
> College: *NMAMIT*  
> Project Title: *SecureVault - Secure Data Storage & Transmission using Cryptography*

---
