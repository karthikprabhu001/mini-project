from flask import Flask, render_template, request, redirect, url_for, flash
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
import sqlite3
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

DB_NAME = 'vault.db'
FERNET_KEY = Fernet.generate_key()
fernet = Fernet(FERNET_KEY)

PRIVATE_KEY_PATH = 'keys/private_key.pem'
PUBLIC_KEY_PATH = 'keys/public_key.pem'


# Initialize Database
def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT,
            encrypted_note TEXT,
            signature BLOB
        )
    ''')
    conn.commit()
    conn.close()


# RSA Key Generation
def generate_keys():
    if not os.path.exists('keys'):
        os.makedirs('keys')
    if not os.path.exists(PRIVATE_KEY_PATH):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()

        with open(PRIVATE_KEY_PATH, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

        with open(PUBLIC_KEY_PATH, 'wb') as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/add', methods=['GET', 'POST'])
def add_note():
    if request.method == 'POST':
        title = request.form['title']
        note = request.form['note']

        encrypted_note = fernet.encrypt(note.encode())

        with open(PRIVATE_KEY_PATH, 'rb') as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)

        signature = private_key.sign(
            encrypted_note,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("INSERT INTO notes (title, encrypted_note, signature) VALUES (?, ?, ?)",
                  (title, encrypted_note, signature))
        conn.commit()
        conn.close()

        flash('Note added securely!')
        return redirect(url_for('view_notes'))

    return render_template('add_note.html')


@app.route('/view')
def view_notes():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT id, title, encrypted_note, signature FROM notes")
    notes = c.fetchall()
    conn.close()

    decrypted_notes = []
    with open(PUBLIC_KEY_PATH, 'rb') as f:
        public_key = serialization.load_pem_public_key(f.read())

    for note in notes:
        id, title, encrypted_note, signature = note

        try:
            public_key.verify(
                signature,
                encrypted_note,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            decrypted_note = fernet.decrypt(encrypted_note).decode()
            verified = True
        except Exception:
            decrypted_note = "[Tampered or Invalid Signature]"
            verified = False

        decrypted_notes.append((id, title, decrypted_note, verified))

    return render_template('view_notes.html', notes=decrypted_notes)


if __name__ == '__main__':
    init_db()
    generate_keys()
    app.run(debug=True)
