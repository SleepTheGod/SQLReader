import os
import base64
import hashlib
from flask import Flask, request, render_template, redirect, url_for, flash
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from secrets import token_bytes

app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['UPLOAD_FOLDER'] = 'uploads/'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

PASSWORD = b'strongpassword'
SALT = os.urandom(16)  # Store salt securely

# Key derivation function
def derive_key(password, salt, iterations=100000):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(password)

# Encryption and decryption functions
def encrypt_string(plaintext, key):
    iv = token_bytes(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padding_len = 16 - len(plaintext) % 16
    padded_plaintext = plaintext + chr(padding_len) * padding_len
    ciphertext = encryptor.update(padded_plaintext.encode()) + encryptor.finalize()
    hmac = HMAC(key, hashes.SHA256(), backend=default_backend())
    hmac.update(ciphertext)
    signature = hmac.finalize()
    return base64.b64encode(iv + ciphertext + signature).decode()

def decrypt_string(encrypted_data, key):
    data = base64.b64decode(encrypted_data)
    iv = data[:16]
    ciphertext = data[16:-32]
    signature = data[-32:]
    hmac = HMAC(key, hashes.SHA256(), backend=default_backend())
    hmac.update(ciphertext)
    try:
        hmac.verify(signature)
    except InvalidSignature:
        raise ValueError("Integrity check failed!")
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    padding_len = padded_plaintext[-1]
    return padded_plaintext[:-padding_len].decode()

ENCRYPTED_STRINGS = [
    encrypt_string("example1", derive_key(PASSWORD, SALT)),
    encrypt_string("example2", derive_key(PASSWORD, SALT)),
    encrypt_string("example3", derive_key(PASSWORD, SALT)),
    encrypt_string("example4", derive_key(PASSWORD, SALT))
]

# Function to read and process the SQL file
def process_sql_file(file_path, key):
    matches = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            for line in file:
                for encrypted_str in ENCRYPTED_STRINGS:
                    decrypted_str = decrypt_string(encrypted_str, key)
                    if decrypted_str in line:
                        matches.append(f"Found '{decrypted_str}' in: {line.strip()}")
    except Exception as e:
        flash(f"Error processing file: {str(e)}", 'error')
    return matches

# Function to convert SQL file content to HTML
def convert_sql_to_html(file_path):
    html_content = '<html><body><h2>SQL File Content</h2><pre>'
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            html_content += file.read().replace('<', '&lt;').replace('>', '&gt;')
    except Exception as e:
        flash(f"Error reading SQL file: {str(e)}", 'error')
    html_content += '</pre></body></html>'
    return html_content

# Home page for file upload
@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part', 'error')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file', 'error')
            return redirect(request.url)
        if file and file.filename.endswith('.sql'):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            key = derive_key(PASSWORD, SALT)
            results = process_sql_file(file_path, key)
            html_content = convert_sql_to_html(file_path)
            os.remove(file_path)  # Clean up after processing
            flash('File processed successfully!', 'success')
            return render_template('uploads.html', results=results, html_content=html_content)
        else:
            flash('Invalid file type. Please upload a .sql file.', 'error')
            return redirect(request.url)
    return render_template('uploads.html', results=None, html_content=None)

if __name__ == '__main__':
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    app.run(debug=True)
