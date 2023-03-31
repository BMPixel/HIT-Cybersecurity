from flask import Flask, request
import sqlite3
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64


def encrypt(plaintext, key):
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return base64.b64encode(cipher.iv + ciphertext).decode()


def decrypt(ciphertext, key):
    data = base64.b64decode(ciphertext)
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC,
                     iv=data[:AES.block_size])
    return unpad(cipher.decrypt(data[AES.block_size:]), AES.block_size).decode()



app = Flask(__name__)

def create_database():
    conn = sqlite3.connect("authentication.db")
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password_hash TEXT)")
    conn.commit()
    conn.close()


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data['username']
    password_hash = data['password_hash']
    conn = sqlite3.connect("authentication.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    existing_user = cursor.fetchone()

    if existing_user:
        cursor.execute(
            "UPDATE users SET password_hash = ? WHERE username = ?", (password_hash, username))
        conn.commit()
        message = "User password updated"
    else:
        cursor.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, password_hash))
        conn.commit()
        message = "User registered"

    conn.close()
    return {"result": "success", "message": message}, 201



@app.route('/authenticate', methods=['POST'])
def authenticate():
    data = request.get_json()
    username = data['username']
    client_hash2 = data['hash2']
    auth_code = data['auth_code']
    conn = sqlite3.connect("authentication.db")
    cursor = conn.cursor()
    cursor.execute(
        "SELECT password_hash FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    if result is None:
        return {"result": "failure", "message": "User not found"}, 404
    password_hash = result[0]
    server_hash2 = hashlib.sha256(
        (password_hash + auth_code).encode()).hexdigest()
    if server_hash2 == client_hash2:
        encrypted_auth_code = encrypt(auth_code, password_hash[:32])
        return {"result": "success", "encrypted_auth_code": encrypted_auth_code}
    return {"result": "failure", "message": "Authentication failed"}, 401

if __name__ == '__main__':
    create_database()
    app.run(debug=True, port=5000)