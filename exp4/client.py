import string
import random
import hashlib
import requests
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


def register(username, password):
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    response = requests.post("http://localhost:5000/register",
                             json={"username": username, "password_hash": password_hash})
    return response.json()


def authenticate(username, password):
    auth_code = ''.join(random.choices(
        string.ascii_letters + string.digits, k=8))
    print("Auth code:", auth_code)
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    hash2 = hashlib.sha256((password_hash + auth_code).encode()).hexdigest()
    response = requests.post("http://localhost:5000/authenticate",
                             json={"username": username, "hash2": hash2, "auth_code": auth_code})
    if response.status_code == 200:
        encrypted_auth_code = response.json()['encrypted_auth_code']
        decrypted_auth_code = decrypt(encrypted_auth_code, password_hash[:32])
        with open("auth_code.txt", "w") as f:
            f.write(decrypted_auth_code)
    return response.json()



def main():
    while True:
        action = input("Enter 'r(egister)' or 'a(uthenticate)': ").lower()
        username = input("Enter your username: ")
        password = input("Enter your password: ")
        if action == "r":
            result = register(username, password)
        elif action == "a":
            result = authenticate(username, password)
        else:
            print("Invalid action")
            continue
        print(result)


if __name__ == '__main__':
    main()
