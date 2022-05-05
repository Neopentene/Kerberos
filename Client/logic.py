import base64
import binascii
import hashlib
import json
import bcrypt
import jwt
import time

from Crypto import Random
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from cryptography.fernet import Fernet


def hexlify(data: bytes):
    return binascii.hexlify(data).decode("utf-8")


def unhexlify(data: bytes | str):
    return binascii.unhexlify(data)


def encrypt_rsa_message(message: str, key: str):
    public_key = RSA.importKey(key)
    cipher = PKCS1_v1_5.new(public_key)
    cipher_text = cipher.encrypt(message.encode())
    return hexlify(cipher_text)


def encrypt_timestamp_client(username: str, tgs_session: str):
    timestamp = int(time.time() * 1000)
    payload = {
        "username": username,
        "time": timestamp
    }

    payload = json.dumps(payload)

    aes = AES.new(tgs_session.encode("utf-8"), AES.MODE_CTR)
    nonce = hexlify(aes.nonce)
    data = hexlify(aes.encrypt(payload.encode("utf-8")))
    return jwt.encode({"data": [data, nonce]}, tgs_session, algorithm="HS256"), timestamp


def decrypt_server_session(tgs_session: str, encrypted_server_session: str, iv: bytes):
    encrypted_server_session = unhexlify(encrypted_server_session)
    aes = AES.new(tgs_session.encode("utf-8"), AES.MODE_CBC, iv=iv)
    decrypt_server_session_instance = aes.decrypt(encrypted_server_session).decode("utf-8")
    return decrypt_server_session_instance


def decrypt_server_timestamp(server_session: str, timestamp: str, nonce: bytes):
    encrypted_server_session = unhexlify(timestamp)
    aes = AES.new(server_session.encode("utf-8"), AES.MODE_CTR, nonce=nonce)
    timestamp = aes.decrypt(encrypted_server_session).decode("utf-8")
    return timestamp


def decrypt_session(password: str, encrypted_tgt_session: str, iv: str):
    encrypted_tgt_session = unhexlify(encrypted_tgt_session)
    aes = AES.new(password.encode("utf-8"), AES.MODE_CBC, unhexlify(iv))
    tgt_session = aes.decrypt(encrypted_tgt_session).decode("utf-8")
    print(tgt_session)
    return tgt_session


def generate_key_from_password(password: bytes, salt: bytes):
    password = bcrypt.hashpw(password, salt)
    password = hashlib.sha256(password).hexdigest()
    password = hashlib.md5(password.encode("utf-8")).hexdigest()
    print(password)
    return password


def generate_secret_key_session():
    return Fernet.generate_key().decode("utf-8")


def generate_rsa_key_pairs(key_size: int):
    return RSA.generate(key_size, Random.new().read)


def bytes_to_base64(byte_string: bytes):
    return base64.b64encode(byte_string).decode("utf-8")


def base64_to_bytes(base64_string: str):
    return base64.b64decode(base64_string)
