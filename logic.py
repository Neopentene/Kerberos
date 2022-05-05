import secrets

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

from database import DatabaseManager as Manager
from database import Errors as DBError


class RSAError(Exception):
    pass


def generate_random_salt(salt_bytes: int):
    return secrets.token_hex(salt_bytes // 2)


def generate_rsa_key_pairs(key_size: int):
    return RSA.generate(key_size, Random.new().read)


def decrypt_rsa_message(message: bytes, key: RSA.RsaKey):
    cipher = PKCS1_v1_5.new(key)
    decrypted_text = cipher.decrypt(message, RSAError, 0)
    return decrypted_text.decode("utf-8")


def create_new_user(username: str, password: str):
    try:
        manager = Manager()
    except DBError:
        return False

    salt = bcrypt.gensalt()
    hashed_password = hashlib.sha256(bcrypt.hashpw(password.encode("utf-8"), salt)).hexdigest()

    try:
        manager.create_new_user(username, hashed_password, salt.decode("utf-8"))
        manager.commit_close()
        return True
    except DBError:
        manager.commit_close()
        return False


def decrypt_client_info(data: str, server_session: str):
    data = jwt.decode(data, server_session, algorithms="HS256")
    nonce = unhexlify(data['data'][1])
    data = unhexlify(data['data'][0])
    aes = AES.new(server_session.encode("utf-8"), AES.MODE_CTR, nonce=nonce)
    data = aes.decrypt(data)
    data = json.loads(data)
    print(data)
    return data


def hexlify(data: bytes):
    return binascii.hexlify(data).decode("utf-8")


def unhexlify(data: bytes | str):
    return binascii.unhexlify(data)


def decrypt_tgt(tgt: str, nonce: bytes):
    try:
        manager = Manager()
    except DBError:
        return None

    tgs_key = manager.get_tgs_key()

    if tgs_key is None:
        tgs_key = Fernet.generate_key().decode("utf-8")
        if manager.update_tgs_key(tgs_key):
            manager.commit()
            return None
        else:
            manager.commit_close()
            return None

    tgs_key = hashlib.md5(tgs_key.encode("utf-8")).hexdigest()
    aes = AES.new(tgs_key.encode("utf-8"), AES.MODE_CTR, nonce=nonce)
    data = jwt.decode(aes.decrypt(unhexlify(tgt)).decode("utf-8"), tgs_key, algorithms="HS256")
    return data


def decrypt_ticket(ticket: str, nonce: bytes):
    try:
        manager = Manager()
    except DBError:
        return None

    server_key = manager.get_server_key()

    if server_key is None:
        server_key = Fernet.generate_key().decode("utf-8")
        if manager.update_server_key(server_key):
            manager.commit()
            return None
        else:
            manager.commit_close()
            return None

    server_key = hashlib.md5(server_key.encode("utf-8")).hexdigest()
    aes = AES.new(server_key.encode("utf-8"), AES.MODE_CTR, nonce=nonce)
    data = jwt.decode(aes.decrypt(unhexlify(ticket)).decode("utf-8"), server_key, algorithms="HS256")
    return data


def create_ticket(username: str, address: str):
    try:
        manager = Manager()
    except DBError:
        return None

    server_session = manager.get_server_session_key(username)
    server_key = manager.get_server_key()
    if server_session is None:
        session_key = hashlib.md5(Fernet.generate_key()).hexdigest()
        if manager.create_new_server_session(username, session_key):
            manager.commit()
            server_session = session_key
        else:
            manager.commit_close()
            return None

    if server_key is None:
        server_key = Fernet.generate_key().decode("utf-8")
        if manager.update_server_key(server_key):
            manager.commit()
        else:
            manager.commit_close()
            return None
    try:
        server_key = hashlib.md5(server_key.encode("utf-8")).hexdigest()
        tgt = {
            "username": username,
            "address": address,
            "time": time.time() * 1000,
            "session_key": server_session
        }
        aes = AES.new(server_key.encode("utf-8"), AES.MODE_CTR)
        encrypted_ticket = binascii.hexlify(aes.encrypt(jwt.encode(tgt, server_key, algorithm="HS256").encode("utf-8")))

        manager.commit_close()
        return [encrypted_ticket.decode("utf-8"), binascii.hexlify(aes.nonce).decode("utf-8")]
    except DBError:
        manager.commit_close()
        return None


def encrypt_timestamp(timestamp: str, server_session: str):
    aes = AES.new(server_session.encode("utf-8"), AES.MODE_CTR)
    encrypted_timestamp = aes.encrypt(timestamp.encode("utf-8"))

    return [binascii.hexlify(encrypted_timestamp).strip().decode("utf-8"),
            binascii.hexlify(aes.nonce).decode("utf-8")]
