import secrets

import binascii
import hashlib
import json
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


def decrypt_client_info(data: str, tgs_session: str):
    data = jwt.decode(data, tgs_session, algorithms="HS256")
    nonce = unhexlify(data['data'][1])
    data = unhexlify(data['data'][0])
    aes = AES.new(tgs_session.encode("utf-8"), AES.MODE_CTR, nonce=nonce)
    data = aes.decrypt(data)
    data = json.loads(data)
    print(data)
    return data


def check_user(username: str, keys: RSA.RsaKey):
    username = decrypt_rsa_message(unhexlify(username), keys)
    print(username)
    manager = Manager()
    status = manager.check_user(username)
    manager.commit_close()
    if status is not None:
        return username, status
    else:
        var = None, False
        return var


def hexlify(data: bytes):
    return binascii.hexlify(data).decode("utf-8")


def unhexlify(data: bytes | str):
    return binascii.unhexlify(data)


def encrypt_server_session_key(username: str, tgs_session: str):
    try:
        manager = Manager()
    except DBError:
        return None

    try:

        aes = AES.new(tgs_session.encode("utf-8"), AES.MODE_CBC)
        server_session = manager.get_server_session_key(username)

        if server_session is None:
            session_key = hashlib.md5(Fernet.generate_key()).hexdigest()
            if manager.create_new_session(username, session_key):
                manager.commit()
                server_session = session_key
            else:
                manager.commit_close()
                return None

        encrypted_session_key = aes.encrypt(server_session.encode("utf-8"))
        manager.commit_close()

        return [binascii.hexlify(encrypted_session_key).strip().decode("utf-8"),
                binascii.hexlify(aes.iv).decode("utf-8")]
    except DBError:
        manager.commit_close()
        return None


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
        ticket = {
            "username": username,
            "address": address,
            "time": time.time() * 1000,
            "session_key": server_session
        }
        aes = AES.new(server_key.encode("utf-8"), AES.MODE_CTR)
        encrypted_ticket = binascii.hexlify(aes.encrypt(jwt.encode(ticket, server_key, algorithm="HS256").encode("utf-8")))

        manager.commit_close()
        return [encrypted_ticket.decode("utf-8"), binascii.hexlify(aes.nonce).decode("utf-8")]
    except DBError:
        manager.commit_close()
        return None
