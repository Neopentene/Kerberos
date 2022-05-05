import secrets

import binascii
import hashlib
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


def check_user(username: str, keys: RSA.RsaKey):
    username = decrypt_rsa_message(unhexlify(username), keys)
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


def encrypt_tgs_session_key(username: str):
    try:
        manager = Manager()
    except DBError:
        return None

    try:
        password, salt = manager.get_user_password(username)
        password = hashlib.md5(password.encode("utf-8")).hexdigest()

        print(password)

        aes = AES.new(password.encode("utf-8"), AES.MODE_CBC)
        tgs_session = manager.get_tgs_session_key(username)

        if tgs_session is None:
            session_key = hashlib.md5(Fernet.generate_key()).hexdigest()
            if manager.create_new_tgs_session(username, session_key):
                manager.commit()
                tgs_session = session_key
            else:
                manager.commit_close()
                return None

        print(tgs_session)

        encrypted_session_key = aes.encrypt(tgs_session.encode("utf-8"))

        manager.commit_close()

        return [binascii.hexlify(encrypted_session_key).strip().decode("utf-8"),
                binascii.hexlify(aes.iv).decode("utf-8"), salt]
    except DBError:
        manager.commit_close()
        return None


def create_tgt(username: str, address: str):
    try:
        manager = Manager()
    except DBError:
        return None

    tgs_session = manager.get_tgs_session_key(username)
    tgs_key = manager.get_tgs_key()
    if tgs_session is None:
        session_key = hashlib.md5(Fernet.generate_key()).hexdigest()
        if manager.create_new_tgs_session(username, session_key):
            manager.commit()
            tgs_session = session_key
        else:
            manager.commit_close()
            return None

    if tgs_key is None:
        tgs_key = Fernet.generate_key().decode("utf-8")
        if manager.update_tgs_key(tgs_key):
            manager.commit()
        else:
            manager.commit_close()
            return None
    try:
        tgs_key = hashlib.md5(tgs_key.encode("utf-8")).hexdigest()
        tgt = {
            "username": username,
            "address": address,
            "time": int(time.time() * 1000),
            "session_key": tgs_session
        }
        aes = AES.new(tgs_key.encode("utf-8"), AES.MODE_CTR)
        encrypted_tgt = binascii.hexlify(aes.encrypt(jwt.encode(tgt, tgs_key, algorithm="HS256").encode("utf-8")))

        manager.commit_close()
        return [encrypted_tgt.decode("utf-8"), binascii.hexlify(aes.nonce).decode("utf-8")]
    except DBError:
        manager.commit_close()
        return None
