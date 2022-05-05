import pyodbc
import bcrypt
import hashlib

import database_information as db

driver = db.driver
server = db.server_name
database = db.db_name
username = db.username
password = db.password

db = pyodbc.connect(
    'DRIVER=' + driver + ';SERVER=tcp:' + server + ';PORT=1433;DATABASE=' + database + ';UID=' + username + ';PWD=' + password)

query = "SELECT user_password, user_salt FROM dbo.users WHERE username = ?"

# salt = b'$2b$12$oDcQLta34ZGI9fUrAKuxke'
# hashed_password = bcrypt.hashpw("Root@123".encode("utf-8"), salt)
# print(hashed_password.decode("utf-8"), salt.decode("utf-8"), hashlib.sha256(hashed_password).hexdigest(), sep="\n")

with db.cursor() as cursor:
    cursor.execute(query, ['root'])
    value = cursor.fetchone()
    print(value[0], value[1].encode("utf-8"))

db.close()
