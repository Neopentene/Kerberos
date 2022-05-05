import pyodbc

import database_information as db

driver = db.driver
server_name = db.server_name
server_database = db.db_name
server_username = db.username
server_password = db.password


class DatabaseManager:
    def __init__(self):
        self.db = pyodbc.connect(
            'DRIVER=' + driver +
            ';SERVER=tcp:' + server_name +
            ';PORT=1433;DATABASE=' + server_database +
            ';UID=' + server_username +
            ';PWD=' + server_password
        )

    def check_connection(self):
        if self.db is not None:
            return True
        else:
            return False

    def get_tgs_key(self):
        if self.check_connection():
            query = "SELECT key_value FROM dbo.server_keys WHERE key_id = 'TGS' AND valid_till >= GETDATE()"
            with self.db.cursor() as cursor:
                try:
                    cursor.execute(query)
                    value = cursor.fetchone()
                    key = value[0] if value is not None else None
                    return key
                except Errors:

                    return None
        return None

    def update_tgs_key(self, key: str):
        if self.check_connection():
            check_query = "SELECT key_value FROM dbo.server_keys WHERE key_id = ?"
            server_key = ""
            with self.db.cursor() as cursor:
                try:
                    cursor.execute(check_query, ['TGS'])
                    value = cursor.fetchone()
                    server_key = value[0] if value is not None else None
                except Errors:
                    server_key = ""

            query = "EXEC dbo.update_key @p_key_id = 'TGS', @p_key_value = ?"
            if server_key is None or server_key == "":
                query = "EXEC dbo.add_new_key @p_key_id = 'TGS', @p_key_value = ?"

            with self.db.cursor() as cursor:
                try:
                    cursor.execute(query, [key])
                    return True
                except Errors:
                    return False
        return False

    def get_server_key(self):
        if self.check_connection():
            query = "SELECT key_value FROM dbo.server_keys WHERE key_id = 'Server' AND valid_till >= GETDATE()"
            with self.db.cursor() as cursor:
                try:
                    cursor.execute(query)
                    value = cursor.fetchone()
                    if value is not None:
                        return value[0]
                    else:
                        return None
                except Errors:
                    return None
        return None

    def update_server_key(self, key: str):
        if self.check_connection():
            check_query = "SELECT key_value FROM dbo.server_keys WHERE key_id = ?"
            server_key = ""
            with self.db.cursor() as cursor:
                try:
                    cursor.execute(check_query, ['Server'])
                    value = cursor.fetchone()
                    if value is not None:
                        server_key = value[0]
                    else:
                        server_key = None
                except Errors:
                    server_key = ""

            query = "EXEC dbo.update_key @p_key_id = 'Server', @p_key_value = ?"
            if server_key is None or server_key == "":
                query = "EXEC dbo.add_new_key @p_key_id = 'Server', @p_key_value = ?"

            with self.db.cursor() as cursor:
                try:
                    cursor.execute(query, [key])
                    return True
                except Errors:
                    return False
        return False

    def create_new_user(self, username: str, password: str):
        if self.check_connection():
            query = "INSERT INTO dbo.users VALUES (?, ?)"
            with self.db.cursor() as cursor:
                try:
                    cursor.execute(query, [username, password])
                    return True
                except Errors:
                    return False
        return False

    def get_server_session_key(self, username: str):
        if self.check_connection():
            query = "SELECT session_key FROM dbo.server_sessions WHERE username = ? AND valid_till >= GETDATE()"
            with self.db.cursor() as cursor:
                try:
                    cursor.execute(query, [username])
                    value = cursor.fetchone()
                    if value is not None:
                        return value[0]
                    else:
                        return None
                except Errors:
                    return None
        return None

    def _delete_old_session(self, username: str):
        if self.check_connection():
            query = "DELETE FROM dbo.server_sessions WHERE username = ?"
            with self.db.cursor() as cursor:
                try:
                    cursor.execute(query, [username])
                    return True
                except Errors:
                    return False
        return False

    def create_new_server_session(self, username: str, session_key: str):
        if self.check_connection():
            self._delete_old_session(username)
            self.commit()
            query = "INSERT INTO dbo.server_sessions VALUES (?, ?, GETDATE(), DATEADD(DAY, 1, GETDATE()))"
            with self.db.cursor() as cursor:
                try:
                    cursor.execute(query, [username, session_key])
                    return True
                except Errors:
                    return False
        return None

    def commit(self):
        if self.check_connection():
            try:
                self.db.commit()
                return True
            except Errors:
                return False
        return False

    def commit_close(self):
        if self.check_connection():
            try:
                self.db.commit()
                self.db.close()
                return True
            except Errors:
                return False
        return False


class Errors(pyodbc.Error):
    pass
