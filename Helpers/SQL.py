from pyodbc import Connection

class SQLHelper:
    def __init__(self, conn: Connection):
        self.conn = conn

    def execute_sql_without_output(self, sql):
        cursor = self.conn.cursor()
        cursor.execute(sql)
        cursor.close()

    def execute_sql_with_output(self, sql):
        cursor = self.conn.cursor()
        cursor.execute(sql)
        rows = cursor.fetchall()
        cursor.close()
        return rows

    def get_person_info(self, person_id):
        sql = f"EXEC dbo.GetPersonInfo {person_id}"
        rows = self.execute_sql_with_output(sql)
        return rows

    def add_person_to_contacts(self, person_id, contact_email):
        sql = f"EXEC dbo.AddPersonToContacts {person_id}, '{contact_email}'"
        self.execute_sql_without_output(sql)

    def add_user(self, email, passwordhash, publickey):
        sql = f"EXEC dbo.AddUser '{email}', '{passwordhash}', '{publickey}'"
        self.execute_sql_without_output(sql)

    def get_messages(self, sender_id, receiver_id, page):
        sql = f"EXEC dbo.GetMessagesBySenderAndReceiver {sender_id}, {receiver_id}, {page}"
        rows = self.execute_sql_with_output(sql)
        return rows

    def get_last_message(self, sender_id, receiver_id):
        sql = f"EXEC dbo.GetLastMessageInConversation {sender_id}, {receiver_id}"
        rows = self.execute_sql_with_output(sql)
        return rows

    def get_public_key_by_username(self, email):
        sql = f"EXEC dbo.GetPublicKeyByUsername '{email}'"
        rows = self.execute_sql_with_output(sql)
        if rows:
            return rows[0][0]
        return None

    def save_message(self, sender_id, receiver_id, message):
        sql = f"EXEC dbo.SaveMessage {sender_id}, {receiver_id}, '{message}'"
        self.execute_sql_without_output(sql)

    def get_password_by_email(self, email):
        sql = f"SELECT passwordhash FROM Kullanicilar WHERE email = '{email}'"
        rows = self.execute_sql_with_output(sql)

        if rows:
            return rows[0][0]

        return None

    def remove_contact(self, user_id, contact_id):
        sql = f"EXEC dbo.RemoveContact {user_id}, {contact_id}"
        self.execute_sql_without_output(sql)

    def get_contacts(self, user_id):
        sql = f"EXEC dbo.GetContacts {user_id}"
        rows = self.execute_sql_with_output(sql)
        return rows

    def get_user_id_by_email(self, email):
        sql = f"SELECT id FROM Kullanicilar WHERE email = '{email}'"
        rows = self.execute_sql_with_output(sql)
        return rows[0][0]

