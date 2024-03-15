from __future__ import annotations
import uuid


class User:
    """
    User model for a user in the database.
    """

    def __init__(self, user_id: str, username: str, email: str, password: str):
        self.user_id = user_id
        self.username = username
        self.email = email
        self.password = password

    @staticmethod
    def insert_user_to_db(user_id: uuid.uuid4, username: str, email: str, hashed_password: str, db_conn) -> User:
        """
        This method inserts a user into the database and returns a User object.
        Note: The password passed as an argument should be a hashed password and not a plaintext
        password.
        """
        cursor = db_conn.cursor()
        query = "INSERT INTO app_user VALUES(%s, %s, %s, %s)"
        cursor.execute(query, (user_id.hex, username, email, hashed_password))
        cursor.close()
        db_conn.commit()
        return User(
            user_id=user_id.hex,
            username=username,
            email=email,
            password=hashed_password
        )
