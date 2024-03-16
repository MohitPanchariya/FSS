from __future__ import annotations
from typing import Optional
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

    @staticmethod
    def get_user(db_conn, user_email: str = None, user_id: str = None) -> Optional[User]:
        """
        Returns a User object if the user exists. Else returns None.
        If neither the user_email nor user_id is specified, the function returns None
        """
        if not user_email and not user_id:
            return None

        cursor = db_conn.cursor()

        if user_id:
            query = "SELECT * from app_user where id = %s"
            cursor.execute(query, (user_id,))
        else:
            query = "SELECT * from app_user where email = %s"
            cursor.execute(query, (user_email,))

        user_data = cursor.fetchone()
        cursor.close()
        if not user_data:
            return None
        return User(
            user_id=user_data["id"].hex,
            email=user_data["email"],
            username=user_data["username"],
            password=user_data["password"]
        )

    @staticmethod
    def get_user_by_session(db_conn, session_id: str) -> Optional[User]:
        """
        Returns a User object if the session exists. Else returns None.
        """
        cursor = db_conn.cursor()
        query = "SELECT user_id from user_session where id = %s"
        cursor.execute(query, (session_id,))
        user_data = cursor.fetchone()
        cursor.close()

        if not user_data["user_id"]:
            return None
        user = User.get_user(db_conn, user_id=user_data["user_id"])
        return user
