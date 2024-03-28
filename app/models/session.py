import datetime
import uuid


class Session:
    """
    Session model for a session in the database.
    """

    def __init__(
            self, session_id: str, user_id: uuid.uuid4, created_at: datetime.datetime,
            expires_at: datetime.datetime
    ):
        self.session_id = session_id
        self.user_id = user_id
        self.created_at = created_at
        self.expires_at = expires_at

    @staticmethod
    def insert_into_db(
            db_conn,
            session_id: str,
            user_id: str,
            created_at: datetime.datetime,
            expires_at: datetime.datetime
    ):
        """
        Inserts a session into the database.
        """
        cursor = db_conn.cursor()
        query = "INSERT INTO user_session VALUES(%s, %s, %s, %s)"
        cursor.execute(query, (session_id, user_id, created_at, expires_at))
        cursor.close()
        db_conn.commit()

    @staticmethod
    def delete_session(db_conn, session_id: str):
        """
        Deletes the session with the given session_id from
        the database.
        """
        query = "DELETE FROM user_session WHERE id = %s"
        cursor = db_conn.cursor()
        cursor.execute(query, (session_id,))
        cursor.close()
        db_conn.commit()

    @staticmethod
    def delete_all_sessions(db_conn, user_id: str):
        """
        Deletes all sessions for a user identified by the given user_id.
        """
        query = "DELETE FROM user_session WHERE user_id = %s"
        cursor = db_conn.cursor()
        cursor.execute(query, (user_id,))
        cursor.close()
        db_conn.commit()

    @staticmethod
    def is_session_active(db_conn, session_id: str) -> bool:
        """
        Returns True if the session is active and False otherwise.
        Deletes the session entry from the database if the session
        has expired.
        """
        cursor = db_conn.cursor()
        query = "SELECT expires_at FROM user_session WHERE id = %s"
        cursor.execute(query, (session_id,))
        session_data = cursor.fetchone()
        cursor.close()

        if session_data:
            # session has expired
            if session_data["expires_at"] < datetime.datetime.now():
                Session.delete_session(db_conn=db_conn, session_id=session_id)
                return False
            # session is still active
            else:
                return True
