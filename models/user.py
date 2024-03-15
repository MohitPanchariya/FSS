class User:
    """
    User model for a user in the database.
    """

    def __init__(self, user_id: str, username: str, email: str, password: str):
        self.user_id = user_id
        self.username = username
        self.email = email
        self.password = password
