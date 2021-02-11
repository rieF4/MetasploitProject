
from metasploit.api.logic.services import UserService
from metasploit.api.database import DatabaseOperations, DatabaseCollections

from metasploit.api.user.user import User


class UserServiceImplementation(UserService):
    """
    Implements the user service.

    Attributes:
        database (DatabaseOperations): DatabaseOperations object.
    """
    type = "User"

    def __init__(self, is_new_user=False, **kwargs):
        self.database = DatabaseOperations(collection_type=DatabaseCollections.USERS)
        self.user = User(is_new_user=is_new_user, **kwargs)

    def create(self):
        return self.create_user()

    def get_one(self):
        return self.get_user()

    def get_all(self):
        return self.get_all_users()

    def get_user(self):
        """
        Returns an existing user document from the DB.

        Returns:
            dict: a user client response in case found.

        Raises:
            UserNotFoundError: in case the user was not found in the DB.
        """
        return User(
            **self.database.get_user_document_by_id(
                user_id=self.user.id, username=self.user.username, password=self.user.password)
        ).client_response()

    def get_all_users(self):
        pass

    def create_user(self):
        """
        Returns a new created user response.
        """
        self.database.insert_user_document(new_user_document=self.user.document())
        new_user_response = self.user.client_response()
        return new_user_response

