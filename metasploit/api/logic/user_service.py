
from metasploit.api.logic.services import UserService
from metasploit.api.database import DatabaseOperations, DatabaseCollections

from metasploit.api.user.user import User
from metasploit.api.errors import PasswordIsInvalidError


class UserServiceImplementation(UserService):
    """
    Implements the user service.

    Attributes:
        database (DatabaseOperations): DatabaseOperations object.
    """
    type = "User"

    def __init__(self, **kwargs):
        self.database = DatabaseOperations(collection_type=DatabaseCollections.USERS)
        self.user = User(**kwargs)

    def create(self):
        return self.create_user()

    def get_one(self):
        return self.get_user()

    def get_all(self):
        return self.get_all_users()

    def delete_one(self):
        return self.delete_user()

    def get_user(self):
        """
        Returns an existing user document from the DB.

        Returns:
            dict: a user client response in case found.

        Raises:
            PasswordIsInvalidError: in case the password is not correct.
        """
        existing_user = User(**self.database.get_user_document_by_id(user_id=self.user.id, username=self.user.username))

        if existing_user.are_passwords_matched(password=self.user.hashed_password):
            return existing_user.client_response()
        else:
            raise PasswordIsInvalidError(password=self.user.password)

    def get_all_users(self):
        """
        Gets all the existing users.

        Returns:
            list[dict]: a list of all available users.
        """
        users_response = []
        all_available_users = self.database.get_all_documents()

        for user in all_available_users:
            users_response.append(User(**user).client_response())
        return users_response

    def create_user(self):
        """
        Creates a user in the DB and returns the new created user document.

        Returns:
            dict: a new user document.
        """
        self.database.insert_user_document(new_user_document=self.user.document())
        new_user_response = self.user.client_response()
        return new_user_response

    def delete_user(self):
        """
        Deletes a user from the DB.

        Returns:
            str: empty string as a response in case of success.
        """
        self.database.delete_amazon_document(resource_id=self.user.id, type=self.type)
        return ''
