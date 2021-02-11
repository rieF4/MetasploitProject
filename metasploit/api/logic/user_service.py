import hashlib

from metasploit.api.logic.services import UserService
from metasploit.api.database import DatabaseOperations, DatabaseCollections

from metasploit.api.user.user import User
from metasploit.api.errors import PasswordIsInvalidError
from metasploit.api.utils.decorators import validate_json_request


class UserServiceImplementation(UserService):
    """
    Implements the user service.

    Attributes:
        database (DatabaseOperations): DatabaseOperations object.
    """
    type = "User"

    def __init__(self):
        self.database = DatabaseOperations(collection_type=DatabaseCollections.USERS)

    def create(self, *args, **kwargs):
        return self.create_user(*args, **kwargs)

    def get_one(self, *args, **kwargs):
        return self.get_user(*args, **kwargs)

    def get_all(self):
        return self.get_all_users()

    def delete_one(self, *args, **kwargs):
        return self.delete_user(*args, **kwargs)

    def get_user(self, username, password):
        """
        Returns an existing user document from the DB.

        Returns:
            dict: a user client response in case found.

        Raises:
            PasswordIsInvalidError: in case the password is not correct.
        """
        existing_user = User(
            **self.database.get_user_document_by_id(
                user_id=hashlib.sha256(username.encode('utf-8')).hexdigest(),
                username=username
            )
        )

        if existing_user.compare_passwords(password=hashlib.sha256(password.encode('utf-8')).hexdigest()):
            return existing_user.client_response()
        else:
            raise PasswordIsInvalidError(password=password)

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

    @validate_json_request("first_name", "last_name", "username", "password", "email")
    def create_user(self, **create_user_json):
        """
        Creates a user in the DB and returns the new created user document.

        Returns:
            dict: a new user document.
        """
        new_user = User(is_hashing_password_required=True, **create_user_json)
        self.database.insert_user_document(new_user_document=new_user.document())
        return new_user.client_response()

    def delete_user(self, username):
        """
        Deletes a user from the DB.

        Returns:
            str: empty string as a response in case of success.
        """
        self.database.delete_amazon_document(
            resource_id=hashlib.sha256(username.encode('utf-8')).hexdigest(), type=self.type
        )
        return ''
