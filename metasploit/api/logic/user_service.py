
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

    def __init__(self, **kwargs):
        self.database = DatabaseOperations(collection_type=DatabaseCollections.USERS)
        self.user = User(**kwargs)

    def create(self):
        return self.create_user()

    # def get_all(self):
    #     pass
    #
    # def get_one(self, *args, **kwargs):
    #     return self.get_user()
    #
    # def delete_one(self, *args, **kwargs):
    #     pass
    #
    # def get_user(self, user_id):
    #     """
    #     Returns an existing user response from the DB.
    #     """
    #     existing_users_details = self.database.get_all_amazon_documents()
    #     for user_details in existing_users_details:
    #         if self.user.compare(user_to_compare=User(**user_details)):
    #             return user_details.client_response()
    #     raise UserNotFoundError
    #
    #
    # def get_all_users(self):
    #     pass

    def create_user(self):
        """
        Returns a new created user response.
        """
        new_user_id = self.database.insert_user_document(new_user_document=self.user.document())
        self.user.id = new_user_id
        new_user_response = self.user.client_response()
        return new_user_response

