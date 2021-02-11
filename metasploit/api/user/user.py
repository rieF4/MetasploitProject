import hashlib
from email_validator import validate_email, EmailNotValidError

from metasploit.api.response import create_new_response, fill_user_document
from metasploit.api.errors import BadEmailError, BadFirstNameOrLastName, BadPasswordLength


class User(object):
    """
    This class represents a user in the API.

    Attributes:
        first_name (str): first name of the user.
        last_name (str): last name of the user.
        email (str): email address of the user.
        username (str): user name.
        _hashed_password (str): the hashed password.
        _id (str): user ID.

    """
    def __init__(
            self,
            is_hashing_password_required=False,
            first_name=None,
            last_name=None,
            email=None,
            username=None,
            password=None,
            _id=None
    ):
        """
        Initializes the user constructor.

        Args:
            is_hashing_password_required (bool): if provided password should be hashed or not.
            first_name (str): first user name.
            last_name (str): last user name.
            username (str): user name.
            email (str): email address of the user.
            password (str): password of the user.
            _id (str): user ID.
        """
        if len(password) < 8:
            raise BadPasswordLength(password=password)
        try:
            validate_email(email=email)
        except EmailNotValidError:
            raise BadEmailError(email=email)

        if not first_name.isalpha() or not last_name.isalpha():
            raise BadFirstNameOrLastName(first_name=first_name, last_name=last_name)

        self._first_name = first_name
        self._last_name = last_name
        self._email = email
        self._username = username
        self._hashed_password = hashlib.sha256(
            password.encode('utf-8')
        ).hexdigest() if is_hashing_password_required else password
        self._id = hashlib.sha256(f"{username}".encode('utf-8')).hexdigest() if not _id else _id

    @property
    def id(self):
        return self._id

    @property
    def first_name(self):
        return self._first_name

    @property
    def last_name(self):
        return self._last_name

    @property
    def email(self):
        return self._email

    @property
    def username(self):
        return self._username

    @property
    def hashed_password(self):
        return self._hashed_password

    def compare_passwords(self, password):
        return self._hashed_password == password

    def client_response(self, response_type='User'):
        """
        Returns a response built for the client.

        Args:
            response_type (str): response type.

        Returns:
            dict: a response meant to be sent for the client.
        """
        return create_new_response(obj=self, response_type=response_type)

    def document(self):
        """
        Returns a response built for the DB.

        Returns:
            dict: a response meant to be saved for the DB.
        """
        return fill_user_document(user=self)
