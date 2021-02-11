import hashlib
from email_validator import validate_email, EmailNotValidError
from bson.objectid import ObjectId

from metasploit.api.response import create_new_response, fill_user_document
from metasploit.api.errors import BadEmailError, BadFirstNameOrLastName, BadPasswordLength


class User(object):

    def __init__(self, first_name, last_name, email, username, password, _id=None):
        """
        Args:
            first_name (str):
        """
        if len(password) < 8:
            raise BadPasswordLength(password=password)
        try:
            validate_email(email=email)
        except EmailNotValidError:
            raise BadEmailError(email=email)

        if first_name.isalpha() and last_name.isalpha():
            self._first_name = first_name
            self._last_name = last_name
        else:
            raise BadFirstNameOrLastName(first_name=first_name, last_name=last_name)

        self._email = email
        self._username = username
        self._hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest() if not _id else password
        if _id:
            self._id = str(_id) if isinstance(ObjectId, _id) else _id

    @property
    def id(self):
        return self._id

    @id.setter
    def id(self, new_id):
        self._id = new_id

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

    def compare(self, user_to_compare):
        return self._username == user_to_compare.user_name and self._hashed_password == user_to_compare.hashed_password

    def are_passwords_matched(self, password):
        return self._hashed_password == hashlib.sha256(bytes(password)).hexdigest()

    def client_response(self, response_type='User'):
        return create_new_response(obj=self, response_type=response_type)

    def document(self):
        return fill_user_document(user=self)
