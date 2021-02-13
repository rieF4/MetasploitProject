
CREATE_USER_URL = "/Users/Create"
GET_USER_URL = "/Users/Get/{username}/{password}"
GET_ALL_USERS_URL = "/Users/Get"
DELETE_USER_URL = "/Users/Delete/{username}"


VALID_PASSWORD = "123456789"
INVALID_PASSWORD = "1234"
VALID_FIRST_NAME = "Guy"
INVALID_FIRST_NAME = "Guy123"
VALID_LAST_NAME = "jackson"
INVALID_LAST_NAME = "jackson123"
USERNAME = "username"
VALID_EMAIL = "guyafik423468@gmail.com"
INVALID_EMAIL = "guyafik42@@.com"


USER_REQUEST_WITH_SHORT_PASSWORD = {
    "first_name": VALID_FIRST_NAME,
    "last_name": VALID_LAST_NAME,
    "username": USERNAME,
    "password": INVALID_PASSWORD,
    "email": VALID_EMAIL
}

USER_REQUEST_WITH_NUMBERS_IN_FIRST_NAME = {
    "first_name": INVALID_FIRST_NAME,
    "last_name": VALID_LAST_NAME,
    "username": USERNAME,
    "password": VALID_PASSWORD,
    "email": VALID_EMAIL
}

USER_REQUEST_WITH_NUMBERS_IN_LAST_NAME = {
    "first_name": VALID_FIRST_NAME,
    "last_name": INVALID_LAST_NAME,
    "username": USERNAME,
    "password": VALID_PASSWORD,
    "email": VALID_EMAIL
}

USER_REQUEST_WITH_INVALID_EMAIL = {
    "first_name": VALID_FIRST_NAME,
    "last_name": VALID_LAST_NAME,
    "username": USERNAME,
    "password": VALID_PASSWORD,
    "email": INVALID_EMAIL
}

USER_REQUEST_WITHOUT_FIRST_NAME_AND_LAST_NAME = {
    "username": USERNAME,
    "password": VALID_PASSWORD,
    "email": VALID_EMAIL
}

USER_REQUEST_WITHOUT_PASSWORD_AND_USER_NAME = {
    "first_name": VALID_FIRST_NAME,
    "last_name": VALID_LAST_NAME,
    "username": USERNAME,
}
