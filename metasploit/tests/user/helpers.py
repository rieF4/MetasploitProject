import logging


logger = logging.getLogger("UserHelpers")


def is_user_response_body_valid(user_response_body, **expected):
    """
    Validates whether a user response body is valid or not.

    Args:
        user_response_body (dict): a user response body.

    Keyword arguments:
         email (str): the expected email.
         first_name (str): the expected first name.
         last_name (str): the expected last name

    Returns:
        bool: True if user response body is valid, False otherwise.
    """
    if "_id" not in user_response_body:
        logger.error(f"There is no _id key in the user response body {user_response_body}")
        return False

    if "email" not in user_response_body:
        logger.error(f"There is no email key in the user response body {user_response_body}")
        return False

    if "first_name" not in user_response_body:
        logger.error(f"There is no first_name key in the user response body {user_response_body}")
        return False

    if "last_name" not in user_response_body:
        logger.error(f"There is no last_name key in the user response body {user_response_body}")
        return False

    return is_user_response_body_expected(user_response_body, **expected)


def is_user_response_body_expected(user_response_body, **expected):
    """
    Verifies whether a user response body is as expected or not.

    Args:
        user_response_body (dict): a user response body.

    Keyword arguments:
         email (str): the expected email.
         first_name (str): the expected first name.
         last_name (str): the expected last name

    Returns:
        bool: True if user response body as expected, False otherwise.
    """
    if "email" in expected:
        expected_email = expected.get("email")
        actual_email = user_response_body.get("email")
        if expected_email != actual_email:
            logger.error(f"actual email: {actual_email}, expected email: {expected_email}")
            return False

    if "first_name" in expected:
        expected_first_name = expected.get("first_name")
        actual_first_name = user_response_body.get("first_name")
        if expected_first_name != actual_first_name:
            logger.error(f"actual first name: {actual_first_name}, expected first name: {expected_first_name}")
            return False

    if "last_name" in expected:
        expected_last_name = expected.get("last_name")
        actual_last_name = user_response_body.get("last_name")
        if actual_last_name != expected_last_name:
            logger.error(f"actual last name: {actual_last_name}, expected last name: {expected_last_name}")
            return False

    return True
