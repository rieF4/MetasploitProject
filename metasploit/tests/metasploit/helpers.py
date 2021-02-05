import logging

logger = logging.getLogger("MetasploitHelpers")


def is_exploit_name_response_valid(exploit_details_body_response):
    """
    Validates whether a get exploit name details response body is valid.

    Args:
        exploit_details_body_response (dict): the response body of the exploit details.

    Returns:
        bool: True if the response is valid, False otherwise.
    """
    if "name" not in exploit_details_body_response:
        logger.error(f"There is no name key in the exploit details response body {exploit_details_body_response}")
        return False

    if "description" not in exploit_details_body_response:
        logger.error(
            f"There is no description key in the exploit details response body {exploit_details_body_response}"
        )
        return False

    if "options" not in exploit_details_body_response:
        logger.error(f"There is no options key in the exploit details response body {exploit_details_body_response}")
        return False

    if "filledOptions" not in exploit_details_body_response:
        logger.error(
            f"There is no filledOptions key in the exploit details response body {exploit_details_body_response}"
        )
        return False

    if "requiredOptions" not in exploit_details_body_response:
        logger.error(
            f"There is no requiredOptions key in the exploit details response body {exploit_details_body_response}"
        )
        return False

    if "platform" not in exploit_details_body_response:
        logger.error(
            f"There is no platform key in the exploit details response body {exploit_details_body_response}"
        )
        return False

    if "rank" not in exploit_details_body_response:
        logger.error(
            f"There is no rank key in the exploit details response body {exploit_details_body_response}"
        )
        return False

    if "privileged" not in exploit_details_body_response:
        logger.error(
            f"There is no privileged key in the exploit details response body {exploit_details_body_response}"
        )
        return False

    if "references" not in exploit_details_body_response:
        logger.error(
            f"There is no references key in the exploit details response body {exploit_details_body_response}"
        )
        return False
    return True
