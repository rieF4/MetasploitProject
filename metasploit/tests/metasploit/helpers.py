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

    if "stance" not in exploit_details_body_response:
        logger.error(
            f"There is no stance key in the exploit details response body {exploit_details_body_response}"
        )
        return False

    return True


def is_payload_name_response_valid(payload_details_response_body):
    """
    Validates whether a get payload name details response body is valid.

    Args:
        payload_details_response_body (dict): the response body of the payload details.

    Returns:
        bool: True if the response is valid, False otherwise.
    """
    if "name" not in payload_details_response_body:
        logger.error(f"There is no name key in the payload details response body {payload_details_response_body}")
        return False

    if "description" not in payload_details_response_body:
        logger.error(
            f"There is no description key in the payload details response body {payload_details_response_body}"
        )
        return False

    if "options" not in payload_details_response_body:
        logger.error(f"There is no options key in the payload details response body {payload_details_response_body}")
        return False

    if "filledOptions" not in payload_details_response_body:
        logger.error(
            f"There is no filledOptions key in the payload details response body {payload_details_response_body}"
        )
        return False

    if "requiredOptions" not in payload_details_response_body:
        logger.error(
            f"There is no requiredOptions key in the payload details response body {payload_details_response_body}"
        )
        return False

    if "platform" not in payload_details_response_body:
        logger.error(
            f"There is no platform key in the payload details response body {payload_details_response_body}"
        )
        return False

    if "rank" not in payload_details_response_body:
        logger.error(
            f"There is no rank key in the payload details response body {payload_details_response_body}"
        )
        return False

    if "privileged" not in payload_details_response_body:
        logger.error(
            f"There is no privileged key in the payload details response body {payload_details_response_body}"
        )
        return False

    if "references" not in payload_details_response_body:
        logger.error(
            f"There is no references key in the payload details response body {payload_details_response_body}"
        )
        return False
    return True
