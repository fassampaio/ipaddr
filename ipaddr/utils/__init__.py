import ipaddress

def is_valid_ip_address(address) -> bool:
    """This function verify if a IP address is valid.
    Args:
        address (str): IP address
    Returns:
        bool: True (ip valid) or False (ip invalid)
    """
    try:
        ip = ipaddress.ip_address(address)
        return True
    except ValueError:
        return False
