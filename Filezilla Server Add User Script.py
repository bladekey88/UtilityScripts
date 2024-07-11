#!/usr/bin/env python
# coding: utf-8


import xml.etree.ElementTree as ET
import hashlib
import secrets
import base64
from typing import List


# #### Generate password hash
def generate_user_password_hash(password: str) -> dict[str, str]:
    """
    Generate a salted and hashed password using PBKDF2-HMAC-SHA256.

    Args:
    - password (str): The password to be hashed.

    Returns:
    - dict: A dictionary containing 'password_hash' (base64 encoded hash) and 'salt' (base64 encoded salt).
    """
    salt: bytes = secrets.token_bytes(32)
    b64_salt: bytes = base64.b64encode(salt)
    password_as_bytes: bytes = password.encode("ascii")
    password_hash: bytes = hashlib.pbkdf2_hmac(
        "sha256", password_as_bytes, salt, 100000
    )
    b64_password_hash: bytes = base64.b64encode(password_hash)
    return {"password_hash": b64_password_hash.decode(), "salt": b64_salt.decode()}


def parse_user_xml(user_file: str) -> None:
    """
    Parse an XML file containing user information.

    Args:
    - user_file (str): Path to the XML file.

    Prints:
    - User Name and Enabled status for each user found in the XML file.
    """
    tree: ET.ElementTree = ET.parse(user_file)
    root: ET.Element = tree.getroot()
    users: List[ET.Element] | None = root.findall("{*}user")

    # Loop through each user element and extract information
    for user in users:

        # Get user attributes (name and enabled)
        user_name = user.get("name")
        user_enabled = user.get("enabled")

    print(f"User Name: {user_name}")
    print(f"Enabled: {user_enabled}")
    print("-" * 20)  # Print a separator between users


def create_user(file_path: str, username, password, group_name) -> None:
    """
    Creates a new user entry in the FileZilla XML configuration file.

    Args:
    - file_path (str): Path to the XML file where users are stored.
    - username (str): Username of the new user to create.
    - password (str): Password for the new user.
    - group_name (str): Name of the group to which the new user belongs.

    Returns:
    - None

    Raises:
    - FileNotFoundError: If the specified XML file does not exist.
    - Exception: If there is an error in parsing the XML file or writing to it.

    This function checks if the username already exists in the XML file. If the
    username does not exist, it creates a new <user> element under the root
    element with the provided username, password hash, salt, and group name.
    The user's password hash and salt are generated using
    `generate_user_password_hash`.

    Note:
    - The function assumes the existence of certain XML structure and elements
      in the FileZilla XML file.

    Example:
    >>> create_user('filezilla.xml', 's.snape', 'password123', 'Staff')
    """

    # Register an empty namespace to avoid ns0 prefixes
    ET.register_namespace("", "https://filezilla-project.org")

    try:
        tree: ET.ElementTree = ET.parse(file_path)
        root: ET.Element = tree.getroot()

        # Check if the username already exists
        # Use {{*}} to treat as literal in f-string, to ignore namespaces

        if root.find(f".//{{*}}user[@name='{username}']") is not None:
            raise Exception(f"User {username} already exists.")

        # Construct XML
        user_elem = ET.SubElement(root, "user", name=username, enabled="true")

        ET.SubElement(
            user_elem,
            "rate_limits",
            inbound="unlimited",
            outbound="unlimited",
            session_inbound="unlimited",
            session_outbound="unlimited",
        )

        ET.SubElement(user_elem, "allowed_ips").text = ""
        ET.SubElement(user_elem, "disallowed_ips").text = ""
        ET.SubElement(
            user_elem, "session_open_limits", files="unlimited", directories="unlimited"
        )
        ET.SubElement(user_elem, "session_count_limit").text = "unlimited"
        ET.SubElement(user_elem, "description").text = ""
        ET.SubElement(user_elem, "group").text = group_name
        ET.SubElement(user_elem, "group").text = "Public"

        password_elem: ET.Element = ET.SubElement(user_elem, "password", index="1")

        # Use password function to create items
        password_params: dict[str, str] = generate_user_password_hash(password)
        ET.SubElement(password_elem, "hash").text = password_params["password_hash"]
        ET.SubElement(password_elem, "salt").text = password_params["salt"]
        ET.SubElement(password_elem, "iterations").text = str(100000)
        ET.SubElement(user_elem, "methods").text = str(1)

        # Write out to file
        tree.write(file_path, encoding="utf-8", xml_declaration=False, method="xml")

    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
    except Exception as e:
        print(f"Error: Failed to create user - {str(e)}")
