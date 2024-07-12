import xml.etree.ElementTree as ET
import hashlib
import secrets
import base64
from typing import List
import sys
import logging


logging.basicConfig(level=logging.INFO, format="%(asctime)s|%(levelname)s|%(message)s")


class FileZillaUserManager:

    NAMESPACE = "https://filezilla-project.org"

    def __init__(self, file_path: str):
        """
        Initialize the FileZillaUserManager with the path to the XML file.

        Args:
        - file_path (str): Path to the XML file.
        """
        self.file_path = file_path
        self._check_access_permission()
        ET.register_namespace("", self.NAMESPACE)

    def _check_access_permission(self) -> None:
        """
        Check if the XML file can be read and written.

        Raises:
        - PermissionError: If the file cannot be accessed due to permissions.
        - FileNotFoundError: If the file does not exist.
        """
        try:
            with open(self.file_path, "r") as f_read, open(
                self.file_path, "a"
            ) as f_write:
                pass
        except PermissionError:
            logging.error(
                f"'{self.file_path}' cannot be accessed due to a permissions error."
            )
            sys.exit(1)
        except FileNotFoundError:
            logging.error(f"'{self.file_path}' not found.")
            sys.exit(1)

    def generate_user_password_hash(
        self, password: str, iterations: int = 100000
    ) -> dict:
        """
        Generate a password hash and salt for the given password.

        Args:
        - password (str): The plain text password to hash.
        - iterations (int): The number of iterations for the hashing algorithm (default is 100000).

        Returns:
        - dict: A dictionary containing the password hash, salt, and number of iterations.
        """
        salt: bytes = secrets.token_bytes(32)
        b64_salt = base64.b64encode(salt)
        password_as_bytes = password.encode("ascii")
        password_hash: bytes = hashlib.pbkdf2_hmac(
            "sha256", password_as_bytes, salt, iterations
        )
        b64_password_hash = base64.b64encode(password_hash)
        return {
            "password_hash": b64_password_hash.decode(),
            "salt": b64_salt.decode(),
            "iterations": iterations,
        }

    def parse_user_xml(self) -> None:
        """
        Parse the XML file and print out each user's name and enabled status.

        Raises:
        - FileNotFoundError: If the XML file does not exist.
        - Exception: If there is an error parsing the XML file.
        """
        try:
            tree = ET.parse(self.file_path)
            root = tree.getroot()
            users = root.findall(f"{{{self.NAMESPACE}}}user")

            for user in users:
                user_name = user.get("name")
                user_enabled = user.get("enabled")
                print(f"User Name: {user_name}")
                print(f"Enabled: {user_enabled}")
                print("-" * 20)
        except FileNotFoundError:
            logging.error(f"Error: File '{self.file_path}' not found.")
        except Exception as e:
            logging.error(f"Error: Failed to parse XML - {str(e)}")

    def create_user(self, username: str, password: str, group_name: str) -> None:
        """
        Create a new user in the XML file with the provided username, password, and group name.

        Args:
        - username (str): The username of the new user.
        - password (str): The password for the new user.
        - group_name (str): The group name for the new user.

        Raises:
        - FileNotFoundError: If the XML file does not exist.
        - PermissionError: If there is a permissions error accessing the file.
        - ValueError: If the username already exists.
        """
        try:
            tree = ET.parse(self.file_path)
            root = tree.getroot()

            if (
                root.find(f".//{{{self.NAMESPACE}}}user[@name='{username}']")
                is not None
            ):
                logging.error(f"User '{username}' already exists.")
                raise ValueError(f"User '{username}' already exists.")

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
                user_elem,
                "session_open_limits",
                files="unlimited",
                directories="unlimited",
            )
            ET.SubElement(user_elem, "session_count_limit").text = "unlimited"
            ET.SubElement(user_elem, "description").text = ""
            ET.SubElement(user_elem, "group").text = group_name
            ET.SubElement(user_elem, "group").text = "Public"

            password_elem = ET.SubElement(user_elem, "password", index="1")
            password_params = self.generate_user_password_hash(password)
            ET.SubElement(password_elem, "hash").text = password_params["password_hash"]
            ET.SubElement(password_elem, "salt").text = password_params["salt"]
            ET.SubElement(password_elem, "iterations").text = str(
                password_params["iterations"]
            )
            ET.SubElement(user_elem, "methods").text = str(1)

            tree.write(
                self.file_path, encoding="utf-8", xml_declaration=False, method="xml"
            )
            logging.info(
                f"'{username}' added. A server restart will be needed for changes to take place"
            )

        except FileNotFoundError:
            logging.error(f"Error: File '{self.file_path}' not found.")
        except PermissionError as e:
            logging.error(f"Error: Failed to create user - {str(e)}")
        except Exception as e:
            logging.error(f"Error: Failed to create user - {str(e)}")
