import abc
from short_lived_tokens.endec.time_utils import get_timestamp_ms, in_range
import zlib
from abc import ABCMeta
import base64
from typing import Tuple


class EndecEngine(metaclass=ABCMeta):
    """Abstract Class `EndecEngine` can be used to define custom Encryption and Decryption Engine as per this Endec Specifications. 

    `Endec` is a portmanteau.

    It works with a very specific Encypted Token Structure out of the box. Although the structure can be overriden.

    Out of the box, a valid token is bytes array and has following structure:
        `<payload> <sep_token> <unix_timestamp> <sep_token> <crc32>`

    Any token with this structure is a valid token for EndecEngine. 
    Although you can override the `sleeve`, `unsleeve`, and `validate` methods to 
    define your own token structure and validation method. (Author doesn't recommended it though).
    """

    @property
    def token_life_ms(self) -> int:
        return self._token_life_ms

    def __init__(self, token_life_ms: int = 1000, key=None, sep_token: bytes = "::".encode(), is_private: bool = False) -> None:
        """constructor function initializes the `endec engine`

        Args:
            token_life_ms (int, optional): Lifetime of Token in milliseconds after which is considered invalid. Defaults to 1 seconds (1000 ms)
            key (str|bytes, optional): PEM file in bytes or file path for it. Defaults to None
            sep_token (bytes, optional): Seperation Token for payload structure. Defaults to '::' utf-8 bytes
            is_private (bool, optional): Mark if Engine has Private Key loaded. Defaults to False
        """

        self.sep_token = sep_token
        self._token_life_ms = token_life_ms
        self.is_private = is_private
        self.key = None

        if key:
            if isinstance(key, bytes):
                self.key = self.set_key(key, is_private)
            elif isinstance(key, str):
                self.key = self.load_key(key, is_private)

        super().__init__()

    @abc.abstractmethod
    def decrypt(self, encrypted_token: bytes) -> bytes:
        """`decrypt` decrypts a encrypted token

        Args:
            encrypted_token (bytes): encrypted token as bytes

        Returns:
            bytes: Decrypted plain text token as bytes
        """
        return None

    @abc.abstractmethod
    def encrypt(self, token: bytes) -> bytes:
        """`encrypt` encrypts a plain text token into a Endec Specified encrypted token

        Args:
            token (bytes): Plain text token as bytes

        Returns:
            bytes: Encrypted token as bytes
        """
        return None

    @abc.abstractmethod
    def generate_keypair(self, key_length: int = 2048) -> Tuple[bytes, bytes]:
        """`generate_keypair` generates a public/private keypair with specified `key_length` and exports PEM file according to RFC1421_/RFC1423

        Args:
            key_length (int, optional): Keylength. Defaults to 2048 bits.

        Returns:
            Tuple[bytes, bytes]: Export Generated (PublicKey, PrivateKey) pair as PEM files. Text encoding, done according to RFC1421_/RFC1423
        """

        return None

    @abc.abstractmethod
    def load_key(self, pemfile_path_abs: str, set_priv=False) -> None:
        """`load_key` loads a RSA Key from file path

        Args:
            pemfile_path_abs (str): Absolute File Path
            passphrase (str, optional): Passphrase for PEM file
            set_priv (bool, optional): Set True if you're reading from a Private PEM file. Defaults to False.

        Raises:
            FileNotFoundError
              When File Path is incorrect
            ValueError/IndexError/TypeError
              When given key cannot be parsed or if passphrase is wrong
        """
        return None

    def save_key(self, pemfile_path: str, key: bytes = None):
        if self.key is None and key is None:
            raise Exception("Key is not set or provied")

        with open(pemfile_path, 'wb') as fp:
            fp.write(self.key) if key is None else fp.write(key)

    def set_key(self, key: bytes, set_priv=False) -> None:
        self.key = key
        if set_priv:
            self.is_private = True

    def sleeve(self, payload: str) -> bytes:
        """`sleeve` method takes in a plain text payload as string and generates a token as per Endec Specification.

        Returns:
            bytes: Endec Specified Token
        """

        payload_bytes = payload.encode()
        timestamp_ms = get_timestamp_ms()
        ts_bytes = timestamp_ms.to_bytes(8, 'big')

        crc = zlib.crc32(payload_bytes + ts_bytes).to_bytes(8, 'big')

        return payload_bytes + self.sep_token + ts_bytes + self.sep_token + crc

    def unsleeve(self, encrypted_token: str) -> Tuple[bytes, int, int]:
        """`unsleeve` method takes in a Base64 Encoded Endec Specified token

        Args:
            encrypted_token (bytes): [description]

        Returns:
            bytes: [description]
        """
        b64_decoded_token = base64.b64decode(encrypted_token)
        decrypted_token = self.decrypt(b64_decoded_token)

        payload, timestamp_ms, crc = tuple(
            decrypted_token.split(self.sep_token))

        return payload, int.from_bytes(timestamp_ms, 'big'), int.from_bytes(crc, 'big')

    def validate(self, encrypted_token: str) -> bool:
        """`validate` validates an encrypted token and checks based on UNIX timestamp and returns a boolean value

        Args:
            encrypted_token (str): Base64 Encoded Encrypted Token. See Endec for Token Structure specification

        Returns:
            bool: validity state of token
        """
        payload, timestamp_ms, crc = self.unsleeve(encrypted_token)
        ts_bytes = timestamp_ms.to_bytes(8, 'big')

        computed_crc = zlib.crc32(payload + ts_bytes)

        if crc == computed_crc:
            return in_range(timestamp_ms, deadline=self.token_life_ms)

        return False
