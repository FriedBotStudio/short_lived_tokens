from typing import Tuple
from short_lived_tokens.endec.engine import EndecEngine
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


class RSAEndecEngine(EndecEngine):
    """Class `RSAEndecEngine` handles RSA Encryption and Decryption. Endec is a portmanteau"""

    def __init__(self, token_life_ms: int = 1000, sep_token: bytes = "::".encode(), private_rsa_pem_file: bytes = None, public_rsa_pem_file=None) -> None:
        """constructor function initializes the `endec engine`

        Args:
            token_life_ms (int): Lifetime of Token in milliseconds after which is considered invalid. Defaults to 1 second (1000 ms)
            sep_token (bytes, optional): Seperation Token for payload structure. Defaults to '::' utf-8 bytes
            private_rsa_pem_file (bytes, optional): RSA Private PEM Binary File. Overrides public_rsa_pem_file variable. Defaults to None.
            public_rsa_pem_file (bytes, optional): RSA Public PEM Binary File. Defaults to None.
        """

        key = None
        is_private = False
        if private_rsa_pem_file is not None or public_rsa_pem_file is not None:
            if private_rsa_pem_file is not None:
                key = RSA.import_key(private_rsa_pem_file)
                is_private = True
            else:
                key = RSA.import_key(public_rsa_pem_file)

            self.encrypter = PKCS1_OAEP.new(key)

        super().__init__(token_life_ms=token_life_ms, key=key,
                         sep_token=sep_token, is_private=is_private)

    def decrypt(self, encrypted_token: bytes) -> bytes:
        """`decrypt` decrypts a RSA encrypted token

        Args:
            encrypted_token (bytes): RSA encrypted token as bytes

        Returns:
            bytes: Decrypted plain text token as bytes
        """
        return self.encrypter.decrypt(encrypted_token)

    def encrypt(self, token: str) -> bytes:
        """`encrypt` encrypts a plain text token into a RSA encrypted Encdec Specified token

        Args:
            token (str): Plain text token as string

        Returns:
            bytes: RSA encrypted token as bytes
        """
        return self.encrypter.encrypt(self.sleeve(token))

    def generate_keypair(self, key_length: int = 2048) -> Tuple[bytes, bytes]:
        """`generate_keypair` generates a public/private keypair with specified `key_length` and exports PEM file according to RFC1421_/RFC1423

        Args:
            key_length (int, optional): RSA Keylength. Defaults to 2048 bits.

        Returns:
            Tuple[bytes, bytes]: Export Generated (PublicKey, PrivateKey) pair as PEM files. Text encoding, done according to RFC1421_/RFC1423
        """
        key = RSA.generate(key_length)
        privkey_pem = key.export_key()
        pubkey_pem = key.publickey().export_key()

        return (pubkey_pem, privkey_pem)

    def load_key(self, pemfile_path_abs: str, passphrase: str = None, set_priv=False) -> None:
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
        try:
            with open(pemfile_path_abs, 'rb') as fp:
                self.set_key(RSA.import_key(
                    fp.read(), passphrase=passphrase), set_priv=set_priv)

                self.encrypter = PKCS1_OAEP.new(self.key)

        except Exception as e:
            raise e
