from .endec import EndecEngine


class Token:
    """A simple `Token` class to deal with short lived tokens"""

    def __init__(self, engine: EndecEngine, encrypted_token=None) -> None:
        """Creates a `Token` with encypted token or empty token"""
        self.engine = engine
        self._is_valid = False

        if encrypted_token is not None:
            self._encrypted_token = encrypted_token
            self._is_valid = self.is_valid(reset=True)

    def is_valid(self, reset=False) -> bool:
        if not reset:
            return self._is_valid

        self._is_valid = self.engine.validate(self._encrypted_token)

        return self._is_valid

    def set_encrypted_token(self, encrypted_token: str) -> None:
        self._encrypted_token = encrypted_token
        self._is_valid = self.is_valid(reset=True)
