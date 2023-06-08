class BaseException(Exception):
    """Base exception class."""

    message: str = ""

    def __init__(self, message: str | None = None, *args: object) -> None:
        if message is not None:
            self.message = message
        super().__init__(self.message, *args)


class HttpRequestError(BaseException):
    """Exception raised when an HTTP request fails."""

    status: int = 0
    reason: str = ""

    def __init__(
        self,
        status: int,
        reason: str,
        message: str | None = None,
        *args: object,
    ) -> None:
        if not message:
            message = f"[{status}] {reason}"
        self.status = status
        self.reason = reason
        self.message = message
        super().__init__(message, *args)


class UserNotFound(BaseException):
    """Exception raised when a user is not found."""

    message = "User not found."


class InvalidParams(BaseException):
    """Exception raised when invalid parameters are provided."""

    message: str = "Invalid parameters"
