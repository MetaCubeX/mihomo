class HttpRequestError(Exception):
    """Http request failed"""

    status: int = 0
    reason: str = ""
    message: str = ""

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
