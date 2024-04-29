from .CommandError import CommandError

class InvalidArgumentError(CommandError):
    """Exception raised for invalid arguments."""
    pass