from .CommandError import CommandError

class FileNotFoundError(CommandError):
    """Exception raised when a file is not found."""
    pass