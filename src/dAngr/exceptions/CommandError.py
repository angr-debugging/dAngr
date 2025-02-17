class CommandError(Exception):
    """Base for command execution errors."""
    pass
    def __eq__(self, value: object) -> bool:
        if not isinstance(value, CommandError):
            return False
        return self.args == value.args