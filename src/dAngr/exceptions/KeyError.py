from .CommandError import CommandError
class KeyError(CommandError):
    def __init__(self, key):
        super(KeyError, self).__init__("KeyError: %s" % key)
        self.key = key