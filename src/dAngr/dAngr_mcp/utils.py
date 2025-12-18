from dAngr.dAngr_mcp.tools import McpCommand
from dAngr.utils.utils import Endness


class McpUtils(McpCommand):
    def __init__(self, debugger, mcp):
        super().__init__(debugger, mcp)
    
    def to_int(self, value:bytes, endness:Endness=Endness.DEFAULT):
        """
        Transform hex value to int based on current state.

        Args:
            value (bytes): value or reference to the object.
            endness (Endness): Endianness of the value. Default is BE.
        """

        return int(value, 16)