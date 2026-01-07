def apply_patches() -> None:
    # Import the module that *defines* VariableAccess
    import angr.knowledge_plugins.variables.variable_access as va
    from angr.code_location import CodeLocation
    from angr.knowledge_plugins.variables.variable_access import VariableAccessSort

    def _parse_from_cmessage(cls, cmsg, variable_by_ident=None, **kwargs):
        assert variable_by_ident is not None

        variable = variable_by_ident[cmsg.ident]
        location = CodeLocation(cmsg.block_addr, cmsg.stmt_idx, ins_addr=cmsg.ins_addr)

        if cmsg.access_type == va.variables_pb2.VariableAccess.READ:
            access_type = VariableAccessSort.READ
        elif cmsg.access_type == va.variables_pb2.VariableAccess.WRITE:
            access_type = VariableAccessSort.WRITE
        elif cmsg.access_type == va.variables_pb2.VariableAccess.REFERENCE:
            access_type = VariableAccessSort.REFERENCE
        else:
            raise NotImplementedError

        offset = cmsg.offset if (hasattr(cmsg, "offset")) else None
        atom_hash = cmsg.atom_hash if (hasattr(cmsg, "HasField") and cmsg.HasField("atom_hash")) else None

        return cls(variable, access_type, location, offset, atom_hash=atom_hash)

    # Patch the existing class object (reliable even if other modules imported it already)
    va.VariableAccess.parse_from_cmessage = classmethod(_parse_from_cmessage)