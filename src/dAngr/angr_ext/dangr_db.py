from typing import Any, TYPE_CHECKING
from angr.angrdb.db import AngrDB
from angr.angrdb.serializers import LoaderSerializer
from angr.angrdb.serializers import KnowledgeBaseSerializer
from angr.project import Project

from angr.errors import AngrCorruptDBError, AngrIncompatibleDBError, AngrDBError
from angr.angrdb.models import DbObject 
from angr.knowledge_base import KnowledgeBase

from io import BytesIO
import json
import binascii
import logging

import cle

class LoadArgsJSONDecoder(json.JSONDecoder):
    """
    A JSON decoder that supports unserializing into bytes.
    """

    def __init__(self):
        super().__init__(object_hook=self._objhook)

    def _objhook(self, d: dict):  # pylint:disable=no-self-use
        if "__custom_type__" in d:
            match d["__custom_type__"]:
                case "bytes":
                    if "__v__" in d:
                        return binascii.unhexlify(d["__v__"])
        return d

class DangrLoaderSerializer(LoaderSerializer):
    @staticmethod
    def load(session):
        all_objects = {}  # path to object
        main_object = None

        db_objects: list[DbObject] = session.query(DbObject)
        load_args = {}

        decoder = LoadArgsJSONDecoder()

        for db_o in db_objects:
            all_objects[db_o.path] = db_o
            if db_o.main_object:
                main_object = db_o
            load_args[db_o] = decoder.decode(db_o.backend_args) if db_o.backend_args else {}

        if main_object is None:
            raise AngrCorruptDBError("Corrupt database: No main object.")

        # build params
        # FIXME: Load other objects

        loader = cle.Loader(BytesIO(main_object.content), auto_load_libs=False, main_opts=load_args[main_object])

        skip_mainbin, _ = LoaderSerializer.should_skip_main_binary(loader)

        loader._main_binary_path = main_object.path
        if not skip_mainbin:
            # fix the binary name of the main binary
            loader.main_object.binary = main_object.path

        return loader

class DAngrDB(AngrDB):
    
    def load(
        self,
        db_path: str,
        kb_names: list[str] | None = None,
        other_kbs: dict[str, KnowledgeBase] | None = None,
        extra_info: dict[str, Any] | None = None,
    ):
        db_str = f"sqlite:///{db_path}"

        with self.open_db(db_str) as Session, self.session_scope(Session) as session:
            # Compatibility check
            dbinfo = self.get_dbinfo(session, extra_info=extra_info)
            if not self.db_compatible(dbinfo.get("version", None)):
                raise AngrIncompatibleDBError(
                    "Version {} is incompatible with the current version of angr.".format(dbinfo.get("version", None))
                )

            # Load the loader
            loader = DangrLoaderSerializer.load(session)
            # Create the project
            if extra_info["arch"] is not None and extra_info["auto_load_libs"] is not None:
                proj = Project(loader, arch=extra_info["arch"], load_options={'auto_load_libs': extra_info["auto_load_libs"]})
            else:
                proj = Project(loader, load_options={'auto_load_libs': False})

            if kb_names is None:
                kb_names = ["global"]

            if (len(kb_names) != 1 or kb_names[0] != "global") and other_kbs is None:
                raise ValueError(
                    'You must provide a dict via "other_kbs" to collect angr KnowledgeBases '
                    "that are not the global one."
                )

            # Load knowledgebases
            for kb_name in kb_names:
                kb = KnowledgeBaseSerializer.load(session, proj, kb_name)
                if kb is not None:
                    if kb_name == "global":
                        proj.kb = kb
                    else:
                        other_kbs[kb_name] = kb

            return proj