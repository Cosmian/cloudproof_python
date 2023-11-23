# -*- coding: utf-8 -*-
import os

from cloudproof_py.findex import Findex
from cloudproof_py.findex import Key
from cloudproof_py.findex import Label
from findex_base import FindexBase


class FindexManagedSQLite(FindexBase):
    """No need to implement Findex callbacks using managed backend SQLite."""

    def __init__(self, key: Key, label: Label) -> None:
        super().__init__()

        # Create database
        sqlite_db = "/tmp/cloudproof_findex.sqlite"
        if os.path.exists(sqlite_db):
            os.remove(sqlite_db)

        self.findex = Findex.new_with_sqlite_backend(key, label, sqlite_db, sqlite_db)
