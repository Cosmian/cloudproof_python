# -*- coding: utf-8 -*-
from base64 import b64encode
from typing import Dict
from typing import Set

from cloudproof_py.findex import Findex
from cloudproof_py.findex import Key
from cloudproof_py.findex import PythonCallbacks
from findex_base import FindexBase


class FindexDict(FindexBase):
    """Implement Findex callbacks using dictionaries."""

    # Implement callback functions
    def fetch_entry_table(self, entry_uids: Set[bytes]) -> Dict[bytes, bytes]:
        """Query the Entry Table.

        Args:
            entry_uids (Set[bytes], optional): uids to query. if None, return the entire table

        Returns:
            Dict[bytes, bytes]: uid -> value mapping
        """
        res = {}
        for uid in entry_uids:
            if uid in self.entry_table:
                res[uid] = self.entry_table[uid]
        return res

    def fetch_chain_table(self, chain_uids: Set[bytes]) -> Dict[bytes, bytes]:
        """Query the Chain Table.

        Args:
            chain_uids (Set[bytes]): uids to query

        Returns:
            Dict[bytes, bytes]: uid -> value mapping
        """
        res = {}
        for uid in chain_uids:
            if uid in self.chain_table:
                res[uid] = self.chain_table[uid]
        return res

    def upsert_entry_table(
        self, old_values: Dict[bytes, bytes], new_values: Dict[bytes, bytes]
    ) -> Dict[bytes, bytes]:
        """Update key-value pairs in the entry table
        WARNING: This implementation will not work for concurrency insertions.

        Args:
            old_values (Dict[bytes, bytes]): old entries
            new_values (Dict[bytes, bytes]): new entries

        Returns:
            Dict[bytes, bytes]: entries that failed update (uid -> current value)
        """
        map_old_values = {}
        for uid, value in old_values.items():
            uid_b64 = b64encode(uid).decode("utf-8")
            map_old_values[uid_b64] = value

        rejected_lines: Dict[bytes, bytes] = {}
        for uid, new_val in new_values.items():
            uid_b64 = b64encode(uid).decode("utf-8")
            if uid_b64 in map_old_values:
                old_val = map_old_values[uid_b64]
            else:
                old_val = b""
            if uid in self.entry_table:
                if self.entry_table[uid] == old_val:
                    self.entry_table[uid] = new_val
                else:
                    rejected_lines[uid] = self.entry_table[uid]
            elif not old_val:
                self.entry_table[uid] = new_val
            else:
                raise Exception("Line got deleted in Entry Table")

        return rejected_lines

    def insert_entry_table(self, entries: Dict[bytes, bytes]) -> None:
        """Insert new key-value pairs in the Entry Table.

        Args:
            chain_items (Dict[bytes, bytes]): uid -> value mapping to insert
        """
        for uid, value in entries.items():
            if uid in self.entry_table:
                raise KeyError("Conflict in Entry Table for UID: {uid}")
            self.entry_table[uid] = value

    def insert_chain_table(self, chain_items: Dict[bytes, bytes]) -> None:
        """Insert new key-value pairs in the Chain Table.

        Args:
            chain_items (Dict[bytes, bytes]): uid -> value mapping to insert
        """
        for uid, value in chain_items.items():
            if uid in self.chain_table:
                raise KeyError("Conflict in Chain Table for UID: {uid}")
            self.chain_table[uid] = value

    def delete_entry_table(self, uids: Set[bytes]) -> None:
        """Delete entries according to given uids"""
        for uid in uids:
            self.entry_table.pop(uid)

    def delete_chain_table(self, uids: Set[bytes]) -> None:
        """Delete chains according to given uids"""
        for uid in uids:
            self.chain_table.pop(uid)

    def dump_entry_tokens(self) -> Set[bytes]:
        """Fetch all entries"""
        return Set(self.entry_table.keys())

    def __init__(self, key: Key, label: str) -> None:
        super().__init__()
        # These tables are encrypted and can be stored on a remote server like Redis
        self.entry_table: Dict[bytes, bytes] = {}
        self.chain_table: Dict[bytes, bytes] = {}

        # Instantiate Findex with custom callbacks
        entry_callbacks = PythonCallbacks.new()

        entry_callbacks.set_fetch(self.fetch_entry_table)
        entry_callbacks.set_upsert(self.upsert_entry_table)
        entry_callbacks.set_insert(self.insert_entry_table)
        entry_callbacks.set_delete(self.delete_entry_table)
        entry_callbacks.set_dump_tokens(self.dump_entry_tokens)

        chain_callbacks = PythonCallbacks.new()
        chain_callbacks.set_fetch(self.fetch_chain_table)
        chain_callbacks.set_insert(self.insert_chain_table)
        chain_callbacks.set_delete(self.delete_chain_table)

        self.findex = Findex.new_with_custom_interface(
            key, label, entry_callbacks, chain_callbacks
        )
