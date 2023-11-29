# -*- coding: utf-8 -*-
from base64 import b64encode
from typing import Dict
from typing import Set

import redis
from cloudproof_py.findex import Findex
from cloudproof_py.findex import Key
from cloudproof_py.findex import Label
from cloudproof_py.findex import PythonCallbacks
from findex_base import FindexBase


class FindexRedis(FindexBase):
    """Implement Findex callbacks using Redis."""

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
            existing_value = self.redis.get(self.prefix_entry + uid)
            if existing_value:
                res[uid] = existing_value
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
            existing_value = self.redis.get(self.prefix_chain + uid)
            if existing_value:
                res[uid] = existing_value
        return res

    def upsert_entry_table(
        self, old_values: Dict[bytes, bytes], new_values: Dict[bytes, bytes]
    ) -> Dict[bytes, bytes]:
        """Update key-value pairs in the Entry Table.
        WARNING: This implementation will not work for concurrency insertions.

        Args:
            entry_updates (Dict[bytes, Tuple[bytes, bytes]]): uid -> (old_value, new_value)

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
            existing_value = self.redis.get(self.prefix_entry + uid)
            if existing_value:
                if existing_value == old_val:
                    self.redis.set(self.prefix_entry + uid, new_val)
                else:
                    rejected_lines[uid] = existing_value
            elif not old_val:
                self.redis.set(self.prefix_entry + uid, new_val)
            else:
                raise Exception("Line got deleted in Entry Table")

        return rejected_lines

    def insert_chain_table(self, chain_items: Dict[bytes, bytes]) -> None:
        """Insert new key-value pairs in the Chain Table.

        Args:
            chain_items (Dict[bytes, bytes]): uid -> value mapping to insert
        """
        for uid, value in chain_items.items():
            if self.redis.exists(self.prefix_chain + uid):
                raise KeyError("Conflict in Chain Table for UID: {uid}")
            self.redis.set(self.prefix_chain + uid, value)

    def __init__(self, key: Key, label: Label) -> None:
        super().__init__()
        self.redis = redis.Redis()

        # The encrypted tables
        self.prefix_entry = b"entry:"
        self.prefix_chain = b"chain:"

        # Instantiate Findex with custom callbacks
        entry_callbacks = PythonCallbacks.new()

        entry_callbacks.set_fetch(self.fetch_entry_table)
        entry_callbacks.set_upsert(self.upsert_entry_table)
        # entry_callbacks.set_insert(self.insert_entry_table) # not implemented yet
        # entry_callbacks.set_delete(self.delete_entry_table) # not implemented yet
        # entry_callbacks.set_dump_tokens(self.dump_entry_tokens) # not implemented yet

        chain_callbacks = PythonCallbacks.new()
        chain_callbacks.set_fetch(self.fetch_chain_table)
        chain_callbacks.set_insert(self.insert_chain_table)
        # chain_callbacks.set_delete(self.delete_chain_table) # not implemented yet

        self.findex = Findex.new_with_custom_backend(
            key, label, entry_callbacks, chain_callbacks
        )
