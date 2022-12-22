# -*- coding: utf-8 -*-
from cloudproof_py.findex import Findex

from typing import Dict, List, Tuple


class FindexDict(Findex.FindexUpsert, Findex.FindexSearch):
    """Implement Findex callbacks using dictionaries"""

    def __init__(self) -> None:
        super().__init__()
        # These tables are encrypted and can be stored on a remote server like Redis
        self.entry_table: Dict[bytes, bytes] = {}
        self.chain_table: Dict[bytes, bytes] = {}

    # Implement callback functions
    def fetch_entry_table(self, entry_uids: List[bytes]) -> Dict[bytes, bytes]:
        """Query the Entry Table.

        Args:
            entry_uids (List[bytes], optional): uids to query. if None, return the entire table

        Returns:
            Dict[bytes, bytes]: uid -> value mapping
        """
        res = {}
        for uid in entry_uids:
            if uid in self.entry_table:
                res[uid] = self.entry_table[uid]
        return res

    def fetch_chain_table(self, chain_uids: List[bytes]) -> Dict[bytes, bytes]:
        """Query the Chain Table.

        Args:
            chain_uids (List[bytes]): uids to query

        Returns:
            Dict[bytes, bytes]: uid -> value mapping
        """
        res = {}
        for uid in chain_uids:
            if uid in self.chain_table:
                res[uid] = self.chain_table[uid]
        return res

    def upsert_entry_table(
        self, entry_updates: Dict[bytes, Tuple[bytes, bytes]]
    ) -> Dict[bytes, bytes]:
        """Update key-value pairs in the Entry Table.
        WARNING: This implementation will not work for concurrency insertions.

        Args:
            entry_updates (Dict[bytes, Tuple[bytes, bytes]]): uid -> (old_value, new_value)

        Returns:
            Dict[bytes, bytes]: entries that failed update (uid -> current value)
        """
        rejected_lines = {}
        for uid, (old_val, new_val) in entry_updates.items():
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

    def insert_chain_table(self, chain_items: Dict[bytes, bytes]) -> None:
        """Insert new key-value pairs in the Chain Table.

        Args:
            chain_items (Dict[bytes, bytes]): uid -> value mapping to insert
        """
        for uid, value in chain_items.items():
            if uid in self.chain_table:
                raise KeyError("Conflict in Chain Table for UID: {uid}")
            self.chain_table[uid] = value
