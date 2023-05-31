# -*- coding: utf-8 -*-
from cloudproof_py.findex import Findex

from typing import Dict, List, Tuple, Sequence
import redis


class FindexRedis(Findex.FindexUpsert, Findex.FindexSearch):
    """Implement Findex callbacks using Redis."""

    def __init__(self) -> None:
        super().__init__()
        self.redis = redis.Redis()

        self.prefix_entry = b"entry:"
        self.prefix_chain = b"chain:"

    # Implement callback functions
    def fetch_entry_table(
        self, entry_uids: List[bytes]
    ) -> Sequence[Tuple[bytes, bytes]]:
        """Query the Entry Table.

        Args:
            entry_uids (List[bytes], optional): uids to query. if None, return the entire table

        Returns:
            Sequence[Tuple[bytes, bytes]]: uid -> value mapping
        """
        res = []
        for uid in entry_uids:
            existing_value = self.redis.get(self.prefix_entry + uid)
            if existing_value:
                res.append((uid, existing_value))
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
            existing_value = self.redis.get(self.prefix_chain + uid)
            if existing_value:
                res[uid] = existing_value
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
