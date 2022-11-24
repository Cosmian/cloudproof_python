# -*- coding: utf-8 -*-
from abc import ABCMeta, abstractmethod
from typing import Dict, List, Optional
from cosmian_findex import IndexedValue, Label, MasterKey, PyFindex


class IFindex(metaclass=ABCMeta):
    def __init__(self) -> None:
        self.findex = PyFindex(
            self.fetch_entry_table,
            self.fetch_chain_table,
            self.upsert_entry_table,
            self.upsert_chain_table,
            self.update_lines,
            self.list_removed_locations,
            self.progress_callback,
        )

    def upsert(self, dict_indexed_values, master_key, label) -> None:
        self.findex.upsert_wrapper(dict_indexed_values, master_key, label)

    def graph_upsert(self, dict_indexed_values, master_key, label) -> None:
        self.findex.graph_upsert_wrapper(dict_indexed_values, master_key, label)

    def search(
        self,
        keywords: List[str],
        master_key: MasterKey,
        label: Label,
        max_result_per_keyword: int = 2**32 - 1,
        max_depth: int = 100,
    ) -> List[IndexedValue]:
        return self.findex.search_wrapper(
            keywords, master_key, label, max_result_per_keyword, max_depth
        )

    def compact(
        self, num_reindexing_before_full_set, master_key, new_master_key, new_label
    ) -> None:
        self.findex.compact_wrapper(
            num_reindexing_before_full_set, master_key, new_master_key, new_label
        )

    @abstractmethod
    def fetch_entry_table(
        self, entry_uids: Optional[List[bytes]] = None
    ) -> Dict[bytes, bytes]:
        """Query the entry table

        Args:
            entry_uids (List[bytes], optional): uids to query.
            if None, return the entire table

        Returns:
            Dict[bytes, bytes]
        """

    @abstractmethod
    def fetch_chain_table(self, chain_uids: List[bytes]) -> Dict[bytes, bytes]:
        """Query the chain table

        Args:
            chain_uids (List[bytes]): uids to query

        Returns:
            Dict[bytes, bytes]
        """

    @abstractmethod
    def upsert_entry_table(self, entry_items: Dict[bytes, bytes]) -> None:
        """Insert new key-value pairs in the entry table

        Args:
            entry_items (Dict[bytes, bytes])
        """

    @abstractmethod
    def upsert_chain_table(self, chain_items: Dict[bytes, bytes]) -> None:
        """Insert new key-value pairs in the chain table

        Args:
            chain_items (Dict[bytes, bytes])
        """

    @abstractmethod
    def remove_entry_table(self, entry_uids: Optional[List[bytes]] = None) -> None:
        """Remove entries from entry table

        Args:
            entry_uids (List[bytes], optional): uid of entries to delete.
            if None, delete all entries
        """

    @abstractmethod
    def remove_chain_table(self, chain_uids: List[bytes]) -> None:
        """Remove entries from chain table

        Args:
            chain_uids (List[bytes]): uids to remove from the chain table
        """

    @abstractmethod
    def list_removed_locations(self, db_uids: List[bytes]) -> List[bytes]:
        """Check wether uids still exist in the database

        Args:
            db_uids (List[bytes]): uids to check

        Returns:
            List[bytes]: list of uids that were removed
        """

    @abstractmethod
    def progress_callback(self, results: List[IndexedValue]) -> bool:
        """Intermediate search results

        Args:
            results (List[IndexedValue]): new locations found

        Returns:
            bool: continue recursive search
        """

    def update_lines(
        self,
        removed_chain_table_uids: List[bytes],
        new_encrypted_entry_table_items: Dict[bytes, bytes],
        new_encrypted_chain_table_items: Dict[bytes, bytes],
    ) -> None:
        """Example implementation of the compact callback

        Update the database with the new values.
        This function should:

        - remove all the Index Entry Table
        - add `new_encrypted_entry_table_items` to the Index Entry Table
        - remove `removed_chain_table_uids` from the Index Chain Table
        - add `new_encrypted_chain_table_items` to the Index Chain Table

        The order of these operation is not important but have some
        implications. This implementation keep the database small but prevent
        using the index during the `update_lines`.

        Other possibility:

        During a small duration, the index tables are much bigger but users can
        continue using the index during the `update_lines`.

        1. save all UIDs from the current Index Entry Table
        2. add `new_encrypted_entry_table_items` to the Index Entry Table
        3. add `new_encrypted_chain_table_items` to the Index Chain Table
        4. publish new label to users
        5. remove old lines from the Index Entry Table (using the saved UIDs in 1.)
        6. remove `removed_chain_table_uids` from the Index Chain Table

        """

        self.remove_entry_table()
        self.upsert_entry_table(new_encrypted_entry_table_items)
        self.remove_chain_table(removed_chain_table_uids)
        self.upsert_chain_table(new_encrypted_chain_table_items)
