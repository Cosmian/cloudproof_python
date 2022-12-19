# -*- coding: utf-8 -*-
from abc import ABCMeta, abstractmethod
from typing import Dict, List, Optional, Tuple
from cosmian_findex import IndexedValue, Label, MasterKey, InternalFindex


class FindexUpsert(InternalFindex, metaclass=ABCMeta):
    """Implement this class to use Findex Upsert API"""

    def __new__(cls, *args, **kargs):
        # allow constructor args without passing them to InternalFindex
        return InternalFindex.__new__(cls)

    def __init__(self) -> None:
        super().__init__()
        self.set_upsert_callbacks(
            self.fetch_entry_table,
            self.fetch_chain_table,
            self.upsert_entry_table,
            self.insert_chain_table,
        )

    def upsert(
        self,
        dict_indexed_values: Dict[IndexedValue, List[str]],
        master_key: MasterKey,
        label: Label,
    ) -> None:
        """Upserts the given relations between `IndexedValue` and `KeyWord` into Findex tables.

        Args:
            dict_indexed_values (Dict[bytes, List[bytes]]): map of `IndexedValue`
                                                            to a list of `Keyword`
            master_key (MasterKey): the user master key
            label (Label): label used to allow versioning
        """
        self.upsert_wrapper(dict_indexed_values, master_key, label)

    @abstractmethod
    def fetch_entry_table(
        self, entry_uids: Optional[List[bytes]] = None
    ) -> Dict[bytes, bytes]:
        """Query the Entry Table.

        Args:
            entry_uids (List[bytes], optional): uids to query. if None, return the entire table

        Returns:
            Dict[bytes, bytes]
        """

    @abstractmethod
    def fetch_chain_table(self, chain_uids: List[bytes]) -> Dict[bytes, bytes]:
        """Query the Chain Table.

        Args:
            chain_uids (List[bytes]): uids to query

        Returns:
            Dict[bytes, bytes]
        """

    @abstractmethod
    def upsert_entry_table(
        self, entry_updates: Dict[bytes, Tuple[bytes, bytes]]
    ) -> Dict[bytes, bytes]:
        """Update key-value pairs in the Entry Table.

        Args:
            entry_updates (Dict[bytes, Tuple[bytes, bytes]]): uid -> (old_value, new_value)

        Returns:
            Dict[bytes, bytes]: entries that failed update (uid -> current value)
        """

    @abstractmethod
    def insert_chain_table(self, chain_items: Dict[bytes, bytes]) -> None:
        """Insert new key-value pairs in the Chain Table.

        Args:
            chain_items (Dict[bytes, bytes])
        """


class FindexSearch(InternalFindex, metaclass=ABCMeta):
    """Implement this class to use Findex Search API"""

    def __new__(cls, *args, **kargs):
        return InternalFindex.__new__(cls)

    def __init__(self) -> None:
        super().__init__()
        self.set_search_callbacks(
            self.fetch_entry_table, self.fetch_chain_table, self.progress_callback
        )

    @abstractmethod
    def fetch_entry_table(
        self, entry_uids: Optional[List[bytes]] = None
    ) -> Dict[bytes, bytes]:
        """Query the Entry Table.

        Args:
            entry_uids (List[bytes], optional): uids to query. if None, return the entire table

        Returns:
            Dict[bytes, bytes]
        """

    @abstractmethod
    def fetch_chain_table(self, chain_uids: List[bytes]) -> Dict[bytes, bytes]:
        """Query the Chain Table.

        Args:
            chain_uids (List[bytes]): uids to query

        Returns:
            Dict[bytes, bytes]
        """

    @abstractmethod
    def progress_callback(self, results: List[IndexedValue]) -> bool:
        """Intermediate search results.

        Args:
            results (List[IndexedValue]): new locations found

        Returns:
            bool: continue recursive search
        """

    def search(
        self,
        keywords: List[str],
        master_key: MasterKey,
        label: Label,
        max_result_per_keyword: int = 2**32 - 1,
        max_depth: int = 100,
    ) -> Dict[str, List[IndexedValue]]:
        """Recursively search Findex graphs for `Location` corresponding to the given `KeyWord`.

        Args:
            keywords (List[str]): keywords to search using Findex
            master_key (MasterKey): user secret key
            label (Label): public label used in keyword hashing
            max_result_per_keyword (int, optional): maximum number of results to fetch per keyword.
            max_depth (int, optional): maximum recursion level allowed. Defaults to 100.

        Returns:
            List[IndexedValue]: `IndexedValue` found for the given `Keyword`
        """
        return self.search_wrapper(
            keywords, master_key, label, max_result_per_keyword, max_depth
        )


class FindexCompact(InternalFindex, metaclass=ABCMeta):
    """Implement this class to use Findex Compact API"""

    def __new__(cls, *args, **kargs):
        return InternalFindex.__new__(cls)

    def __init__(self) -> None:
        super().__init__()
        self.set_compact_callbacks(
            self.fetch_entry_table,
            self.fetch_chain_table,
            self.update_lines,
            self.list_removed_locations,
        )

    @abstractmethod
    def fetch_entry_table(
        self, entry_uids: Optional[List[bytes]] = None
    ) -> Dict[bytes, bytes]:
        """Query the Entry Table.

        Args:
            entry_uids (List[bytes], optional): uids to query. if None, return the entire table

        Returns:
            Dict[bytes, bytes]
        """

    @abstractmethod
    def fetch_chain_table(self, chain_uids: List[bytes]) -> Dict[bytes, bytes]:
        """Query the Chain Table.

        Args:
            chain_uids (List[bytes]): uids to query

        Returns:
            Dict[bytes, bytes]
        """

    @abstractmethod
    def insert_chain_table(self, chain_items: Dict[bytes, bytes]) -> None:
        """Insert new key-value pairs in the Chain Table.

        Args:
            chain_items (Dict[bytes, bytes])
        """

    @abstractmethod
    def insert_entry_table(self, entries_items: Dict[bytes, bytes]) -> None:
        """Insert new key-value pairs in the Entry Table.

        Args:
            entries_items (Dict[bytes, bytes])
        """

    @abstractmethod
    def remove_entry_table(self, entry_uids: Optional[List[bytes]] = None) -> None:
        """Remove entries from Entry Table.

        Args:
            entry_uids (List[bytes], optional): uid of entries to delete. if None,
                delete all entries
        """

    @abstractmethod
    def remove_chain_table(self, chain_uids: List[bytes]) -> None:
        """Remove entries from Chain Table.

        Args:
            chain_uids (List[bytes]): uids to remove from the chain table
        """

    @abstractmethod
    def list_removed_locations(self, locations: List[bytes]) -> List[bytes]:
        """Check whether the given `Locations` still exist.

        Args:
            locations (List[bytes]): `Locations` to check

        Returns:
            List[bytes]: list of `Locations` that were removed
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

        - removes all the Entry Table;
        - removes `chain_table_uids_to_remove` from the Chain Table;
        - inserts `new_chain_table_items` into the Chain Table;
        - inserts `new_entry_table_items` into the Entry Table.

        The order of these operations is not important but has some
        implications. This implementation keeps the database small but prevents
        using the index during the `update_lines`.

        Override this method if you want another implementation, e.g. :

        1. saves all Entry Table UIDs;
        2. inserts `new_chain_table_items` into the Chain Table;
        3. inserts `new_entry_table_items` into the Entry Table;
        4. publish new label to users;
        5. remove old lines from the Entry Table (using the saved UIDs in 1.);
        6. removes `chain_table_uids_to_remove` from the Chain Table.

        With this implementation, the index tables are much bigger during a small duration,
        but users can continue using the index during the `update_lines`.
        """

        self.remove_entry_table()
        self.remove_chain_table(removed_chain_table_uids)
        self.insert_chain_table(new_encrypted_chain_table_items)
        self.insert_entry_table(new_encrypted_entry_table_items)

    def compact(
        self,
        num_reindexing_before_full_set: int,
        master_key: MasterKey,
        new_master_key: MasterKey,
        new_label: Label,
    ) -> None:
        """Performs compacting on the entry and chain tables.

        Args:
            num_reindexing_before_full_set (int): number of compacting to do before
            being sure that a big portion of the indexes were checked
            master_key (MasterKey): current master key
            new_master_key (MasterKey): newly generated key
            new_label (Label): newly generated label
        """
        self.compact_wrapper(
            num_reindexing_before_full_set, master_key, new_master_key, new_label
        )
