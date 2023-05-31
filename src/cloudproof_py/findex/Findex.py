# -*- coding: utf-8 -*-
from abc import ABCMeta, abstractmethod
from typing import Callable, Dict, List, Optional, Sequence, Set, Tuple, Union

from cloudproof_findex import (
    IndexedValuesAndKeywords,
    InternalFindex,
    Keyword,
    Label,
    Location,
    MasterKey,
    ProgressResults,
    SearchResults,
)


class FindexBase(metaclass=ABCMeta):
    def __init__(self) -> None:
        self.findex_core = InternalFindex()


class FindexUpsert(FindexBase, metaclass=ABCMeta):
    """Implement this class to use Findex Upsert API"""

    def __init__(self) -> None:
        super().__init__()
        self.findex_core.set_upsert_callbacks(
            self.fetch_entry_table,
            self.upsert_entry_table,
            self.insert_chain_table,
        )

    def upsert(
        self,
        master_key: MasterKey,
        label: Label,
        additions: IndexedValuesAndKeywords,
        deletions: IndexedValuesAndKeywords,
    ) -> None:
        """Upserts the given relations between `IndexedValue` and `Keyword` into Findex tables.

        Args:
            master_key (MasterKey): the user master key
            label (Label): label used to allow versioning
            additions (Dict[Location | Keyword, List[Keyword | str]]):
                map of `IndexedValue` to a list of `Keyword` to add to the index
            deletions (Dict[Location | Keyword, List[Keyword | str]]):
                map of `IndexedValue` to a list of `Keyword` to delete from the index
        """
        self.findex_core.upsert_wrapper(master_key, label, additions, deletions)

    @abstractmethod
    def fetch_entry_table(
        self, entry_uids: List[bytes]
    ) -> Sequence[Tuple[bytes, bytes]]:
        """Query the Entry Table.

        Args:
            entry_uids (List[bytes], optional): uids to query. if None, return the entire table

        Returns:
           Sequence[Tuple[bytes, bytes]]: uid -> value mapping
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
            chain_items (Dict[bytes, bytes]): uid -> value mapping to insert
        """


class FindexSearch(FindexBase, metaclass=ABCMeta):
    """Implement this class to use Findex Search API"""

    def __init__(self) -> None:
        super().__init__()
        self.findex_core.set_search_callbacks(
            self.fetch_entry_table, self.fetch_chain_table
        )

    @abstractmethod
    def fetch_entry_table(
        self, entry_uids: List[bytes]
    ) -> Sequence[Tuple[bytes, bytes]]:
        """Query the Entry Table.

        Args:
            entry_uids (List[bytes], optional): uids to query. if None, return the entire table

        Returns:
            Sequence[Tuple[bytes, bytes]]: uid -> value mapping
        """

    @abstractmethod
    def fetch_chain_table(self, chain_uids: List[bytes]) -> Dict[bytes, bytes]:
        """Query the Chain Table.

        Args:
            chain_uids (List[bytes]): uids to query

        Returns:
            Dict[bytes, bytes]: uid -> value mapping
        """

    def search(
        self,
        master_key: MasterKey,
        label: Label,
        keywords: Sequence[Union[Keyword, str]],
        progress_callback: Optional[Callable[[ProgressResults], bool]] = None,
    ) -> SearchResults:
        """Recursively search Findex graphs for `Locations` corresponding to the given `Keyword`.

        Args:
            keywords (List[Keyword | str]): keywords to search using Findex.
            master_key (MasterKey): user secret key.
            label (Label): public label used in keyword hashing.
            progress_callback (Callable[[Dict[str, List[IndexedValue]]], bool], optional): callback
                to process intermediate search results.

        Returns:
            Dict[Keyword, List[Location]]: `Locations` found by `Keyword`
        """
        return self.findex_core.search_wrapper(
            master_key,
            label,
            keywords,
            progress_callback,
        )


class FindexCompact(FindexBase, metaclass=ABCMeta):
    """Implement this class to use Findex Compact API"""

    def __init__(self) -> None:
        super().__init__()
        self.findex_core.set_compact_callbacks(
            self.fetch_entry_table,
            self.fetch_chain_table,
            self.update_lines,
            self.list_removed_locations,
            self.fetch_all_entry_table_uids,
        )

    @abstractmethod
    def fetch_entry_table(
        self, entry_uids: List[bytes]
    ) -> Sequence[Tuple[bytes, bytes]]:
        """Query the Entry Table.

        Args:
            entry_uids (List[bytes]): uids to query

        Returns:
            Sequence[Tuple[bytes, bytes]]: uid -> value mapping
        """

    @abstractmethod
    def fetch_all_entry_table_uids(self) -> Set[bytes]:
        """Return all UIDs in the Entry Table.

        Returns:
            Set[bytes]: uid set
        """

    @abstractmethod
    def fetch_chain_table(self, chain_uids: List[bytes]) -> Dict[bytes, bytes]:
        """Query the Chain Table.

        Args:
            chain_uids (List[bytes]): uids to query

        Returns:
            Dict[bytes, bytes]: uid -> value mapping
        """

    @abstractmethod
    def insert_chain_table(self, chain_items: Dict[bytes, bytes]) -> None:
        """Insert new key-value pairs in the Chain Table.

        Args:
            chain_items (Dict[bytes, bytes]): uid -> value mapping to insert
        """

    @abstractmethod
    def insert_entry_table(self, entries_items: Dict[bytes, bytes]) -> None:
        """Insert new key-value pairs in the Entry Table.

        Args:
            entries_items (Dict[bytes, bytes]): uid -> value mapping to insert
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
    def list_removed_locations(self, locations: List[Location]) -> List[Location]:
        """Check whether the given `Locations` still exist.

        Args:
            locations (List[Location]): `Locations` to check

        Returns:
            List[Location]: list of `Locations` that were removed
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
        master_key: MasterKey,
        new_master_key: MasterKey,
        new_label: Label,
        num_reindexing_before_full_set: int,
    ) -> None:
        """Performs compacting on the entry and chain tables.

        Args:
            num_reindexing_before_full_set (int): number of compacting to do before
            being sure that a big portion of the indexes were checked
            master_key (MasterKey): current master key
            new_master_key (MasterKey): newly generated key
            new_label (Label): newly generated label
        """
        self.findex_core.compact_wrapper(
            master_key, new_master_key, new_label, num_reindexing_before_full_set
        )
