# -*- coding: utf-8 -*-
import sqlite3
from cloudproof_py.findex import Findex, IndexedValue

from typing import Dict, List, Set, Tuple, Optional


class FindexSQLite(Findex.FindexUpsert, Findex.FindexSearch):
    """Implementation of Findex traits for a SQLite backend"""

    def __init__(self, db_conn: sqlite3.Connection) -> None:
        super().__init__()
        self.conn = db_conn

    def fetch_entry_table(self, entry_uids: List[bytes]) -> Dict[bytes, bytes]:
        """Query the entry table

        Args:
            entry_uids List[bytes]: uids to query. if None, return the entire table

        Returns:
            Dict[bytes, bytes]
        """
        str_uids = ",".join("?" * len(entry_uids))
        cur = self.conn.execute(
            f"SELECT uid, value FROM entry_table WHERE uid IN ({str_uids})",
            entry_uids,
        )
        values = cur.fetchall()
        output_dict = {}
        for value in values:
            output_dict[value[0]] = value[1]
        return output_dict

    def fetch_all_entry_table_uids(self) -> Set[bytes]:
        """Return all UIDs in the Entry Table.

        Returns:
            Set[bytes]
        """
        cur = self.conn.execute("SELECT uid FROM entry_table")
        values = cur.fetchall()

        return {value[0] for value in values}

    def fetch_chain_table(self, chain_uids: List[bytes]) -> Dict[bytes, bytes]:
        """Query the chain table

        Args:
            chain_uids (List[bytes]): uids to query

        Returns:
            Dict[bytes, bytes]
        """
        str_uids = ",".join("?" * len(chain_uids))
        cur = self.conn.execute(
            f"SELECT uid, value FROM chain_table WHERE uid IN ({str_uids})", chain_uids
        )
        values = cur.fetchall()
        output_dict = {}
        for v in values:
            output_dict[v[0]] = v[1]
        return output_dict

    def upsert_entry_table(
        self, entry_updates: Dict[bytes, Tuple[bytes, bytes]]
    ) -> Dict[bytes, bytes]:
        """Update key-value pairs in the entry table

        Args:
            entry_updates (Dict[bytes, Tuple[bytes, bytes]]): uid -> (old_value, new_value)

        Returns:
            Dict[bytes, bytes]: entries that failed update (uid -> current value)
        """
        rejected_lines: Dict[bytes, bytes] = {}
        for uid, (old_val, new_val) in entry_updates.items():
            cursor = self.conn.execute(
                """INSERT INTO entry_table(uid,value) VALUES(?,?)
                    ON CONFLICT (uid) DO UPDATE SET value=? WHERE value=?
                """,
                (uid, new_val, new_val, old_val),
            )
            # Insertion has failed
            if cursor.rowcount < 1:
                cursor = self.conn.execute(
                    "SELECT value from entry_table WHERE uid=?", (uid,)
                )
                rejected_lines[uid] = cursor.fetchone()[0]

        return rejected_lines

    def insert_entry_table(self, entries_items: Dict[bytes, bytes]) -> None:
        """Insert new key-value pairs in the entry table

        Args:
            entry_items (Dict[bytes, bytes])
        """
        sql_insert_entry = """INSERT INTO entry_table(uid,value) VALUES(?,?)"""
        self.conn.executemany(
            sql_insert_entry, entries_items.items()
        )  # batch insertions

    def insert_chain_table(self, chain_items: Dict[bytes, bytes]) -> None:
        """Insert new key-value pairs in the chain table

        Args:
            chain_items (Dict[bytes, bytes])
        """
        sql_insert_chain = """INSERT INTO chain_table(uid,value) VALUES(?,?)"""
        self.conn.executemany(sql_insert_chain, chain_items.items())  # batch insertions

    def remove_entry_table(self, entry_uids: Optional[List[bytes]] = None) -> None:
        """Remove entries from entry table

        Args:
            entry_uids (List[bytes], optional): uid of entries to delete.
            if None, delete all entries
        """
        if entry_uids:
            self.conn.executemany(
                "DELETE FROM entry_table WHERE uid = ?", [(uid,) for uid in entry_uids]
            )
        else:
            self.conn.execute("DELETE FROM entry_table")

    def remove_chain_table(self, chain_uids: List[bytes]) -> None:
        """Remove entries from chain table

        Args:
            chain_uids (List[bytes]): uids to remove from the chain table
        """
        self.conn.executemany(
            "DELETE FROM chain_table WHERE uid = ?", [(uid,) for uid in chain_uids]
        )

    def list_removed_locations(self, db_uids: List[bytes]) -> List[bytes]:
        """Check whether uids still exist in the database

        Args:
            db_uids (List[bytes]): uids to check

        Returns:
            List[bytes]: list of uids that were removed
        """
        res = []
        for uid in db_uids:
            cursor = self.conn.execute("SELECT * FROM users WHERE id = ?", (uid,))
            if not cursor.fetchone():
                res.append(uid)
        return res

    def progress_callback(self, results: List[IndexedValue]) -> bool:
        """Intermediate search results

        Args:
            results (List[IndexedValue]): new locations found

        Returns:
            bool: continue recursive search
        """
        return True
