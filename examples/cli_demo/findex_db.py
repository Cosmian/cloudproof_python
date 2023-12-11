# -*- coding: utf-8 -*-
import sqlite3
from base64 import b64encode
from typing import Dict
from typing import Optional
from typing import Set

from cloudproof_py.findex import Findex
from cloudproof_py.findex import Key
from cloudproof_py.findex import PythonCallbacks


class FindexSQLite:
    # Start implementing Findex methods

    def fetch_entry_table(self, entry_uids: Set[bytes]) -> Dict[bytes, bytes]:
        """Query the entry table

        Args:
            entry_uids (Set[bytes]): uids to query. if None, return the entire table

        Returns:
            Dict[bytes, bytes]
        """
        str_uids = ",".join("?" * len(entry_uids))
        cur = self.conn.execute(
            f"SELECT uid, value FROM entry_table WHERE uid IN ({str_uids})",
            list(entry_uids),
        )
        values = cur.fetchall()
        output_dict = {}
        for value in values:
            output_dict[value[0]] = value[1]
        return output_dict

    def dump_entry_tokens(self) -> Set[bytes]:
        """Return all UIDs in the Entry Table.

        Returns:
            Set[bytes]
        """
        cur = self.conn.execute("SELECT uid FROM entry_table")
        values = cur.fetchall()

        return {value[0] for value in values}

    def fetch_chain_table(self, chain_uids: Set[bytes]) -> Dict[bytes, bytes]:
        """Query the chain table

        Args:
            chain_uids (Set[bytes]): uids to query

        Returns:
            Dict[bytes, bytes]
        """
        str_uids = ",".join("?" * len(chain_uids))
        cur = self.conn.execute(
            f"SELECT uid, value FROM chain_table WHERE uid IN ({str_uids})",
            list(chain_uids),
        )
        values = cur.fetchall()
        output_dict = {}
        for v in values:
            output_dict[v[0]] = v[1]
        return output_dict

    def upsert_entry_table(
        self, old_values: Dict[bytes, bytes], new_values: Dict[bytes, bytes]
    ) -> Dict[bytes, bytes]:
        """Update key-value pairs in the entry table

        Args:
            old_values (Dict[bytes, bytes]): old entries
            new_values (Dict[bytes, bytes]): new entries

        Returns:
            Dict[bytes, bytes]: entries that failed update (uid -> current value)
        """
        # print("upsert_entry_table")
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

    def insert_chain_table(self, chain_items: Dict[bytes, bytes]) -> None:
        """Insert new key-value pairs in the chain table

        Args:
            chain_items (Dict[bytes, bytes])
        """
        sql_insert_chain = """INSERT INTO chain_table(uid,value) VALUES(?,?)"""
        self.conn.executemany(sql_insert_chain, chain_items.items())  # batch insertions

    def delete_entry_table(self, entry_uids: Optional[Set[bytes]] = None) -> None:
        """Delete entries from entry table

        Args:
            entry_uids (Set[bytes], optional): uid of entries to delete.
            if None, delete all entries
        """
        if entry_uids:
            self.conn.executemany(
                "DELETE FROM entry_table WHERE uid = ?", [(uid,) for uid in entry_uids]
            )
        else:
            self.conn.execute("DELETE FROM entry_table")

    def delete_chain_table(self, chain_uids: Set[bytes]) -> None:
        """Delete entries from chain table

        Args:
            chain_uids (Set[bytes]): uids to remove from the chain table
        """
        self.conn.executemany(
            "DELETE FROM chain_table WHERE uid = ?", [(uid,) for uid in chain_uids]
        )

    # End findex trait implementation

    def __init__(self, key: Key, label: str, conn: sqlite3.Connection) -> None:
        # super().__init__()

        # Create database
        self.conn = conn

        # Instantiate Findex with custom callbacks
        entry_callbacks = PythonCallbacks.new()

        entry_callbacks.set_fetch(self.fetch_entry_table)
        entry_callbacks.set_upsert(self.upsert_entry_table)
        entry_callbacks.set_delete(self.delete_entry_table)
        entry_callbacks.set_dump_tokens(self.dump_entry_tokens)

        chain_callbacks = PythonCallbacks.new()
        chain_callbacks.set_fetch(self.fetch_chain_table)
        chain_callbacks.set_insert(self.insert_chain_table)
        chain_callbacks.set_delete(self.delete_chain_table)

        self.findex = Findex.new_with_custom_interface(
            key, label, entry_callbacks, chain_callbacks
        )
