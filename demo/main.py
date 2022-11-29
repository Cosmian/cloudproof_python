# -*- coding: utf-8 -*-
import sqlite3
from cloudproof_py import IFindex, IndexedValue, MasterKey, Label
from typing import Dict, List, Optional


def create_table(conn, create_table_sql):
    try:
        c = conn.cursor()
        c.execute(create_table_sql)
    except sqlite3.Error as e:
        print(e)


sql_create_entry_table = """CREATE TABLE IF NOT EXISTS entry_table (
                                            uid BLOB PRIMARY KEY,
                                            value BLOB NOT NULL
                                        );"""

sql_create_chain_table = """CREATE TABLE IF NOT EXISTS chain_table (
                                            uid BLOB PRIMARY KEY,
                                            value BLOB NOT NULL
                                        );"""


class SQLiteFindex(IFindex):
    def __init__(self) -> None:
        super().__init__()

        # Create database
        self.conn = sqlite3.connect(":memory:")
        create_table(self.conn, sql_create_entry_table)
        create_table(self.conn, sql_create_chain_table)

    def fetch_entry_table(
        self, entry_uids: Optional[List[bytes]] = None
    ) -> Dict[bytes, bytes]:
        """Query the entry table

        Args:
            entry_uids (List[bytes], optional): uids to query. if None, return the entire table

        Returns:
            Dict[bytes, bytes]
        """
        if entry_uids:
            cur = self.conn.cursor()
            str_uids = ",".join("?" * len(entry_uids))
            cur.execute(
                f"SELECT uid, value FROM entry_table WHERE uid IN ({str_uids})",
                entry_uids,
            )
            values = cur.fetchall()
            output_dict = {}
            for value in values:
                output_dict[value[0]] = value[1]
            return output_dict
        return {}

    def fetch_chain_table(self, chain_uids: List[bytes]) -> Dict[bytes, bytes]:
        """Query the chain table

        Args:
            chain_uids (List[bytes]): uids to query

        Returns:
            Dict[bytes, bytes]
        """
        cur = self.conn.cursor()
        str_uids = ",".join("?" * len(chain_uids))
        cur.execute(
            f"SELECT uid, value FROM chain_table WHERE uid IN ({str_uids})", chain_uids
        )
        values = cur.fetchall()
        output_dict = {}
        for v in values:
            output_dict[v[0]] = v[1]
        return output_dict

    def upsert_entry_table(self, entry_items: Dict[bytes, bytes]) -> None:
        """Insert new key-value pairs in the entry table

        Args:
            entry_items (Dict[bytes, bytes])
        """
        sql_insert_entry = (
            """INSERT OR REPLACE INTO entry_table(uid,value) VALUES(?,?)"""
        )
        cur = self.conn.cursor()  # starts implicitly a transaction
        cur.executemany(sql_insert_entry, entry_items.items())  # bulk insertions

    def upsert_chain_table(self, chain_items: Dict[bytes, bytes]) -> None:
        """Insert new key-value pairs in the chain table

        Args:
            chain_items (Dict[bytes, bytes])
        """
        sql_insert_chain = (
            """INSERT OR REPLACE INTO chain_table(uid,value) VALUES(?,?)"""
        )
        cur = self.conn.cursor()  # starts implicitly a transaction
        cur.executemany(sql_insert_chain, chain_items.items())  # bulk insertions

    def remove_entry_table(self, entry_uids: Optional[List[bytes]] = None) -> None:
        """Remove entries from entry table

        Args:
            entry_uids (List[bytes], optional): uid of entries to delete.
            if None, delete all entries
        """
        if entry_uids:
            cur = self.conn.cursor()
            if entry_uids:
                sql_insert_entry = """DELETE FROM entry_table WHERE uid = ?"""
                cur.executemany(sql_insert_entry, entry_uids)
            else:
                cur.execute("DELETE FROM entry_table")

    def remove_chain_table(self, chain_uids: List[bytes]) -> None:
        """Remove entries from chain table

        Args:
            chain_uids (List[bytes]): uids to remove from the chain table
        """
        sql_insert_entry = """DELETE FROM chain_table WHERE uid = ?"""
        cur = self.conn.cursor()
        cur.executemany(sql_insert_entry, chain_uids)

    def list_removed_locations(self, db_uids: List[bytes]) -> List[bytes]:
        """Check wether uids still exist in the database

        Args:
            db_uids (List[bytes]): uids to check

        Returns:
            List[bytes]: list of uids that were removed
        """
        return []

    def progress_callback(self, results: List[IndexedValue]) -> bool:
        """Intermediate search results

        Args:
            results (List[IndexedValue]): new locations found

        Returns:
            bool: continue recursive search
        """
        return True


if __name__ == "__main__":
    mf = SQLiteFindex()

    mk = MasterKey.random()
    label = Label.random()

    db = {
        "1": ["Martin", "Sheperd"],
        "2": ["Martial", "Wilkins"],
        "3": ["John", "Sheperd"],
    }
    mf.upsert(db, mk, label)

    print(mf.search(["Sheperd"], mk, label))
