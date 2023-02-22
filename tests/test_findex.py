# -*- coding: utf-8 -*-
import sqlite3
from cloudproof_py.findex import Findex, IndexedValue, MasterKey, Label
from cloudproof_py.findex.utils import generate_auto_completion
from typing import Dict, List, Optional, Set, Tuple
import unittest
import json
from base64 import b64decode
import os


def create_table(conn, create_table_sql):
    try:
        conn.execute(create_table_sql)
    except sqlite3.Error as e:
        print(e)


sql_create_users_table = """CREATE TABLE IF NOT EXISTS users (
                                            id BLOB PRIMARY KEY,
                                            firstName text NOT NULL,
                                            lastName text NOT NULL
                                        );"""


sql_create_entry_table = """CREATE TABLE IF NOT EXISTS entry_table (
                                            uid BLOB PRIMARY KEY,
                                            value BLOB NOT NULL
                                        );"""

sql_create_chain_table = """CREATE TABLE IF NOT EXISTS chain_table (
                                            uid BLOB PRIMARY KEY,
                                            value BLOB NOT NULL
                                        );"""


class FindexSQLite(Findex.FindexUpsert, Findex.FindexSearch, Findex.FindexCompact):
    # Start implementing Findex methods

    def fetch_entry_table(self, entry_uids: List[bytes]) -> Dict[bytes, bytes]:
        """Query the entry table

        Args:
            entry_uids (List[bytes]): uids to query. if None, return the entire table

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

    def list_removed_locations(self, locations: List[bytes]) -> List[bytes]:
        """Check wether uids still exist in the database

        Args:
            db_uids (List[bytes]): uids to check

        Returns:
            List[bytes]: list of uids that were removed
        """
        res = []
        for uid in locations:
            cursor = self.conn.execute("SELECT * FROM users WHERE id = ?", (uid,))
            if not cursor.fetchone():
                res.append(uid)
        return res

    # End findex trait implementation

    def __init__(self, conn: sqlite3.Connection) -> None:
        super().__init__()

        # Create database
        self.conn = conn

    def insert_users(self, new_users: Dict[bytes, List[str]]) -> None:
        flat_entries = [(id, *val) for id, val in new_users.items()]
        sql_insert_user = """INSERT INTO users(id,firstName,lastName) VALUES(?,?,?)"""
        cur = self.conn.cursor()
        cur.executemany(sql_insert_user, flat_entries)

    def remove_users(self, users_id: List[bytes]) -> None:
        sql_rm_user = """DELETE FROM users WHERE id = ?"""
        cur = self.conn.cursor()
        cur.executemany(sql_rm_user, [(id,) for id in users_id])

    def get_num_lines(self, db_table: str) -> int:
        return self.conn.execute(f"SELECT COUNT(*) from {db_table};").fetchone()[0]


class TestFindexSQLite(unittest.TestCase):
    def setUp(self) -> None:
        # Init db tables
        conn = sqlite3.connect(":memory:")
        create_table(conn, sql_create_users_table)
        create_table(conn, sql_create_entry_table)
        create_table(conn, sql_create_chain_table)
        # Init Findex objects
        self.interface = FindexSQLite(conn)
        self.mk = MasterKey.random()
        self.label = Label.random()

        self.users = {
            b"1": ["Martin", "Sheperd"],
            b"2": ["Martial", "Wilkins"],
            b"3": ["John", "Sheperd"],
        }
        self.interface.insert_users(self.users)

    def test_sqlite_upsert_graph(self) -> None:
        # Simple insertion

        indexed_values_and_keywords = {
            IndexedValue.from_location(key): value for key, value in self.users.items()
        }
        self.interface.upsert(indexed_values_and_keywords, self.mk, self.label)

        res = self.interface.search(["Sheperd"], self.mk, self.label)
        self.assertEqual(len(res["Sheperd"]), 2)
        self.assertEqual(self.interface.get_num_lines("entry_table"), 5)
        self.assertEqual(self.interface.get_num_lines("chain_table"), 5)

        # Generate and upsert graph

        keywords_list = [item for sublist in self.users.values() for item in sublist]
        graph = generate_auto_completion(keywords_list)
        self.interface.upsert(graph, self.mk, self.label)

        self.assertEqual(self.interface.get_num_lines("entry_table"), 18)
        self.assertEqual(self.interface.get_num_lines("chain_table"), 18)

        res = self.interface.search(["Mar"], self.mk, self.label)
        # 2 names starting with Mar
        self.assertEqual(len(res["Mar"]), 2)

        res = self.interface.search(["Mar", "She"], self.mk, self.label)
        # all names starting with Mar or She
        self.assertEqual(len(res["Mar"]), 2)
        self.assertEqual(len(res["She"]), 2)

        # test process callback
        def early_stop_progress_callback(res: Dict[str, List[IndexedValue]]):
            if "Martin" in res:
                return False
            return True

        res = self.interface.search(
            ["Mar"],
            self.mk,
            self.label,
            progress_callback=early_stop_progress_callback,
        )
        # only one location found after early stopping
        self.assertEqual(len(res["Mar"]), 1)

    def test_sqlite_compact(self) -> None:
        indexed_values_and_keywords = {
            IndexedValue.from_location(key): value for key, value in self.users.items()
        }
        self.interface.upsert(indexed_values_and_keywords, self.mk, self.label)

        # Remove one line in the database before compacting
        self.interface.remove_users([b"1"])
        new_label = Label.random()
        new_mk = MasterKey.random()
        self.interface.compact(1, self.mk, new_mk, new_label)

        # only one result left for `Sheperd`
        res = self.interface.search(["Sheperd"], new_mk, new_label)
        self.assertEqual(len(res), 1)

        # searching with old label will fail
        res = self.interface.search(["Sheperd"], new_mk, self.label)
        self.assertEqual(len(res), 0)

        # searching with old key will fail
        res = self.interface.search(["Sheperd"], self.mk, new_label)
        self.assertEqual(len(res), 0)


class TestFindexNonRegressionTest(unittest.TestCase):
    def setUp(self) -> None:
        # Init Findex objects
        self.mk = MasterKey.from_bytes(b64decode("6hb1TznoNQFvCWisGWajkA=="))
        self.label = Label.from_bytes(b"Some Label")

        with open("./tests/data/users.json") as f:
            self.users = json.load(f)

    def test_create_non_regression_file(self) -> None:
        # Create DB tables
        conn = sqlite3.connect("./tests/data/export/sqlite.db")
        conn.execute("DROP TABLE IF EXISTS entry_table")
        conn.execute("DROP TABLE IF EXISTS chain_table")
        create_table(conn, sql_create_entry_table)
        create_table(conn, sql_create_chain_table)
        conn.commit()

        self.interface = FindexSQLite(conn)

        # Create indexed entries for users and upsert them
        new_indexed_entries = {
            IndexedValue.from_location((id + 1).to_bytes(8, "big")): [
                str(user[k]) for k in list(user.keys())[1:]
            ]
            for id, user in enumerate(self.users)
        }
        self.interface.upsert(new_indexed_entries, self.mk, self.label)
        conn.commit()

        # Check the insertion is successful
        res = self.interface.search(["France"], self.mk, self.label)
        self.assertEqual(len(res["France"]), 30)

        conn.close()

    def verify(self, db_file: str) -> None:
        conn = sqlite3.connect(db_file)
        self.interface = FindexSQLite(conn)

        # Verify search results
        res = self.interface.search(["France"], self.mk, self.label)
        self.assertEqual(len(res["France"]), 30)

        # Upsert a single user
        new_user_entry = {
            IndexedValue.from_location(b"10000"): [
                "another first name",
                "another last name",
                "another phone",
                "another email",
                "France",
                "another region",
                "another employee number",
                "confidential",
            ]
        }
        self.interface.upsert(new_user_entry, self.mk, self.label)

        # Another search
        res = self.interface.search(["France"], self.mk, self.label)
        self.assertEqual(len(res["France"]), 31)

        conn.close()

    def test_check_non_regression_files(self) -> None:
        test_folder = "./tests/data/findex/non_regression/"
        for filename in os.listdir(test_folder):
            if filename[-2:] == "db":
                self.verify(os.path.join(test_folder, filename))
                print(filename, "successfully tested")


if __name__ == "__main__":
    unittest.main()
