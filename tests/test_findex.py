# -*- coding: utf-8 -*-
import json
import os
import sqlite3
import unittest
from base64 import b64decode
from base64 import b64encode
from typing import Dict
from typing import List
from typing import Optional
from typing import Set

from cloudproof_py.findex import Findex
from cloudproof_py.findex import Key
from cloudproof_py.findex import Keyword
from cloudproof_py.findex import Location
from cloudproof_py.findex import PythonCallbacks
from cloudproof_py.findex.typing import IndexedValuesAndKeywords
from cloudproof_py.findex.typing import ProgressResults
from cloudproof_py.findex.utils import generate_auto_completion


def create_table(conn: sqlite3.Connection, create_table_sql: str) -> None:
    """create Findex 2 tables and another table for Users"""
    try:
        conn.execute(create_table_sql)
    except sqlite3.Error as e:
        print(e)


SQL_CREATE_USERS_TABLE = """CREATE TABLE IF NOT EXISTS users (
                                            id BLOB PRIMARY KEY,
                                            firstName text NOT NULL,
                                            lastName text NOT NULL
                                        );"""


SQL_CREATE_ENTRY_TABLE = """CREATE TABLE IF NOT EXISTS entry_table (
                                            uid BLOB PRIMARY KEY,
                                            value BLOB NOT NULL
                                        );"""

SQL_CREATE_CHAIN_TABLE = """CREATE TABLE IF NOT EXISTS chain_table (
                                            uid BLOB PRIMARY KEY,
                                            value BLOB NOT NULL
                                        );"""


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

    def insert_entry_table(self, entry_items: Dict[bytes, bytes]) -> None:
        """Insert new key-value pairs in the entry table

        Args:
            entry_items (Dict[bytes, bytes])
        """
        sql_insert_entry = """INSERT INTO entry_table(uid,value) VALUES(?,?)"""
        self.conn.executemany(sql_insert_entry, entry_items.items())  # batch insertions

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
        entry_callbacks.set_insert(self.insert_entry_table)
        entry_callbacks.set_delete(self.delete_entry_table)
        entry_callbacks.set_dump_tokens(self.dump_entry_tokens)

        chain_callbacks = PythonCallbacks.new()
        chain_callbacks.set_fetch(self.fetch_chain_table)
        chain_callbacks.set_insert(self.insert_chain_table)
        chain_callbacks.set_delete(self.delete_chain_table)

        self.findex = Findex.new_with_custom_interface(
            key, label, entry_callbacks, chain_callbacks
        )

    def insert_users(self, new_users: Dict[bytes, List[str]]) -> None:
        """Insert users in SQLite database"""
        flat_entries = [(id, *val) for id, val in new_users.items()]
        sql_insert_user = """INSERT INTO users(id,firstName,lastName) VALUES(?,?,?)"""
        cur = self.conn.cursor()
        cur.executemany(sql_insert_user, flat_entries)

    def remove_users(self, users_id: Set[bytes]) -> None:
        """Delete users from SQLite database"""
        sql_rm_user = """DELETE FROM users WHERE id = ?"""
        cur = self.conn.cursor()
        cur.executemany(sql_rm_user, [(id,) for id in users_id])

    def get_num_lines(self, db_table: str) -> int:
        """Get number of lines of given table"""
        return int(self.conn.execute(f"SELECT COUNT(*) from {db_table};").fetchone()[0])


class TestFindexSQLite(unittest.TestCase):
    def setUp(self) -> None:
        # Init db tables
        self.conn = sqlite3.connect(":memory:")
        create_table(self.conn, SQL_CREATE_USERS_TABLE)
        create_table(self.conn, SQL_CREATE_ENTRY_TABLE)
        create_table(self.conn, SQL_CREATE_CHAIN_TABLE)
        # Init Findex objects
        self.findex_key = Key.random()
        self.label = "My public label"
        self.interface = FindexSQLite(self.findex_key, self.label, self.conn)

        self.users = {
            b"1": ["Martin", "Sheperd"],
            b"2": ["Martial", "Wilkins"],
            b"3": ["John", "Sheperd"],
        }
        self.interface.insert_users(self.users)

    def test_sqlite_upsert_graph(self) -> None:
        # Simple insertion
        indexed_values_and_keywords: IndexedValuesAndKeywords = {
            Location.from_bytes(key): value for key, value in self.users.items()
        }
        inserted_kw = self.interface.findex.add(indexed_values_and_keywords)
        self.assertEqual(len(inserted_kw), 5)

        res = self.interface.findex.search(["Sheperd"])
        self.assertEqual(len(res["Sheperd"]), 2)
        self.assertEqual(self.interface.get_num_lines("entry_table"), 5)
        self.assertEqual(self.interface.get_num_lines("chain_table"), 5)

        # Generate and upsert graph

        keywords_list = [item for sublist in self.users.values() for item in sublist]
        graph = generate_auto_completion(keywords_list)
        self.interface.findex.add(graph)

        self.assertEqual(self.interface.get_num_lines("entry_table"), 18)
        self.assertEqual(self.interface.get_num_lines("chain_table"), 18)

        res = self.interface.findex.search(["Mar"])
        # 2 names starting with Mar
        self.assertEqual(len(res["Mar"]), 2)

        res = self.interface.findex.search(
            [Keyword.from_string("Mar"), Keyword.from_string("She")],
        )
        # all names starting with Mar or She
        self.assertEqual(len(res[Keyword.from_string("Mar")]), 2)
        self.assertEqual(len(res[Keyword.from_string("She")]), 2)

        # test process callback
        def early_stop_progress_callback(res: ProgressResults) -> bool:
            if "Martin" in res:
                return True
            return False

        res = self.interface.findex.search(
            ["Mar"],
            interrupt=early_stop_progress_callback,
        )

        # only one location found after early stopping
        self.assertEqual(len(res["Mar"]), 1)

    def test_sqlite_compact(self) -> None:
        indexed_values_and_keywords: IndexedValuesAndKeywords = {
            Location.from_bytes(key): value for key, value in self.users.items()
        }
        self.interface.findex.add(indexed_values_and_keywords)

        res = self.interface.findex.search(["Sheperd"])
        self.assertEqual(len(res["Sheperd"]), 2)

        # Remove one line in the database before compacting
        self.interface.remove_users(set([b"1"]))
        new_label = "My new public label"
        new_key = Key.random()

        def filter_obsolete_data(locations: Set[Location]) -> Set[Location]:
            """Check whether the given `Locations` still exist.

            Args:
                locations (List[Location]): `Locations` to check

            Returns:
                List[Location]: list of `Locations` that were removed
            """
            res = set()
            for uid in locations:
                cursor = self.conn.execute(
                    "SELECT * FROM users WHERE id = ?", (bytes(uid),)
                )
                if not cursor.fetchone():
                    res.add(uid)
            return res

        self.interface.findex.compact(new_key, new_label, 1, filter_obsolete_data)

        self.interface = FindexSQLite(new_key, new_label, self.conn)

        # only one result left for `Sheperd`
        res = self.interface.findex.search(["Sheperd"])
        self.assertEqual(len(res["Sheperd"]), 1)


class TestFindexNonRegressionTest(unittest.TestCase):
    def setUp(self) -> None:
        # Init Findex objects
        self.findex_key = Key.from_bytes(b64decode("6hb1TznoNQFvCWisGWajkA=="))
        self.label = "Some Label"

        with open("./tests/data/users.json", encoding="utf-8") as f:
            self.users = json.load(f)

    def test_create_non_regression_file(self) -> None:
        # Create DB tables
        conn = sqlite3.connect("./tests/data/export/sqlite.db")
        conn.execute("DROP TABLE IF EXISTS entry_table")
        conn.execute("DROP TABLE IF EXISTS chain_table")
        create_table(conn, SQL_CREATE_ENTRY_TABLE)
        create_table(conn, SQL_CREATE_CHAIN_TABLE)
        conn.commit()

        interface = FindexSQLite(self.findex_key, self.label, conn)

        # Create indexed entries for users and upsert them
        new_indexed_entries: IndexedValuesAndKeywords = {
            Location.from_int(id): [str(user[k]) for k in list(user.keys())[1:]]
            for id, user in enumerate(self.users)
        }
        interface.findex.add(new_indexed_entries)
        conn.commit()

        # Check the insertion is successful
        res = interface.findex.search(["France"])
        self.assertEqual(len(res["France"]), 30)

        conn.close()

    def verify(self, db_file: str) -> None:
        """internal function to verify test vectors"""
        conn = sqlite3.connect(db_file)
        interface = FindexSQLite(self.findex_key, self.label, conn)

        # Verify search results
        res = interface.findex.search(["France"])
        self.assertEqual(len(res["France"]), 30)

        # Upsert a single user
        new_user_entry: IndexedValuesAndKeywords = {
            Location.from_int(10000): [
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
        interface.findex.add(new_user_entry)

        # Another search
        res = interface.findex.search(["France"])
        self.assertEqual(len(res["France"]), 31)

        conn.close()

    def test_check_non_regression_files(self) -> None:
        """Check non regression test vectors"""
        test_folder = "./tests/data/findex/non_regression/"
        for filename in os.listdir(test_folder):
            if filename[-2:] == "db":
                self.verify(os.path.join(test_folder, filename))
                print(filename, "successfully tested")


if __name__ == "__main__":
    unittest.main()
