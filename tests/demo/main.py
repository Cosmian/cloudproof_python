# -*- coding: utf-8 -*-
import sqlite3
from cloudproof_py.findex import Findex, IndexedValue, MasterKey, Label
from cloudproof_py.cover_crypt import (
    Policy,
    PolicyAxis,
    CoverCrypt,
    PublicKey,
    UserSecretKey,
)
from typing import Dict, List, Optional, Tuple
from random import random
import json
from random import randbytes


def create_table(conn, create_table_sql):
    try:
        c = conn.cursor()
        c.execute(create_table_sql)
    except sqlite3.Error as e:
        print(e)


sql_create_users_table = """CREATE TABLE IF NOT EXISTS users (
                                            id BLOB PRIMARY KEY,
                                            firstName BLOB NOT NULL,
                                            lastName BLOB NOT NULL,
                                            email BLOB NOT NULL,
                                            phone BLOB NOT NULL,
                                            country BLOB NOT NULL,
                                            region BLOB NOT NULL,
                                            employeeNumber BLOB NOT NULL,
                                            security BLOB NOT NULL

                                        );"""


sql_create_entry_table = """CREATE TABLE IF NOT EXISTS entry_table (
                                            uid BLOB PRIMARY KEY,
                                            value BLOB NOT NULL
                                        );"""

sql_create_chain_table = """CREATE TABLE IF NOT EXISTS chain_table (
                                            uid BLOB PRIMARY KEY,
                                            value BLOB NOT NULL
                                        );"""


class CCEncrypt:
    country_list = set(["France", "Spain", "Germany"])
    department_fields = {
        "firstName": "MKG",
        "lastName": "MKG",
        "phone": "HR",
        "email": "HR",
        "country": "HR",
        "region": "HR",
        "employeeNumber": "HR",
        "security": "HR",
    }

    def __init__(
        self,
        CoverCryptInstance: CoverCrypt,
        policy: Policy,
        public_key: PublicKey,
        user_key: UserSecretKey,
    ):
        self.CoverCryptInstance = CoverCryptInstance
        self.public_key = public_key
        self.policy = policy
        self.user_key = user_key

    def encrypt_user(self, user: Dict[str, str]) -> List[bytes]:
        res = []
        if not user["country"] in CCEncrypt.country_list:
            raise ValueError(
                f"The user country: {user['country']} is not specified in the Policy."
            )

        for field_name, value in user.items():
            if field_name not in CCEncrypt.department_fields:
                raise ValueError(
                    f"The user field: {field_name} does not belong to any Attribute."
                )
            res.append(
                self.CoverCryptInstance.encrypt(
                    policy,
                    f"""Country::{user['country']} &&
                    Department::{CCEncrypt.department_fields[field_name]}""",
                    self.public_key,
                    value.encode("utf-8"),
                )
            )

        return res

    def decrypt_user(self, user: List[bytes]) -> Dict[str, str]:
        res: Dict[str, str] = {}

        if len(CCEncrypt.department_fields) != len(user):
            raise ValueError("Cannot decrypt user: wrong number of fields")

        for i, field_name in enumerate(CCEncrypt.department_fields):
            try:
                plain_data, _ = self.CoverCryptInstance.decrypt(self.user_key, user[i])
                res[field_name] = plain_data.decode("utf-8")
            except Exception:
                res[field_name] = "Unauthorized"

        return res


class SQLiteClient(Findex.FindexTrait):
    # Start implementing Findex methods

    def fetch_entry_table(
        self, entry_uids: Optional[List[bytes]] = None
    ) -> Dict[bytes, bytes]:
        """Query the entry table

        Args:
            entry_uids (List[bytes], optional): uids to query. if None, return the entire table

        Returns:
            Dict[bytes, bytes]
        """
        cur = self.conn.cursor()
        if entry_uids:
            str_uids = ",".join("?" * len(entry_uids))
            cur.execute(
                f"SELECT uid, value FROM entry_table WHERE uid IN ({str_uids})",
                entry_uids,
            )
        else:
            cur.execute("SELECT uid, value FROM entry_table")

        values = cur.fetchall()
        output_dict = {}
        for value in values:
            output_dict[value[0]] = value[1]
        return output_dict

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
            if random() < 0.5:
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
            else:
                rejected_lines[uid] = new_val

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
        """Check wether uids still exist in the database

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

    # End findex implementation

    def __init__(self, cc_encrypt: CCEncrypt) -> None:
        super().__init__()

        self.cc_encrypt = cc_encrypt

        # Create database
        self.conn = sqlite3.connect(":memory:")
        create_table(self.conn, sql_create_users_table)
        create_table(self.conn, sql_create_entry_table)
        create_table(self.conn, sql_create_chain_table)

    def insert_users(self, new_users: List[Dict[str, str]], uid_size=32) -> List[bytes]:
        db_uids = [randbytes(uid_size) for i in range(len(new_users))]

        flat_entries = []
        for i in range(len(new_users)):
            flat_entries.append(
                (db_uids[i], *self.cc_encrypt.encrypt_user(new_users[i]))
            )

        sql_insert_user = """INSERT INTO
            users(id,firstName,lastName, email, phone, country, region, employeeNumber, security)
            VALUES(?,?,?,?,?,?,?,?,?)"""
        cur = self.conn.cursor()
        cur.executemany(sql_insert_user, flat_entries)

        return db_uids

    def fetch_users(self, users_id: List[bytes]):
        str_uids = ",".join("?" * len(users_id))
        cur = self.conn.execute(
            f"SELECT * FROM users WHERE id IN ({str_uids})",
            users_id,
        )
        values = cur.fetchall()
        res = []
        for user in values:
            res.append(self.cc_encrypt.decrypt_user(user[1:]))
        return res

    def remove_users(self, users_id: List[bytes]) -> None:
        sql_rm_user = """DELETE FROM users WHERE id = ?"""
        cur = self.conn.cursor()
        cur.executemany(sql_rm_user, [(id,) for id in users_id])

    def get_num_lines(self, db_table: str) -> int:
        return self.conn.execute(f"SELECT COUNT(*) from {db_table};").fetchone()[0]


if __name__ == "__main__":
    # Admin part
    policy = Policy()
    policy.add_axis(
        PolicyAxis(
            "Country",
            ["France", "Spain", "Germany"],
            hierarchical=False,
        )
    )
    policy.add_axis(
        PolicyAxis(
            "Department", ["MKG", "HR"], hierarchical=True
        )  # HR can access mkg data about users
    )

    CoverCryptInstance = CoverCrypt()
    cc_master_key, cc_public_key = CoverCryptInstance.generate_master_keys(policy)

    cc_userkey_fr_hr = CoverCryptInstance.generate_user_secret_key(
        cc_master_key, "Country::France && Department::HR", policy
    )

    # User part
    cc_encrypt = CCEncrypt(CoverCryptInstance, policy, cc_public_key, cc_userkey_fr_hr)

    db_server = SQLiteClient(cc_encrypt)

    with open("./data.json", "r", encoding="utf-8") as f:
        users = json.load(f)

    db_uids = db_server.insert_users(users)

    print(db_server.fetch_users(db_uids))

    # Findex

    findex_key = MasterKey.random()
    label = Label.random()

    indexed_values_and_keywords = {
        IndexedValue.from_location(user_id): list(user.values())
        for user_id, user in zip(db_uids, users)
    }
    db_server.upsert(indexed_values_and_keywords, findex_key, label)

    found_users = db_server.search(["Felix"], findex_key, label)
    users_id = []
    for user in found_users:
        if user_id := user.get_location():
            users_id.append(user_id)

    print(
        "Result for search: 'Felix' with access `Country::France` and `Department::HR`"
    )
    print(db_server.fetch_users(users_id))
