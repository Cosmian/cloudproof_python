# -*- coding: utf-8 -*-
import sqlite3
from cloudproof_py.findex import Findex, IndexedValue, MasterKey, Label
from cloudproof_py.cover_crypt import (
    Policy,
    PolicyAxis,
    CoverCrypt,
    PublicKey,
    UserSecretKey,
    Attribute,
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


class CloudProofField:
    def __init__(
        self,
        field_name: str,
        col_attributes: List[Attribute],
        row_policy_axis: Optional[PolicyAxis] = None,
        is_searchable: bool = False,
    ):

        self.name = field_name
        self.col_attributes = col_attributes
        self.row_policy_axis = row_policy_axis
        self.is_searchable = is_searchable

    def __repr__(self) -> str:
        return f"""CloudProofField |{self.name}|\
(C{len(self.col_attributes)}\
{f'|R' if self.row_policy_axis else ''}\
{'|Fx' if self.is_searchable else ''})"""


class CloudProofEntry:
    def __init__(
        self,
        scheme: List[CloudProofField],
        CoverCryptInstance: CoverCrypt,
        policy: Policy,
        public_key: PublicKey,
        user_key: UserSecretKey,
    ) -> None:

        self.CoverCryptInstance = CoverCryptInstance
        self.policy = policy
        self.public_key = public_key
        self.user_key = user_key
        self.values: Dict[str, str] = {}

        # used during decryption
        self.ordered_field_names = [field.name for field in scheme]

        self.fields_policy_axis = {}
        self.scheme = {}
        for field in scheme:
            self.scheme[field.name] = field
            if field.row_policy_axis:
                self.fields_policy_axis[field.name] = field.row_policy_axis

    def set_values(self, values: Dict[str, str]):
        for field_name, val in values.items():
            if field_name not in self.scheme:
                raise ValueError(f"{field_name} is an unknown field.")
            self.values[field_name] = val
        return self

    def get_keywords(self) -> List[str]:
        res = []
        for field_name, field_val in self.values.items():
            if self.scheme[field_name].is_searchable:
                res.append(field_val)
        return res

    def encrypt_values(self) -> List[bytes]:
        res = []

        row_attributes = "|| ".join(
            [
                f"{policy_axis}::{self.values[field_name]}"
                for field_name, policy_axis in self.fields_policy_axis.items()
            ]
        )

        for field in self.scheme.values():
            col_attributes = "|| ".join(
                [attr.to_string() for attr in field.col_attributes]
            )

            res.append(
                self.CoverCryptInstance.encrypt(
                    self.policy,
                    f"({row_attributes}) && ({col_attributes})",
                    self.public_key,
                    self.values[field.name].encode("utf-8"),
                )
            )

        return res

    def decrypt_set_values(self, encrypted_data: List[bytes]):
        if len(encrypted_data) != len(self.ordered_field_names):
            raise ValueError("Cannot decrypt data: wrong number of fields")

        for i, field_name in enumerate(self.ordered_field_names):
            try:
                plain_data, _ = self.CoverCryptInstance.decrypt(
                    self.user_key, encrypted_data[i]
                )
                self.values[field_name] = plain_data.decode("utf-8")
            except Exception:
                self.values[field_name] = "Unauthorized"

        return self

    def __repr__(self) -> str:
        if len(self.values) > 0:
            return self.values.__repr__()
        return self.scheme.__repr__()


class CloudProofEntryGenerator:
    def __init__(
        self,
        fields_scheme: List[CloudProofField],
        CoverCryptInstance: CoverCrypt,
        policy: Policy,
        public_key: PublicKey,
        user_key: UserSecretKey,
    ):

        self.fields_scheme = fields_scheme
        self.CoverCryptInstance = CoverCryptInstance
        self.policy = policy
        self.public_key = public_key
        self.user_key = user_key

    def new_entry(self):
        return CloudProofEntry(
            self.fields_scheme,
            self.CoverCryptInstance,
            self.policy,
            self.public_key,
            self.user_key,
        )


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

    def __init__(self) -> None:
        super().__init__()

        # Create database
        self.conn = sqlite3.connect(":memory:")
        create_table(self.conn, sql_create_users_table)
        create_table(self.conn, sql_create_entry_table)
        create_table(self.conn, sql_create_chain_table)

    def insert_users(
        self, new_users: List[CloudProofEntry], uid_size=32
    ) -> List[bytes]:
        db_uids = [randbytes(uid_size) for i in range(len(new_users))]

        flat_entries = []
        for i in range(len(new_users)):
            flat_entries.append((db_uids[i], *new_users[i].encrypt_values()))

        sql_insert_user = """INSERT INTO
            users(id,firstName,lastName, email, phone, country, region, employeeNumber, security)
            VALUES(?,?,?,?,?,?,?,?,?)"""
        cur = self.conn.cursor()
        cur.executemany(sql_insert_user, flat_entries)

        return db_uids

    def fetch_users(
        self, users_id: List[bytes], entry_generator: CloudProofEntryGenerator
    ) -> List[CloudProofEntry]:
        str_uids = ",".join("?" * len(users_id))
        cur = self.conn.execute(
            f"SELECT * FROM users WHERE id IN ({str_uids})",
            users_id,
        )
        values = cur.fetchall()
        res = []
        for user in values:
            res.append(entry_generator.new_entry().decrypt_set_values(user[1:]))
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
        cc_master_key, "Country::France && Department::MKG", policy
    )

    # Declare `data to encrypt` schema
    UserGenerator = CloudProofEntryGenerator(
        [
            CloudProofField(
                field_name="firstName",
                col_attributes=[Attribute("Department", "MKG")],
                is_searchable=True,
            ),
            CloudProofField(
                field_name="lastName",
                col_attributes=[Attribute("Department", "MKG")],
                is_searchable=True,
            ),
            CloudProofField(
                field_name="phone",
                col_attributes=[Attribute("Department", "HR")],
                is_searchable=False,
            ),
            CloudProofField(
                field_name="email",
                col_attributes=[Attribute("Department", "HR")],
                is_searchable=False,
            ),
            CloudProofField(
                field_name="country",
                col_attributes=[Attribute("Department", "HR")],
                row_policy_axis="Country",
                is_searchable=True,
            ),
            CloudProofField(
                field_name="region",
                col_attributes=[Attribute("Department", "HR")],
                is_searchable=True,
            ),
            CloudProofField(
                field_name="employeeNumber",
                col_attributes=[Attribute("Department", "HR")],
                is_searchable=False,
            ),
            CloudProofField(
                field_name="security",
                col_attributes=[Attribute("Department", "HR")],
                is_searchable=False,
            ),
        ],
        CoverCryptInstance,
        policy,
        cc_public_key,
        cc_userkey_fr_hr,
    )

    # User part

    with open("./data.json", "r", encoding="utf-8") as f:
        data = json.load(f)
        users = [UserGenerator.new_entry().set_values(user) for user in data]

    db_server = SQLiteClient()
    db_uids = db_server.insert_users(users)

    res = db_server.fetch_users(db_uids, UserGenerator)

    # Findex

    findex_key = MasterKey.random()
    label = Label.random()

    indexed_values_and_keywords = {
        IndexedValue.from_location(user_id): user.get_keywords()
        for user_id, user in zip(db_uids, users)
    }
    db_server.upsert(indexed_values_and_keywords, findex_key, label)

    found_users = db_server.search(["Martin"], findex_key, label)
    users_id = []
    for user in found_users:
        if user_id := user.get_location():
            users_id.append(user_id)

    print(
        "Result for search: 'Martin' with access `Country::France` and `Department::MKG`:"
    )
    print(db_server.fetch_users(users_id, UserGenerator))
