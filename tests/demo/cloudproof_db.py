# -*- coding: utf-8 -*-
from typing import List, Optional, Dict
from cloudproof_py.cover_crypt import (
    Policy,
    PolicyAxis,
    CoverCrypt,
    PublicKey,
    UserSecretKey,
    Attribute,
)
from cloudproof_py.findex import Findex, Label, MasterKey, IndexedValue
import sqlite3
from random import randbytes


class CloudProofKMS:
    def __init__(
        self,
        cc_instance: CoverCrypt,
        cc_policy: Policy,
        cc_public_key: PublicKey,
        cc_user_key: UserSecretKey,
        findex_master_key: MasterKey,
        findex_label: Label,
    ) -> None:
        self.cc_instance = cc_instance
        self.cc_policy = cc_policy
        self.cc_public_key = cc_public_key
        self.cc_user_key = cc_user_key

        self.findex_master_key = findex_master_key
        self.findex_label = findex_label


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
    def __init__(self, scheme: List[CloudProofField]) -> None:
        self.values: Dict[str, str] = {}
        self.db_uid: Optional[bytes] = None

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

    def encrypt_values(self, kms: CloudProofKMS) -> List[bytes]:
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
                kms.cc_instance.encrypt(
                    kms.cc_policy,
                    f"({row_attributes}) && ({col_attributes})",
                    kms.cc_public_key,
                    self.values[field.name].encode("utf-8"),
                )
            )

        return res

    def decrypt_set_values(self, kms: CloudProofKMS, encrypted_data: List[bytes]):
        if len(encrypted_data) != len(self.ordered_field_names):
            raise ValueError("Cannot decrypt data: wrong number of fields")

        for i, field_name in enumerate(self.ordered_field_names):
            try:
                plain_data, _ = kms.cc_instance.decrypt(
                    kms.cc_user_key, encrypted_data[i]
                )
                self.values[field_name] = plain_data.decode("utf-8")
            except Exception:
                self.values[field_name] = "Unauthorized"

        return self

    def set_db_uid(self, uid: bytes):
        self.db_uid = uid

    def __repr__(self) -> str:
        if len(self.values) > 0:
            return self.values.__repr__()
        return self.scheme.__repr__()


class CloudProofEntryGenerator:
    def __init__(self, fields_scheme: List[CloudProofField]):
        self.fields_scheme = fields_scheme

    def new_entry(self):
        return CloudProofEntry(self.fields_scheme)


# TODO: Extract sql statement out of this class
class CloudProofDatabaseInterface:
    def __init__(
        self,
        db_conn: sqlite3.Connection,
        findex_interface: Findex.FindexTrait,
        entry_generator: CloudProofEntryGenerator,
        kms: CloudProofKMS,
    ) -> None:
        self.conn = db_conn
        self.findex_interface = findex_interface
        self.entry_generator = entry_generator
        self.kms = kms

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
        try:
            self.conn.execute(sql_create_users_table)
        except sqlite3.Error as e:
            print(e)

    def insert_users(
        self,
        new_users: List[CloudProofEntry],
        kms: CloudProofKMS,
        uid_size=32,
    ) -> None:
        db_uids = [randbytes(uid_size) for i in range(len(new_users))]

        flat_entries = []
        for i in range(len(new_users)):
            new_users[i].set_db_uid(db_uids[i])
            flat_entries.append((db_uids[i], *new_users[i].encrypt_values(self.kms)))

        # Insert users in DB

        sql_insert_user = """INSERT INTO
            users(id,firstName,lastName, email, phone, country, region, employeeNumber, security)
            VALUES(?,?,?,?,?,?,?,?,?)"""
        cur = self.conn.cursor()
        cur.executemany(sql_insert_user, flat_entries)

        # Insert keywords in DB
        indexed_values_and_keywords = {
            IndexedValue.from_location(user_id): user.get_keywords()
            for user_id, user in zip(db_uids, new_users)
        }
        self.findex_interface.upsert(
            indexed_values_and_keywords, kms.findex_master_key, kms.findex_label
        )

    def fetch_users(self, users_id: List[bytes]) -> List[CloudProofEntry]:
        str_uids = ",".join("?" * len(users_id))
        cur = self.conn.execute(
            f"SELECT * FROM users WHERE id IN ({str_uids})",
            users_id,
        )
        values = cur.fetchall()
        res = []
        for user in values:
            res.append(
                self.entry_generator.new_entry().decrypt_set_values(self.kms, user[1:])
            )
        return res

    def remove_users(self, users_id: List[bytes]) -> None:
        sql_rm_user = """DELETE FROM users WHERE id = ?"""
        cur = self.conn.cursor()
        cur.executemany(sql_rm_user, [(id,) for id in users_id])

    def search_users(self, keywords: List[str]) -> List[CloudProofEntry]:
        found_users = self.findex_interface.search(
            keywords, self.kms.findex_master_key, self.kms.findex_label
        )
        user_ids = []
        for user in found_users:
            if user_id := user.get_location():
                user_ids.append(user_id)

        return self.fetch_users(user_ids)
