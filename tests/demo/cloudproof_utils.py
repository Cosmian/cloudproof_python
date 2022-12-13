# -*- coding: utf-8 -*-
from typing import List, Optional, Dict
import sqlite3
from random import randbytes
from copy import deepcopy
from termcolor import colored

from cloudproof_py.cover_crypt import (
    Policy,
    CoverCrypt,
    PublicKey,
    UserSecretKey,
    Attribute,
)
from cloudproof_py.findex import Findex, Label, MasterKey, IndexedValue


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


class CloudProofValue:
    def __init__(self):
        self.has_decryption_failed: bool = False
        self.data: Optional[str] = None

    def set_data(self, val: str):
        self.has_decryption_failed = False
        self.data = val

    def __repr__(self) -> str:
        if self.has_decryption_failed:
            return colored("Unauthorized", "red", attrs=["bold"])
        if self.data:
            return self.data
        return ""


class CloudProofField:
    def __init__(
        self,
        field_name: str,
        col_attributes: List[Attribute],
        row_policy_axis: Optional[str] = None,
        is_searchable: bool = False,
    ):

        self.name = field_name
        self.col_attributes = [attr.to_string() for attr in col_attributes]
        self.row_policy_axis = row_policy_axis
        self.is_searchable = is_searchable
        self.value = CloudProofValue()

    def get_value(self) -> str:
        if self.value.has_decryption_failed or self.value.data is None:
            raise ValueError("CloudProofField '{self.name}' has no value")
        return self.value.data

    def set_value(self, val: str) -> None:
        self.value.set_data(val)

    def __repr__(self) -> str:
        return f"""{self.name}: {self.value}"""


class CloudProofEntry:
    def __init__(self, scheme: List[CloudProofField]) -> None:
        # self.values: Dict[str, str] = {}
        self.db_uid: Optional[bytes] = None

        # used during decryption
        self.ordered_field_names = [field.name for field in scheme]

        self.fields_policy_axis = {}
        self.fields = {}
        for field in scheme:
            self.fields[field.name] = field
            if field.row_policy_axis:
                self.fields_policy_axis[field.name] = field.row_policy_axis

    def set_values(self, values: Dict[str, str]):
        for field_name, val in values.items():
            if field_name not in self.fields:
                raise ValueError(f"{field_name} is an unknown field.")
            self.fields[field_name].set_value(val)
        return self

    def get_keywords(self) -> List[str]:
        res = []
        for field in self.fields.values():
            if field.is_searchable:
                res.append(field.get_value())
        return res

    def encrypt_values(self, kms: CloudProofKMS) -> List[bytes]:
        res = []
        row_attributes = "|| ".join(
            [
                f"{policy_axis}::{self.fields[field_name].get_value()}"
                for field_name, policy_axis in self.fields_policy_axis.items()
            ]
        )

        for field in self.fields.values():
            col_attributes = "|| ".join(field.col_attributes)

            res.append(
                kms.cc_instance.encrypt(
                    kms.cc_policy,
                    f"({row_attributes}) && ({col_attributes})",
                    kms.cc_public_key,
                    self.fields[field.name].get_value().encode("utf-8"),
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
                self.fields[field_name].set_value(plain_data.decode("utf-8"))
            except Exception:
                self.fields[field_name].value.has_decryption_failed = True

        return self

    def set_db_uid(self, uid: bytes):
        self.db_uid = uid

    def __repr__(self) -> str:
        return " | ".join([field.__repr__() for field in self.fields.values()])


class CloudProofEntryGenerator:
    def __init__(self, fields_scheme: List[CloudProofField]):
        self.fields_scheme = fields_scheme

    def new_entry(self):
        return CloudProofEntry(deepcopy(self.fields_scheme))


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
        uid_size=32,
    ) -> None:
        db_uids = [randbytes(uid_size) for i in range(len(new_users))]

        flat_entries = []
        for i, new_user in enumerate(new_users):
            new_user.set_db_uid(db_uids[i])
            flat_entries.append((db_uids[i], *new_user.encrypt_values(self.kms)))

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
            indexed_values_and_keywords,
            self.kms.findex_master_key,
            self.kms.findex_label,
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
        unique_users = set(
            [
                indexed_value
                for sublist in found_users.values()
                for indexed_value in sublist
            ]
        )
        user_ids = []
        for user in unique_users:
            if user_id := user.get_location():
                user_ids.append(user_id)

        return self.fetch_users(user_ids)
