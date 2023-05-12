# -*- coding: utf-8 -*-
import json
import sqlite3
from secrets import token_bytes

from findex_db import FindexSQLite
from termcolor import colored

from cloudproof_py import cover_crypt, findex

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


if __name__ == "__main__":
    # Creating DB tables
    conn = sqlite3.connect(":memory:")
    # Table to store encrypted data
    conn.execute(sql_create_users_table)
    # Indexing tables required by Findex
    conn.execute(sql_create_entry_table)
    conn.execute(sql_create_chain_table)

    # Initialize CoverCrypt
    policy = cover_crypt.Policy()
    policy.add_axis(
        cover_crypt.PolicyAxis(
            "Country",
            [("France", False), ("Spain", False), ("Germany", False)],
            hierarchical=False,
        )
    )
    policy.add_axis(
        cover_crypt.PolicyAxis(
            "Department",
            [("MKG", False), ("HR", False), ("SEC", False)],
            hierarchical=True,
        )
    )
    cc_interface = cover_crypt.CoverCrypt()
    cc_master_key, cc_public_key = cc_interface.generate_master_keys(policy)

    # Creating user key with different policy access
    key_Alice = cc_interface.generate_user_secret_key(
        cc_master_key,
        "Country::France && Department::MKG",
        policy,
    )

    key_Bob = cc_interface.generate_user_secret_key(
        cc_master_key,
        "(Country::Spain || Country::Germany) && Department::HR",
        policy,
    )

    key_Charlie = cc_interface.generate_user_secret_key(
        cc_master_key,
        "(Country::France || Country::Spain) && Department::SEC",
        policy,
    )

    # Declare encryption scheme
    mapping_field_department = {
        "firstName": "MKG",
        "lastName": "MKG",
        "phone": "HR",
        "email": "HR",
        "country": "HR",
        "region": "HR",
        "employeeNumber": "SEC",
        "security": "SEC",
    }

    # Insert user data to DB + Indexing
    with open("./data.json", "r", encoding="utf-8") as f:
        users = json.load(f)

    # Encryption + Insertion in DB
    user_db_uids = []
    for user in users:
        # Encrypt each column of the user individually
        encrypted_user = [
            cc_interface.encrypt(
                policy,
                f"Country::{user['country']} && Department::{mapping_field_department[col_name]}",
                cc_public_key,
                col_value.encode("utf-8"),
            )
            for col_name, col_value in user.items()
        ]
        db_uid = token_bytes(32)
        user_db_uids.append(db_uid)

        conn.execute(
            """INSERT INTO
            users(id,firstName,lastName, email, phone, country, region, employeeNumber, security)
            VALUES(?,?,?,?,?,?,?,?,?)""",
            (db_uid, *encrypted_user),
        )
    print("CoverCrypt: encryption and db insertion done!")

    # Initialize Findex
    findex_master_key = findex.MasterKey.random()
    findex_label = findex.Label.random()
    findex_interface = FindexSQLite(conn)

    # Mapping of the users database UID to the corresponding keywords (firstname, lastname, etc)
    mapping_indexed_values_to_keywords: findex.typing.IndexedValuesAndKeywords = {
        findex.Location.from_bytes(user_id): [
            keyword.lower() for keyword in user.values()
        ]
        for user_id, user in zip(user_db_uids, users)
    }
    # Upsert keywords
    findex_interface.upsert(
        findex_master_key, findex_label, mapping_indexed_values_to_keywords, {}
    )
    print("Findex: Done indexing", len(users), "users")
    print(
        "Auto completion available: only type the 3 first letters of a word to get results"
    )
    activate_auto_completion = input("Activate search auto completion? [y/n] ") == "y"
    if activate_auto_completion:
        keywords = [keyword.lower() for user in users for keyword in user.values()]
        findex_interface.upsert(
            findex_master_key,
            findex_label,
            findex.utils.generate_auto_completion(keywords),
            {},
        )

    cc_user_keys = {"Alice": key_Alice, "Bob": key_Bob, "Charlie": key_Charlie}

    while True:
        print("\n Available user keys:")
        print("\t Alice: Country::France && Department::MKG")
        print("\t Bob: (Country::Spain || Country::Germany) && Department::HR")
        print("\t Charlie: (Country::France || Country::Spain) && Department::SEC")

        input_user_key = ""
        while input_user_key not in cc_user_keys:
            input_user_key = input(
                "Choose a user key from 'Alice', 'Bob' and 'Charlie': "
            )
        user_key = cc_user_keys[input_user_key]

        print("\n You can now search the database for users by providing keywords")
        print("Examples of words to try: 'Martin', 'France', 'Kalia'")
        keyword = input("Enter a keyword: ").lower()

        # 1. Findex search
        found_users = findex_interface.search(
            findex_master_key, findex_label, [keyword]
        )
        if len(found_users) == 0:
            print(colored("No user found!", "red", attrs=["bold"]))
            continue
        found_users_uids = [bytes(location) for location in found_users[keyword]]

        # 2. Query user database
        str_uids = ",".join("?" * len(found_users_uids))
        cur = conn.execute(
            f"SELECT * FROM users WHERE id IN ({str_uids})",
            found_users_uids,
        )
        encrypted_data = cur.fetchall()

        # 3. Decryption
        print("Query results:")
        for db_user in encrypted_data:
            encrypted_user = db_user[1:]  # skip the uid
            for i, col_name in enumerate(mapping_field_department):
                try:
                    decrypted_value, _ = cc_interface.decrypt(
                        user_key, encrypted_user[i]
                    )
                    print(
                        f"{col_name}: {decrypted_value.decode('utf-8'):12.12}",
                        end=" | ",
                    )
                except Exception:
                    # Our user doesn't have access to this data
                    print(
                        f"{col_name}:",
                        colored("Unauthorized", "red", attrs=["bold"]),
                        end=" | ",
                    )
            print("")
