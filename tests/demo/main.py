# -*- coding: utf-8 -*-
from findex_db import FindexSQLite
from cloudproof_db import (
    CloudProofEntryGenerator,
    CloudProofField,
    CloudProofKMS,
    CloudProofDatabaseInterface,
)

from cloudproof_py.findex import MasterKey, Label
from cloudproof_py.cover_crypt import (
    Policy,
    PolicyAxis,
    CoverCrypt,
    Attribute,
)
import json
import sqlite3


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

    # Findex
    findex_key = MasterKey.random()
    label = Label.random()

    kms = CloudProofKMS(
        CoverCryptInstance, policy, cc_public_key, cc_userkey_fr_hr, findex_key, label
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
        ]
    )

    # User part
    conn = sqlite3.connect(":memory:")

    with open("./data.json", "r", encoding="utf-8") as f:
        data = json.load(f)
        users = [UserGenerator.new_entry().set_values(user) for user in data]

    db_server = CloudProofDatabaseInterface(
        conn, FindexSQLite(conn), UserGenerator, kms
    )
    db_server.insert_users(users, kms)

    print(db_server.search_users(["Martin"]))
