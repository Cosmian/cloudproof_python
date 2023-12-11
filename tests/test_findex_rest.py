# -*- coding: utf-8 -*-
import json
import unittest
from base64 import b64decode

import requests
from cloudproof_py.findex import AuthorizationToken
from cloudproof_py.findex import Findex
from cloudproof_py.findex import Key
from cloudproof_py.findex import Location


class TestFindexRest(unittest.TestCase):
    def test_add_and_search(self) -> None:
        base_url = "http://localhost:8080"
        label = "Hello World!"

        # Creating the index on the backend
        try:
            response = requests.post(
                f"{base_url}/indexes", json={"name": "test"}, timeout=10
            )
        except requests.exceptions.ConnectionError:
            raise Exception(
                "Findex Cloud docker should be running on your local machine to run this test!"
            )

        if response.status_code != 200:
            raise Exception("Error while creating indexes in Findex Cloud!")

        # Creating access token
        index = json.loads(response.text)
        key = Key.from_bytes(b64decode("6hb1TznoNQFvCWisGWajkA=="))

        token = AuthorizationToken.new(
            index["public_id"],
            key,
            Key.from_bytes(bytes(index["fetch_entries_key"])),
            Key.from_bytes(bytes(index["fetch_chains_key"])),
            Key.from_bytes(bytes(index["upsert_entries_key"])),
            Key.from_bytes(bytes(index["insert_chains_key"])),
        )
        findex = Findex.new_with_rest_interface(label, str(token), base_url)

        # Upsert data
        findex.add(
            {
                Location.from_string("42"): ["John", "Doe"],
                Location.from_string("38"): ["Jane", "Doe"],
            }
        )

        # Search for keyword 'Doe'
        res = findex.search(["Doe"])
        assert len(res["Doe"]) == 2


if __name__ == "__main__":
    unittest.main()
