# -*- coding: utf-8 -*-
import json

import requests
from cloudproof_py.findex import AuthorizationToken
from cloudproof_py.findex import Findex
from cloudproof_py.findex import Key
from cloudproof_py.findex import Label
from findex_base import FindexBase


class FindexManagedRestServer(FindexBase):
    """No need to implement Findex callbacks using managed backend Rest server."""

    def __init__(self, key: Key, label: Label) -> None:
        super().__init__()
        base_url = "http://localhost:8080"
        label = Label.from_string("Hello World!")

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
        key = Key.random()

        token = AuthorizationToken.new(
            index["public_id"],
            key,
            Key.from_bytes(bytes(index["fetch_entries_key"])),
            Key.from_bytes(bytes(index["fetch_chains_key"])),
            Key.from_bytes(bytes(index["upsert_entries_key"])),
            Key.from_bytes(bytes(index["insert_chains_key"])),
        )
        self.findex = Findex.new_with_rest_backend(key, label, str(token), base_url)
