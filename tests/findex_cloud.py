# -*- coding: utf-8 -*-
import json

import requests

from cloudproof_py.findex import FindexCloud, Label, Location

if __name__ == "__main__":
    base_url = "http://localhost:8080"
    label = Label.from_string("Hello World!")

    # Creating the index on the backend
    try:
        response = requests.post(f"{base_url}/indexes", json={"name": "test"})
    except requests.exceptions.ConnectionError:
        raise Exception(
            "Findex Cloud docker should be running on your local machine to run this test!"
        )

    if response.status_code != 200:
        raise Exception("Error while creating indexes in Findex Cloud!")

    # Creating access token
    index = json.loads(response.text)
    token = FindexCloud.generate_new_token(
        index["public_id"],
        bytes(index["fetch_entries_key"]),
        bytes(index["fetch_chains_key"]),
        bytes(index["upsert_entries_key"]),
        bytes(index["insert_chains_key"]),
    )

    # Upsert data
    FindexCloud.upsert(
        {
            Location.from_string("42"): ["John", "Doe"],
            Location.from_string("38"): ["Jane", "Doe"],
        },
        token,
        label,
        base_url=base_url,
    )

    # Search for keyword 'Doe'
    res = FindexCloud.search(["Doe"], token, label, base_url=base_url)
    assert len(res["Doe"]) == 2

    print("Results:", res)
