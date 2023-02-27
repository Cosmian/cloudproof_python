# -*- coding: utf-8 -*-
import argparse
from typing import Dict, List, Union

from findex_dict import FindexDict
from findex_redis import FindexRedis
from findex_sqlite import FindexSQLite

from cloudproof_py.findex import MasterKey, Label, IndexedValue, Findex, utils

# Simple database containing the firstname and lastname of each user.
# Each line has a corresponding UID: 1, 2 or 3.
data = {
    "1": ["Martin", "Shepherd"],
    "2": ["Martial", "Wilkins"],
    "3": ["John", "Shepherd"],
}


def main(backend: str = "Dict"):
    print("Database to index:", data)

    # Initialize a symmetric key
    master_key = MasterKey.random()

    # Initialize a random label
    label = Label.random()

    # Instance the class implementing the required callbacks
    findex_interface: Union[Findex.FindexUpsert, Findex.FindexSearch]
    if backend == "Redis":
        findex_interface = FindexRedis()
    elif backend == "SQLite":
        findex_interface = FindexSQLite()
    else:
        findex_interface = FindexDict()

    # Create the index
    indexed_values_and_keywords = {}
    for uid, keywords in data.items():
        # Convert database UIDs to IndexedValue expected by Findex
        location = IndexedValue.from_location(uid.encode("utf-8"))
        # This location has 2 keywords associated: the firstname and lastname
        indexed_values_and_keywords[location] = keywords

    # Upsert in Findex
    findex_interface.upsert(indexed_values_and_keywords, master_key, label)

    # Search
    keywords_to_search = ["Shepherd", "John"]
    found_locations = findex_interface.search(keywords_to_search, master_key, label)

    print("Locations found by keyword:")
    for keyword, locations in found_locations.items():
        print("\t", keyword, ":", locations)

    # The keyword `Shepherd` points to the lines 1 and 3 of the database.
    # `John` only points to the line 3.

    # Adding alias:
    # Keywords can point to Locations but also to other Keywords, thus generating a graph.

    # Create the alias `Joe` for `John`
    alias_graph = {
        IndexedValue.from_keyword(b"John"): ["Joe"],
    }
    findex_interface.upsert(alias_graph, master_key, label)

    # Now searching `Joe` will return the same location as `John`
    print("Search with aliases:")
    print("\t", findex_interface.search(["Joe"], master_key, label))

    # Generate an auto-completion graph:
    # For example, with the word `Wilkins`, one could upsert the following aliases:
    # ["Wil" => "Wilk", "Wilk" => "Wilki", "Wilki" => "Wilkin", "Wilkin" => "Wilkins"].
    # A search for the Keyword "Wil" will then return the Location of `Wilkins`.

    # CloudProof provides a helper function to generate such graph
    auto_completion_graph = utils.generate_auto_completion(
        ["Martin", "Martial", "Wilkins"]
    )
    findex_interface.upsert(auto_completion_graph, master_key, label)

    found_locations = findex_interface.search(["Mar", "Wil"], master_key, label)
    print("Search with auto-completion:")
    for keyword, locations in found_locations.items():
        print("\t", keyword, ":", locations)

    # `Mar` points to both Martin's and Martial's locations.
    # `Wil` only points to Wilkins' location.

    print("Search using the `progress_callback`: ")

    def echo_progress_callback(res: Dict[str, List[IndexedValue]]) -> bool:
        print("\t Partial results:", res)
        return True

    found_locations = findex_interface.search(
        ["Mar"], master_key, label, progress_callback=echo_progress_callback
    )
    print("\t Final results:", found_locations)


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Findex example.")
    parser.add_argument(
        "--redis", action="store_true", help="Use Redis to store Findex indexing tables"
    )
    parser.add_argument(
        "--sqlite",
        action="store_true",
        help="Use SQLite to store Findex indexing tables",
    )

    args = parser.parse_args()

    if args.redis:
        print(
            "Using Redis backend (be sure to have a running Redis instance on your computer)"
        )
        main("Redis")
    elif args.sqlite:
        print("Using in-memory SQLite")
        main("SQLite")
    else:
        print("Using in-memory dictionaries")
        main("Dict")
