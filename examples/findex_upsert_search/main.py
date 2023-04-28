# -*- coding: utf-8 -*-
import argparse
from typing import Union

from findex_dict import FindexDict
from findex_redis import FindexRedis
from findex_sqlite import FindexSQLite

from cloudproof_py.findex import Findex, Keyword, Label, Location, MasterKey, utils
from cloudproof_py.findex.typing import IndexedValuesAndKeywords, ProgressResults

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
    indexed_values_and_keywords: IndexedValuesAndKeywords = {}
    for uid, keywords in data.items():
        # Convert database UIDs to IndexedValue expected by Findex
        location = Location.from_string(uid)
        # This location has 2 keywords associated: the firstname and lastname
        indexed_values_and_keywords[location] = keywords

    # Upsert in Findex
    findex_interface.upsert(master_key, label, indexed_values_and_keywords, {})

    # Search
    keywords_to_search = ["Shepherd", "John"]
    found_locations = findex_interface.search(master_key, label, keywords_to_search)

    print("Locations found by keyword:")
    for keyword, locations in found_locations.items():
        print("\t", keyword, ":", locations)

    # The keyword `Shepherd` points to the lines 1 and 3 of the database.
    # `John` only points to the line 3.

    # Adding alias:
    # Keywords can point to Locations but also to other Keywords, thus generating a graph.

    # Create the alias `Joe` for `John`
    alias_graph: IndexedValuesAndKeywords = {
        Keyword.from_string("John"): ["Joe"],
    }
    findex_interface.upsert(master_key, label, alias_graph, {})

    # Now searching `Joe` will return the same location as `John`
    print("Search with aliases:")
    print("\t", findex_interface.search(master_key, label, ["Joe"]))

    # Generate an auto-completion graph:
    # For example, with the word `Wilkins`, one could upsert the following aliases:
    # ["Wil" => "Wilk", "Wilk" => "Wilki", "Wilki" => "Wilkin", "Wilkin" => "Wilkins"].
    # A search for the Keyword "Wil" will then return the Location of `Wilkins`.

    # CloudProof provides a helper function to generate such graph
    auto_completion_graph = utils.generate_auto_completion(
        ["Martin", "Martial", "Wilkins"]
    )
    findex_interface.upsert(master_key, label, auto_completion_graph, {})

    found_locations = findex_interface.search(master_key, label, ["Mar", "Wil"])
    print("Search with auto-completion:")
    for keyword, locations in found_locations.items():
        print("\t", keyword, ":", locations)

    # `Mar` points to both Martin's and Martial's locations.
    # `Wil` only points to Wilkins' location.

    print("Search using the `progress_callback`: ")

    def echo_progress_callback(res: ProgressResults) -> bool:
        print("\t Partial results:", res)
        return True

    found_locations = findex_interface.search(
        master_key, label, ["Mar"], progress_callback=echo_progress_callback
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
