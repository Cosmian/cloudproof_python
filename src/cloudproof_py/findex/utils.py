# -*- coding: utf-8 -*-
from typing import List, Dict
from cosmian_findex import IndexedValue


def generate_auto_completion(
    keywords: List[str],
    min_word_len: int = 3,
    encoding: str = "utf-8",
) -> Dict[IndexedValue, List[str]]:
    """Generate a Findex graph of all sub-words from a list of keywords.
    For the keyword "Thibaud" with `min_word_len` at 3 it will return
    these aliases ["Thi" => "Thib", "Thib" => "Thiba", "Thiba" => "Thibau", "Thibau" => "Thibaud"]

    The original keywords and corresponding locations must be inserted in Findex independently.

    Args:
        keywords (List[str]): words to generate sub-words from
        min_word_len (int, optional): length of the smallest sub-word to generate. Defaults to 3.
        encoding (str, optional): used to encode the string to bytes. Defaults to "utf-8".

    Returns:
        Dict[IndexedValue, List[str]]: keyword -> sub-word mapping to upsert in Findex.
    """
    res = {}
    for word in keywords:
        for i in range(min_word_len, len(word)):
            res[IndexedValue.from_keyword(word[: i + 1].encode(encoding))] = [word[:i]]

    return res
