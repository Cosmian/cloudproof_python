# -*- coding: utf-8 -*-
from typing import List

from cloudproof_findex import IndexedValuesAndKeywords, Keyword


def generate_auto_completion(
    keywords: List[str],
    min_word_len: int = 3,
) -> IndexedValuesAndKeywords:
    """Generate a Findex graph of all sub-words from a list of keywords.
    For the keyword "Thibaud" with `min_word_len` at 3 it will return
    these aliases ["Thi" => "Thib", "Thib" => "Thiba", "Thiba" => "Thibau", "Thibau" => "Thibaud"]

    The original keywords and corresponding locations must be inserted in Findex independently.

    Args:
        keywords (List[str]): words to generate sub-words from
        min_word_len (int, optional): length of the smallest sub-word to generate. Defaults to 3.

    Returns:
        Dict[Keywords, List[Keywords]]: keyword -> sub-word mapping to upsert in Findex.
    """
    res: IndexedValuesAndKeywords = {}
    for word in keywords:
        for i in range(min_word_len, len(word)):
            res[Keyword.from_string(word[: i + 1])] = [word[:i]]

    return res
