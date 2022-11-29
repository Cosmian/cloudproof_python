# -*- coding: utf-8 -*-
from cosmian_cover_crypt import (
    Policy as PolicyPyo3,
)


class Policy(PolicyPyo3):
    def __init__(self, max_attributes: int = 2**32 - 1) -> None:
        """Generates a new policy

        Args:
            max_attributes (int): number of attribute
                creations (revocation + addition) allowed.
        """
        super().__init__(max_attributes)
