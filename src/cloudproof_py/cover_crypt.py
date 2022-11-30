# -*- coding: utf-8 -*-
from cosmian_cover_crypt import Policy as PolicyPyo3, PolicyAxis, Attribute
from typing import List


class Policy(PolicyPyo3):
    """A policy is a set of policy axes. A fixed number of attribute creations
    (revocations + additions) is allowed.

    Args:
        max_attributes (int): number of attribute creations allowed.
    """

    def __new__(cls, max_attribute_creations: int = 2**32 - 1):
        """Generates a new policy"""
        return super().__new__(cls, max_attribute_creations)

    def add_axis(self, axis: PolicyAxis) -> None:
        """Adds the given policy axis to the policy.

        Args:
            axis (PolicyAxis)
        """
        super().add_axis(axis)

    def rotate(self, attribute: Attribute) -> None:
        """Rotates an attribute, changing its underlying value with an unused value.

        Args:
            attr (Attribute)
        """
        super().rotate(attribute)

    def attributes(self) -> List[Attribute]:
        """Returns the list of Attributes of this Policy.

        Returns:
            List[Attribute]
        """
        return super().attributes()

    def attribute_values(self, attribute: Attribute) -> List[int]:
        """Returns the list of all attributes values given to this Attribute
        over the time after rotations. The current value is returned first

        Args:
            attr (Attribute)

        Returns:
            List[int]
        """
        return super().attribute_values(attribute)

    def attribute_current_value(attribute: Attribute) -> int:
        """Retrieves the current value of an attribute.

        Args:
            attr (Attribute)

        Returns:
            int
        """
        return super().attribute_current_value(attribute)

    def to_json(self) -> str:
        """Formats policy to json."""
        return super().to_json()

    @staticmethod
    def from_json(policy_json: str) -> PolicyPyo3:
        """Reads policy from a string in json format.

        Args:
            policy_json (str)

        Returns:
            Policy
        """
        return PolicyPyo3.from_json(policy_json)
