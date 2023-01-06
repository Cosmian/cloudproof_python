# -*- coding: utf-8 -*-
from typing import Tuple, Union, List
from cosmian_kms import GetResponse, KmsClient as InternalKmsClient
from cosmian_cover_crypt import (
    Policy,
    Attribute,
    PublicKey,
    MasterSecretKey,
    UserSecretKey,
)


class KmsClient(InternalKmsClient):
    def create_cover_crypt_master_key_pair(
        self, policy: Union[Policy, str]
    ) -> Tuple[str, str]:
        """Generate the master authority keys for supplied Policy.

        Args:
            policy_json (Union[Policy, str]): policy used to generate the keys

        Returns:
            Tuple[str, str]: (Public key UID, Master secret key UID)
        """
        if type(policy) == Policy:
            return super().create_cover_crypt_master_key_pair(policy.to_json())
        return super().create_cover_crypt_master_key_pair(policy)

    def rotate_cover_crypt_attributes(
        self, master_secret_key_identifier: str, attributes: List[Union[Attribute, str]]
    ) -> Tuple[str, str]:
        """Rotate the given policy attributes. This will rekey in the KMS:
            - the Master Keys
            - all User Decryption Keys that contain one of these attributes in their policy.

        Args:
            master_secret_key_identifier (str): master secret key UID
            attributes (List[Union[Attribute, str]]): attributes to rotate e.g. ["Department::HR"]

        Returns:
            Tuple[str, str]: (Public key UID, Master secret key UID)
        """
        return super().rotate_cover_crypt_attributes(
            master_secret_key_identifier,
            [
                attr.to_string() if type(attr) == Attribute else attr
                for attr in attributes
            ],
        )

    def retrieve_cover_crypt_public_master_key(
        self, public_key_identifier: str
    ) -> PublicKey:
        """Fetch a CoverCrypt Public Master key.

        Args:
            public_key_identifier (str): the key unique identifier in the KMS

        Returns:
            PublicKey
        """
        return PublicKey.from_bytes(
            super().get_object(public_key_identifier).key_block()
        )

    def retrieve_cover_crypt_private_master_key(
        self, master_secret_key_identifier: str
    ) -> MasterSecretKey:
        """Fetch a CoverCrypt Private Master key.

        Args:
            master_secret_key_identifier (str): the key unique identifier in the KMS

        Returns:
            MasterSecretKey
        """
        return MasterSecretKey.from_bytes(
            super().get_object(master_secret_key_identifier).key_block()
        )

    def retrieve_cover_crypt_user_key(self, user_key_identifier: str) -> UserSecretKey:
        """Fetch a CoverCrypt Private User key.

        Args:
            user_key_identifier (str): the key unique identifier in the KMS

        Returns:
            UserSecretKey
        """
        return UserSecretKey.from_bytes(
            super().get_object(user_key_identifier).key_block()
        )


__all__ = ["GetResponse", "KmsClient"]
