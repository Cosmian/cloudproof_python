# -*- coding: utf-8 -*-
from typing import Tuple, Union, List, Optional
from cosmian_kms import KmsObject, KmsClient as InternalKmsClient
from cosmian_cover_crypt import (
    Policy,
    Attribute,
    PublicKey,
    MasterSecretKey,
    UserSecretKey,
)


class KmsClient(InternalKmsClient):
    async def create_cover_crypt_master_key_pair(
        self, policy: Union[Policy, bytes]
    ) -> Tuple[str, str]:
        """Generate the master authority keys for supplied Policy.

        Args:
            policy_json (Union[Policy, str]): policy used to generate the keys

        Returns:
            Tuple[str, str]: (Public key UID, Master secret key UID)
        """
        if isinstance(policy, Policy):
            return await super().create_cover_crypt_master_key_pair(policy.to_bytes())
        return await super().create_cover_crypt_master_key_pair(policy)

    async def rotate_cover_crypt_attributes(
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
        return await super().rotate_cover_crypt_attributes(
            master_secret_key_identifier,
            [
                attr.to_string() if isinstance(attr, Attribute) else attr
                for attr in attributes
            ],
        )

    async def cover_crypt_encryption(
        self,
        public_key_identifier: str,
        access_policy_str: str,
        data: bytes,
        header_metadata: Optional[bytes] = None,
        authentication_data: Optional[bytes] = None,
    ) -> bytes:
        """Hybrid encryption. Concatenates the encrypted header and the symmetric
        ciphertext.

        Args:
            public_key_identifier (str): identifier of the public key
            access_policy_str (str): the access policy to use for encryption
            data (bytes): data to encrypt
            header_metadata (Optional[bytes]): additional data to encrypt in the header
            authentication_data (Optional[bytes]): authentication data to use in the encryption

        Returns:
            Future[bytes]: ciphertext
        """
        return bytes(
            await super().cover_crypt_encryption(
                public_key_identifier,
                access_policy_str,
                data,
                header_metadata,
                authentication_data,
            )
        )

    async def cover_crypt_decryption(
        self,
        user_key_identifier: str,
        encrypted_data: bytes,
        authentication_data: Optional[bytes] = None,
    ) -> Tuple[bytes, bytes]:
        """Hybrid decryption.

        Args:
            user_key_identifier (str): user secret key identifier
            encrypted_data (bytes): encrypted header || symmetric ciphertext
            authentication_data (Optional[bytes]): authentication data to use in the decryption

        Returns:
            Future[Tuple[bytes, bytes]]: (plaintext bytes, header metadata bytes)
        """
        plaintext, header = await super().cover_crypt_decryption(
            user_key_identifier, encrypted_data, authentication_data
        )
        return bytes(plaintext), bytes(header)

    async def retrieve_cover_crypt_public_master_key(
        self, public_key_identifier: str
    ) -> PublicKey:
        """Fetch a CoverCrypt Public Master key.

        Args:
            public_key_identifier (str): the key unique identifier in the KMS

        Returns:
            PublicKey
        """
        object = await super().get_object(public_key_identifier)
        return PublicKey.from_bytes(object.key_block())

    async def retrieve_cover_crypt_private_master_key(
        self, master_secret_key_identifier: str
    ) -> MasterSecretKey:
        """Fetch a CoverCrypt Private Master key.

        Args:
            master_secret_key_identifier (str): the key unique identifier in the KMS

        Returns:
            MasterSecretKey
        """
        object = await super().get_object(master_secret_key_identifier)
        return MasterSecretKey.from_bytes(object.key_block())

    async def retrieve_cover_crypt_user_decryption_key(
        self, user_key_identifier: str
    ) -> UserSecretKey:
        """Fetch a CoverCrypt Private User key.

        Args:
            user_key_identifier (str): the key unique identifier in the KMS

        Returns:
            UserSecretKey
        """
        object = await super().get_object(user_key_identifier)
        return UserSecretKey.from_bytes(object.key_block())


__all__ = ["KmsObject", "KmsClient"]
