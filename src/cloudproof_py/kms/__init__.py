# -*- coding: utf-8 -*-
from typing import List
from typing import Optional
from typing import Tuple
from typing import Union

from cloudproof_cover_crypt import Attribute
from cloudproof_cover_crypt import MasterPublicKey
from cloudproof_cover_crypt import MasterSecretKey
from cloudproof_cover_crypt import Policy
from cloudproof_cover_crypt import UserSecretKey
from cosmian_kms import KmsClient as InternalKmsClient
from cosmian_kms import KmsObject
from cosmian_kms import UidOrTags


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
        self,
        attributes: List[Union[Attribute, str]],
<<<<<<< HEAD
        master_secret_key_identifier: UidOrTags,
=======
        master_secret_key_identifier: Optional[str],
>>>>>>> ad9b01b (feat: support KMS 4.11)
    ) -> Tuple[str, str]:
        """Rotate the given policy attributes. This will rekey in the KMS:
            - the Master Keys
            - all User Decryption Keys that contain one of these attributes in their policy.

        Args:
            attributes (List[Union[Attribute, str]]): attributes to rotate e.g. ["Department::HR"]
            master_secret_key_identifier (Union[str, List[str])): master secret key referenced by its UID or a list of tags

        Returns:
            Tuple[str, str]: (Public key UID, Master secret key UID)
        """
        return await super().rotate_cover_crypt_attributes(
            [
                attr.to_string() if isinstance(attr, Attribute) else attr
                for attr in attributes
            ],
            master_secret_key_identifier,
        )

    async def cover_crypt_encryption(
        self,
        encryption_policy_str: str,
        data: bytes,
<<<<<<< HEAD
        public_key_identifier: UidOrTags,
=======
        public_key_identifier: Optional[str],
>>>>>>> ad9b01b (feat: support KMS 4.11)
        header_metadata: Optional[bytes] = None,
        authentication_data: Optional[bytes] = None,
    ) -> bytes:
        """Hybrid encryption. Concatenates the encrypted header and the symmetric
        ciphertext.

        Args:
            encryption_policy_str (str): the access policy to use for encryption
            data (bytes): data to encrypt
            public_key_identifier (Union[str, List[str]]): public key unique id or associated tags
            header_metadata (Optional[bytes]): additional data to encrypt in the header
            authentication_data (Optional[bytes]): authentication data to use in the encryption

        Returns:
            Future[bytes]: ciphertext
        """
        return bytes(
            await super().cover_crypt_encryption(
                encryption_policy_str,
                data,
                public_key_identifier,
                header_metadata,
                authentication_data,
            )
        )

    async def cover_crypt_decryption(
        self,
        encrypted_data: bytes,
<<<<<<< HEAD
        user_key_identifier: UidOrTags,
=======
        user_key_identifier: Optional[str],
>>>>>>> ad9b01b (feat: support KMS 4.11)
        authentication_data: Optional[bytes] = None,
    ) -> Tuple[bytes, bytes]:
        """Hybrid decryption.

        Args:
            encrypted_data (bytes): encrypted header || symmetric ciphertext
            user_key_identifier (Union[str, List[str]]): user secret key unique id or associated tags
            authentication_data (Optional[bytes]): authentication data to use in the decryption

        Returns:
            Future[Tuple[bytes, bytes]]: (plaintext bytes, header metadata bytes)
        """
        plaintext, header = await super().cover_crypt_decryption(
            encrypted_data, user_key_identifier, authentication_data
        )
        return bytes(plaintext), bytes(header)

    async def retrieve_cover_crypt_public_master_key(
        self, public_key_identifier: UidOrTags
    ) -> MasterPublicKey:
        """Fetch a CoverCrypt Public Master key.

        Args:
            public_key_identifier (Union[str, List[str]]): public key unique id or associated tags

        Returns:
            MasterPublicKey
        """
        object = await super().get_object(public_key_identifier)
        return MasterPublicKey.from_bytes(object.key_block())

    async def retrieve_cover_crypt_private_master_key(
        self, master_secret_key_identifier: UidOrTags
    ) -> MasterSecretKey:
        """Fetch a CoverCrypt Private Master key.

        Args:
            master_secret_key_identifier (str): the master secret key unique id or associated tags

        Returns:
            MasterSecretKey
        """
        object = await super().get_object(master_secret_key_identifier)
        return MasterSecretKey.from_bytes(object.key_block())

    async def retrieve_cover_crypt_user_decryption_key(
        self, user_key_identifier: UidOrTags
    ) -> UserSecretKey:
        """Fetch a CoverCrypt Private User key.

        Args:
            user_key_identifier (Union[str, List[str]]): user secret key unique id or associated tags

        Returns:
            UserSecretKey
        """
        object = await super().get_object(user_key_identifier)
        return UserSecretKey.from_bytes(object.key_block())


__all__ = ["KmsObject", "KmsClient"]
