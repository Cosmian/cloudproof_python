# -*- coding: utf-8 -*-
import asyncio

from cloudproof_py.cover_crypt import Policy
from cloudproof_py.cover_crypt import PolicyAxis
from cloudproof_py.kms import KmsClient


async def main():
    """Usage example of Cover Crypt with the KMS
    Keys generation, encryption and decryption are processed by an external KMS."""

    # Creating Policy
    policy = Policy()
    policy.add_axis(
        PolicyAxis(
            "Security Level",
            [
                ("Protected", False),
                ("Confidential", False),
                # the following attribute is hybridized allowing post-quantum resistance
                ("Top Secret", True),
            ],
            hierarchical=True,  # this is a hierarchical axis
        )
    )
    policy.add_axis(
        PolicyAxis(
            "Department",
            [("FIN", False), ("MKG", False), ("HR", False)],
            hierarchical=False,  # this is NOT a hierarchical axis
        )
    )

    # Generating master keys
    kms_client = KmsClient(server_url="http://localhost:9998", api_key="")
    (
        public_key_uid,
        private_key_uid,
    ) = await kms_client.create_cover_crypt_master_key_pair(policy)

    # Copy the keys locally for backup
    _ = await kms_client.retrieve_cover_crypt_public_master_key(public_key_uid)
    _ = await kms_client.retrieve_cover_crypt_private_master_key(private_key_uid)

    # Messages encryption
    protected_mkg_data = b"protected_mkg_message"
    protected_mkg_ciphertext = await kms_client.cover_crypt_encryption(
        "Department::MKG && Security Level::Protected",
        protected_mkg_data,
        public_key_uid,
    )

    top_secret_mkg_data = b"top_secret_mkg_message"
    top_secret_mkg_ciphertext = await kms_client.cover_crypt_encryption(
        "Department::MKG && Security Level::Top Secret",
        top_secret_mkg_data,
        public_key_uid,
    )

    protected_fin_data = b"protected_fin_message"
    protected_fin_ciphertext = await kms_client.cover_crypt_encryption(
        "Department::FIN && Security Level::Protected",
        protected_fin_data,
        public_key_uid,
    )

    # Generating user keys
    confidential_mkg_user_uid = await kms_client.create_cover_crypt_user_decryption_key(
        "Department::MKG && Security Level::Confidential",
        private_key_uid,
    )

    topSecret_mkg_fin_user_uid = (
        await kms_client.create_cover_crypt_user_decryption_key(
            "(Department::MKG || Department::FIN) && Security Level::Top Secret",
            private_key_uid,
        )
    )

    # Decryption with the right access policy
    protected_mkg_plaintext, _ = await kms_client.cover_crypt_decryption(
        protected_mkg_ciphertext, confidential_mkg_user_uid
    )
    assert protected_mkg_plaintext == protected_mkg_data

    # Decryption without the right access will fail
    try:
        # will throw
        await kms_client.cover_crypt_decryption(
            top_secret_mkg_ciphertext, confidential_mkg_user_uid
        )
    except Exception as e:
        # ==> the user is not be able to decrypt
        print("Expected error:", e)

    try:
        # will throw
        await kms_client.cover_crypt_decryption(
            protected_fin_ciphertext, confidential_mkg_user_uid
        )
    except Exception as e:
        # ==> the user is not be able to decrypt
        print("Expected error:", e)

    # User with Top Secret access can decrypt messages
    # of all Security Level within the right Department

    protected_mkg_plaintext2, _ = await kms_client.cover_crypt_decryption(
        protected_mkg_ciphertext, topSecret_mkg_fin_user_uid
    )
    assert protected_mkg_plaintext2 == protected_mkg_data

    topSecret_mkg_plaintext, _ = await kms_client.cover_crypt_decryption(
        top_secret_mkg_ciphertext, topSecret_mkg_fin_user_uid
    )
    assert topSecret_mkg_plaintext == top_secret_mkg_data

    protected_fin_plaintext, _ = await kms_client.cover_crypt_decryption(
        protected_fin_ciphertext, topSecret_mkg_fin_user_uid
    )
    assert protected_fin_plaintext == protected_fin_data

    # Rekey

    # Rekey all keys having access to "Department::MKG"
    # all active keys will be rekeyed automatically
    await kms_client.rekey_cover_crypt_access_policy("Department::MKG", private_key_uid)

    # New confidential marketing message
    confidential_mkg_data = b"confidential_secret_mkg_message"
    confidential_mkg_ciphertext = await kms_client.cover_crypt_encryption(
        "Department::MKG && Security Level::Confidential",
        confidential_mkg_data,
        public_key_uid,
    )

    # Decrypting the messages with the rekeyed key

    # decrypting the "old" `protected marketing` message
    old_protected_mkg_plaintext, _ = await kms_client.cover_crypt_decryption(
        protected_mkg_ciphertext, confidential_mkg_user_uid
    )
    assert old_protected_mkg_plaintext == protected_mkg_data

    # decrypting the "new" `confidential marketing` message
    new_confidential_mkg_plaintext, _ = await kms_client.cover_crypt_decryption(
        confidential_mkg_ciphertext, confidential_mkg_user_uid
    )
    assert new_confidential_mkg_plaintext == confidential_mkg_data

    # Prune: remove old keys for the MKG attribute

    await kms_client.prune_cover_crypt_access_policy("Department::MKG", private_key_uid)

    # decrypting old messages will fail
    try:
        old_protected_mkg_plaintext, _ = await kms_client.cover_crypt_decryption(
            protected_mkg_ciphertext, confidential_mkg_user_uid
        )
    except Exception as e:
        # ==> the user is not be able to decrypt
        print("Expected error:", e)

    # decrypting the "new" message will still work
    new_confidential_mkg_plaintext, _ = await kms_client.cover_crypt_decryption(
        confidential_mkg_ciphertext, confidential_mkg_user_uid
    )
    assert new_confidential_mkg_plaintext == confidential_mkg_data

    # Edit Policy

    # Rename attribute "Department::MKG" to "Department::Marketing"
    await kms_client.rename_cover_crypt_attribute(
        "Department::MKG", "Marketing", private_key_uid
    )

    # decryption rights have not been modified even for previously generated keys and ciphers
    confidential_mkg_plaintext, _ = await kms_client.cover_crypt_decryption(
        confidential_mkg_ciphertext,
        confidential_mkg_user_uid,
    )
    assert confidential_mkg_plaintext == confidential_mkg_data

    # new encryption or user key generation must use the new attribute name
    topSecret_marketing_data = b"top_secret_marketing_message"
    topSecret_marketing_ciphertext = await kms_client.cover_crypt_encryption(
        "Department::Marketing && Security Level::Top Secret",
        topSecret_marketing_data,
        public_key_uid,
    )

    # new "Marketing" message can still be decrypted with "MKG" keys
    topSecret_marketing_plaintext, _ = await kms_client.cover_crypt_decryption(
        topSecret_marketing_ciphertext, topSecret_mkg_fin_user_uid
    )
    assert topSecret_marketing_plaintext == topSecret_marketing_data

    # Add attributes
    await kms_client.add_cover_crypt_attribute(
        "Department::R&D", False, private_key_uid
    )

    # hierarchical axis are immutable (no addition nor deletion allowed)
    try:
        await kms_client.add_cover_crypt_attribute(
            "Security Level::Classified", False, private_key_uid
        )
    except Exception as e:
        print("Expected error:", e)

    # encrypt a message for the newly created `R&D` attribute
    protected_rd_data = b"protected_rd_message"
    protected_rd_ciphertext = await kms_client.cover_crypt_encryption(
        "Department::R&D && Security Level::Protected",
        protected_rd_data,
        public_key_uid,
    )

    # and generate a user key with access rights for this attribute
    confidential_rd_fin_user_key_uid = (
        await kms_client.create_cover_crypt_user_decryption_key(
            "(Department::R&D || Department::FIN) && Security Level::Confidential",
            private_key_uid,
        )
    )

    # decrypt the R&D message with the new user key
    protected_rd_plaintext, _ = await kms_client.cover_crypt_decryption(
        protected_rd_ciphertext, confidential_rd_fin_user_key_uid
    )
    assert protected_rd_plaintext == protected_rd_data

    # Removing access to an attribute
    # 1 - Keep decryption access to ciphertext from old attributes but remove the right to encrypt new data

    await kms_client.disable_cover_crypt_attribute("Department::R&D", private_key_uid)
    # this method can also be used on hierarchical axis
    await kms_client.disable_cover_crypt_attribute(
        "Security Level::Protected", private_key_uid
    )

    # disabled attributes can no longer be used to encrypt data

    # new data encryption for `Department::R&D` will fail
    try:
        await kms_client.cover_crypt_encryption(
            "Department::R&D && Security Level::Protected",
            protected_rd_data,
            public_key_uid,
        )
    except Exception as e:
        # ==> disabled attributes can no longer be used to encrypt data
        print("Expected error:", e)

    # decryption of old ciphertext is still possible
    new_protected_rd_plaintext, _ = await kms_client.cover_crypt_decryption(
        protected_rd_ciphertext, confidential_rd_fin_user_key_uid
    )
    assert new_protected_rd_plaintext == protected_rd_data

    # remove attributes
    # /!\ this operation is irreversible and may cause data loss

    await kms_client.remove_cover_crypt_attribute("Department::R&D", private_key_uid)
    # removing attribute from hierarchical axis is prohibited
    try:
        await kms_client.remove_cover_crypt_attribute(
            "Security Level::Protected", private_key_uid
        )
    except Exception as e:
        print("Expected error:", e)

    # removed attributes can no longer be used to encrypt or decrypt
    try:
        await kms_client.decrypt(
            protected_rd_ciphertext,
            confidential_rd_fin_user_key_uid,
        )
    except Exception as e:
        # ==> unable to decrypt data for a removed attribute
        print("Expected error:", e)


if __name__ == "__main__":
    loop = asyncio.new_event_loop()
    loop.run_until_complete(main())
    loop.close()
