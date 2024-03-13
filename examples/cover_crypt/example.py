# -*- coding: utf-8 -*-
import asyncio

from cloudproof_py.cover_crypt import Attribute
from cloudproof_py.cover_crypt import CoverCrypt
from cloudproof_py.cover_crypt import Policy
from cloudproof_py.cover_crypt import PolicyAxis
from cloudproof_py.cover_crypt import UserSecretKey


async def main(use_kms: bool = True):
    """Usage example of Cover Crypt
    Keys generation, encryption and decryption are done locally."""

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
    cover_crypt = CoverCrypt()
    master_private_key, public_key = cover_crypt.generate_master_keys(policy)

    # Messages encryption
    protected_mkg_data = b"protected_mkg_message"
    protected_mkg_ciphertext = cover_crypt.encrypt(
        policy,
        "Department::MKG && Security Level::Protected",
        public_key,
        protected_mkg_data,
    )

    top_secret_mkg_data = b"top_secret_mkg_message"
    top_secret_mkg_ciphertext = cover_crypt.encrypt(
        policy,
        "Department::MKG && Security Level::Top Secret",
        public_key,
        top_secret_mkg_data,
    )

    protected_fin_data = b"protected_fin_message"
    protected_fin_ciphertext = cover_crypt.encrypt(
        policy,
        "Department::FIN && Security Level::Protected",
        public_key,
        protected_fin_data,
    )

    # Generating user keys
    confidential_mkg_user_key = cover_crypt.generate_user_secret_key(
        master_private_key,
        "Department::MKG && Security Level::Confidential",
        policy,
    )

    topSecret_mkg_fin_user_key = cover_crypt.generate_user_secret_key(
        master_private_key,
        "(Department::MKG || Department::FIN) && Security Level::Top Secret",
        policy,
    )

    # Decryption with the right access policy
    protected_mkg_plaintext, _ = cover_crypt.decrypt(
        confidential_mkg_user_key, protected_mkg_ciphertext
    )
    assert protected_mkg_plaintext == protected_mkg_data

    # Decryption without the right access will fail
    try:
        # will throw
        cover_crypt.decrypt(confidential_mkg_user_key, top_secret_mkg_ciphertext)
    except Exception as e:
        # ==> the user is not be able to decrypt
        print("Expected error:", e)

    try:
        # will throw
        cover_crypt.decrypt(confidential_mkg_user_key, protected_fin_ciphertext)
    except Exception as e:
        # ==> the user is not be able to decrypt
        print("Expected error:", e)

    # User with Top Secret access can decrypt messages
    # of all Security Level within the right Department

    protected_mkg_plaintext2, _ = cover_crypt.decrypt(
        topSecret_mkg_fin_user_key, protected_mkg_ciphertext
    )
    assert protected_mkg_plaintext2 == protected_mkg_data

    topSecret_mkg_plaintext, _ = cover_crypt.decrypt(
        topSecret_mkg_fin_user_key, top_secret_mkg_ciphertext
    )
    assert topSecret_mkg_plaintext == top_secret_mkg_data

    protected_fin_plaintext, _ = cover_crypt.decrypt(
        topSecret_mkg_fin_user_key, protected_fin_ciphertext
    )
    assert protected_fin_plaintext == protected_fin_data

    # Rekey

    # make a copy of the current user key
    old_confidential_mkg_user_key = UserSecretKey.from_bytes(
        confidential_mkg_user_key.to_bytes()
    )

    # Rekey MKG attribute
    cover_crypt.rekey_master_keys(
        "Department::MKG", policy, master_private_key, public_key
    )

    # update user key
    cover_crypt.refresh_user_secret_key(
        confidential_mkg_user_key,
        master_private_key,
        keep_old_accesses=True,
    )

    # New confidential marketing message

    confidential_mkg_data = b"confidential_secret_mkg_message"
    confidential_mkg_ciphertext = cover_crypt.encrypt(
        policy,
        "Department::MKG && Security Level::Confidential",
        public_key,
        confidential_mkg_data,
    )

    # Decrypting the messages with the rekeyed key

    # decrypting the "old" `protected marketing` message
    old_protected_mkg_plaintext, _ = cover_crypt.decrypt(
        confidential_mkg_user_key, protected_mkg_ciphertext
    )
    assert old_protected_mkg_plaintext == protected_mkg_data

    # decrypting the "new" `confidential marketing` message
    new_confidential_mkg_plaintext, _ = cover_crypt.decrypt(
        confidential_mkg_user_key, confidential_mkg_ciphertext
    )
    assert new_confidential_mkg_plaintext == confidential_mkg_data

    # Decrypting the messages with the NON rekeyed key

    # decrypting the "old" `protected marketing` message with the old key works
    old_protected_mkg_plaintext, _ = cover_crypt.decrypt(
        old_confidential_mkg_user_key, protected_mkg_ciphertext
    )
    assert old_protected_mkg_plaintext == protected_mkg_data

    # decrypting the "new" `confidential marketing` message with the old key fails
    try:
        cover_crypt.decrypt(old_confidential_mkg_user_key, confidential_mkg_ciphertext)
    except Exception as e:
        # ==> the user is not be able to decrypt
        print("Expected error:", e)

    # Prune: remove old keys for the MKG attribute

    cover_crypt.prune_master_secret_key("Department::MKG", policy, master_private_key)

    # update user key
    cover_crypt.refresh_user_secret_key(
        confidential_mkg_user_key,
        master_private_key,
        keep_old_accesses=True,  # will not keep removed rotations
    )

    # decrypting the "old" `protected marketing` message will fail
    try:
        cover_crypt.decrypt(confidential_mkg_user_key, protected_mkg_ciphertext)
    except Exception as e:
        # ==> the user is not be able to decrypt
        print("Expected error:", e)

    # decrypting the "new" `confidential marketing` message will still work
    new_confidential_mkg_plaintext, _ = cover_crypt.decrypt(
        confidential_mkg_user_key, confidential_mkg_ciphertext
    )
    assert new_confidential_mkg_plaintext == confidential_mkg_data

    # Edit policy

    # Addition
    policy.add_attribute(Attribute("Department", "R&D"), is_hybridized=False)

    # hierarchical axis are immutable (no addition nor deletion allowed)
    try:
        policy.add_attribute(Attribute("Security Level", "Classified"), False)
    except Exception as e:
        print("Expected error:", e)

    # new attributes can be used after updating the master keys
    cover_crypt.update_master_keys(policy, master_private_key, public_key)
    protected_rd_data = b"top_secret_mkg_message"
    protected_rd_ciphertext = cover_crypt.encrypt(
        policy,
        "Department::R&D && Security Level::Protected",
        public_key,
        protected_rd_data,
    )
    confidential_rd_fin_user_key = cover_crypt.generate_user_secret_key(
        master_private_key,
        "(Department::R&D || Department::FIN) && Security Level::Confidential",
        policy,
    )
    protected_rd_plaintext, _ = cover_crypt.decrypt(
        confidential_rd_fin_user_key, protected_rd_ciphertext
    )
    assert protected_rd_plaintext == protected_rd_data

    # Rename attribute "Department::MKG" to "Department::Marketing"
    policy.rename_attribute(Attribute("Department", "MKG"), "Marketing")

    # Encryption and decryption work the same even with previously generated keys and ciphers
    confidential_mkg_plaintext, _ = cover_crypt.decrypt(
        confidential_mkg_user_key, confidential_mkg_ciphertext
    )
    assert confidential_mkg_plaintext == confidential_mkg_data

    # Removing access to an attribute
    # 1 - Keep decryption access to ciphertext from old attributes but remove the right to encrypt new data

    policy.disable_attribute(Attribute("Department", "R&D"))
    # this method can also be used on hierarchical axis
    policy.disable_attribute(Attribute("Security Level", "Protected"))

    # after updating the keys, disabled attributes can no longer be used to encrypt data
    cover_crypt.update_master_keys(policy, master_private_key, public_key)
    cover_crypt.refresh_user_secret_key(
        confidential_rd_fin_user_key,
        master_private_key,
        keep_old_accesses=True,
    )

    # New data encryption for `Department::R&D` will fail
    try:
        cover_crypt.encrypt(
            policy,
            "Department::R&D && Security Level::Protected",
            public_key,
            protected_rd_data,
        )
    except Exception as e:
        print("Expected error:", e)

    # Decryption of old ciphertext is still possible
    new_protected_rd_plaintext, _ = cover_crypt.decrypt(
        confidential_rd_fin_user_key, protected_rd_ciphertext
    )
    assert new_protected_rd_plaintext == protected_rd_data

    # 2 - Complete removing of an attribute
    # /!\ this operation is irreversible and may cause data loss

    policy.remove_attribute(Attribute("Department", "R&D"))
    # removing attribute from hierarchical axis is prohibited
    try:
        policy.remove_attribute(Attribute("Security Level", "Protected"))
    except Exception as e:
        print("Expected error:", e)

    # after updating the keys, removed attributes can no longer be used to encrypt or decrypt
    cover_crypt.update_master_keys(policy, master_private_key, public_key)
    cover_crypt.refresh_user_secret_key(
        confidential_rd_fin_user_key,
        master_private_key,
        keep_old_accesses=True,
    )
    try:
        cover_crypt.decrypt(confidential_rd_fin_user_key, protected_rd_ciphertext)
    except Exception as e:
        print("Expected error:", e)

    # 3 - Removing an entire axis
    # /!\ this operation is irreversible and may cause data loss

    # any type of axis can be removed
    policy.remove_axis("Security Level")

    # updating the keys will remove all access to previous ciphertext encrypted for `Security Level`
    cover_crypt.update_master_keys(policy, master_private_key, public_key)
    try:
        cover_crypt.generate_user_secret_key(
            master_private_key,
            "Department::FIN && Security Level::Confidential",  # `Security Level` can no longer be used here
            policy,
        )
    except Exception as e:
        print("Expected error:", e)


if __name__ == "__main__":
    loop = asyncio.new_event_loop()
    loop.run_until_complete(main())
    loop.close()
