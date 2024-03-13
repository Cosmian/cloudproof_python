# -*- coding: utf-8 -*-
import unittest

from cloudproof_py.cover_crypt import Attribute
from cloudproof_py.cover_crypt import CoverCrypt
from cloudproof_py.cover_crypt import MasterPublicKey
from cloudproof_py.cover_crypt import MasterSecretKey
from cloudproof_py.cover_crypt import Policy
from cloudproof_py.cover_crypt import PolicyAxis
from cloudproof_py.cover_crypt import UserSecretKey
from cloudproof_py.kms import KmsClient


class TestCoverCryptNative(unittest.TestCase):
    def test_doc_example(self) -> None:
        policy = Policy()
        policy.add_axis(
            PolicyAxis(
                "Security Level",
                [("Protected", False), ("Confidential", False), ("Top Secret", True)],
                hierarchical=True,
            )
        )
        policy.add_axis(
            PolicyAxis(
                "Department",
                ["FIN", "MKG", "HR"],
                hierarchical=False,
            )
        )

        cover_crypt = CoverCrypt()
        master_private_key, public_key = cover_crypt.generate_master_keys(policy)

        protected_mkg_data = b"protected_mkg_message"
        protected_mkg_ciphertext = cover_crypt.encrypt(
            policy,
            "Department::MKG && Security Level::Protected",
            public_key,
            protected_mkg_data,
        )

        topSecret_mkg_data = b"top_secret_mkg_message"
        topSecret_mkg_ciphertext = cover_crypt.encrypt(
            policy,
            "Department::MKG && Security Level::Top Secret",
            public_key,
            topSecret_mkg_data,
        )

        protected_fin_data = b"protected_fin_message"
        protected_fin_ciphertext = cover_crypt.encrypt(
            policy,
            "Department::FIN && Security Level::Protected",
            public_key,
            protected_fin_data,
        )

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

        protected_mkg_plaintext, _ = cover_crypt.decrypt(
            confidential_mkg_user_key, protected_mkg_ciphertext
        )
        self.assertEqual(protected_mkg_plaintext, protected_mkg_data)

        with self.assertRaises(Exception):
            cover_crypt.decrypt(confidential_mkg_user_key, topSecret_mkg_ciphertext)

        with self.assertRaises(Exception):
            cover_crypt.decrypt(confidential_mkg_user_key, protected_fin_ciphertext)

        protected_mkg_plaintext2, _ = cover_crypt.decrypt(
            topSecret_mkg_fin_user_key, protected_mkg_ciphertext
        )
        self.assertEqual(protected_mkg_plaintext2, protected_mkg_data)

        topSecret_mkg_plaintext, _ = cover_crypt.decrypt(
            topSecret_mkg_fin_user_key, topSecret_mkg_ciphertext
        )
        self.assertEqual(topSecret_mkg_plaintext, topSecret_mkg_data)

        protected_fin_plaintext, _ = cover_crypt.decrypt(
            topSecret_mkg_fin_user_key, protected_fin_ciphertext
        )
        self.assertEqual(protected_fin_plaintext, protected_fin_data)

        # make a copy of the current user key
        old_confidential_mkg_userKey = UserSecretKey.from_bytes(
            confidential_mkg_user_key.to_bytes()
        )

        # rekey MKG attribute
        cover_crypt.rekey_master_keys(
            "Department::MKG", policy, master_private_key, public_key
        )

        # update user key
        cover_crypt.refresh_user_secret_key(
            confidential_mkg_user_key,
            master_private_key,
            keep_old_accesses=True,
        )

        confidential_mkg_data = b"confidential_secret_mkg_message"
        confidential_mkg_ciphertext = cover_crypt.encrypt(
            policy,
            "Department::MKG && Security Level::Confidential",
            public_key,
            confidential_mkg_data,
        )

        # decrypting the "old" `protected marketing` message
        old_protected_mkg_plaintext, _ = cover_crypt.decrypt(
            confidential_mkg_user_key, protected_mkg_ciphertext
        )
        self.assertEqual(old_protected_mkg_plaintext, protected_mkg_data)

        # decrypting the "new" `confidential marketing` message
        new_confidential_mkg_plaintext, _ = cover_crypt.decrypt(
            confidential_mkg_user_key, confidential_mkg_ciphertext
        )
        self.assertEqual(new_confidential_mkg_plaintext, confidential_mkg_data)

        # Decrypting the messages with the NON rekeyed key

        # decrypting the "old" `protected marketing` message with the old key works
        old_protected_mkg_plaintext, _ = cover_crypt.decrypt(
            old_confidential_mkg_userKey, protected_mkg_ciphertext
        )
        self.assertEqual(old_protected_mkg_plaintext, protected_mkg_data)

        # decrypting the "new" `confidential marketing` message with the old key fails
        with self.assertRaises(Exception):
            cover_crypt.decrypt(
                old_confidential_mkg_userKey, confidential_mkg_ciphertext
            )

        # old keys for this attribute will be definitely removed from the master secret key
        cover_crypt.prune_master_secret_key(
            "Department::MKG", policy, master_private_key
        )

        # update user key
        cover_crypt.refresh_user_secret_key(
            confidential_mkg_user_key,
            master_private_key,
            keep_old_accesses=True,  # will not keep removed rotations
        )

        # decrypting the "old" `protected marketing` message will fail
        with self.assertRaises(Exception):
            cover_crypt.decrypt(confidential_mkg_user_key, protected_mkg_ciphertext)

        # decrypting the "new" `confidential marketing` message will still work
        new_confidential_mkg_plaintext, _ = cover_crypt.decrypt(
            confidential_mkg_user_key, confidential_mkg_ciphertext
        )
        self.assertEqual(new_confidential_mkg_plaintext, confidential_mkg_data)

        # Addition
        policy.add_attribute(Attribute("Department", "R&D"), is_hybridized=False)

        # hierarchical axis are immutable (no addition nor deletion allowed)
        with self.assertRaises(Exception):
            policy.add_attribute(Attribute("Security Level", "Classified"), False)

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
        self.assertEqual(protected_rd_plaintext, protected_rd_data)

        # Rename attribute "Department::MKG" to "Department::Marketing"
        policy.rename_attribute(Attribute("Department", "MKG"), "Marketing")

        # Encryption and decryption work the same even with previously generated keys and ciphers
        confidential_mkg_plaintext, _ = cover_crypt.decrypt(
            confidential_mkg_user_key, confidential_mkg_ciphertext
        )
        self.assertEqual(confidential_mkg_plaintext, confidential_mkg_data)

        # Disable attribute
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
        with self.assertRaises(Exception):
            cover_crypt.encrypt(
                policy,
                "Department::R&D && Security Level::Protected",
                public_key,
                protected_rd_data,
            )

        # Decryption of old ciphertext is still possible
        new_protected_rd_plaintext, _ = cover_crypt.decrypt(
            confidential_rd_fin_user_key, protected_rd_ciphertext
        )
        self.assertEqual(new_protected_rd_plaintext, protected_rd_data)

        # Remove an attribute
        policy.remove_attribute(Attribute("Department", "R&D"))
        # removing attribute from hierarchical axis is prohibited
        with self.assertRaises(Exception):
            policy.remove_attribute(Attribute("Security Level", "Protected"))

        # after updating the keys, removed attributes can no longer be used to encrypt or decrypt
        cover_crypt.update_master_keys(policy, master_private_key, public_key)
        cover_crypt.refresh_user_secret_key(
            confidential_rd_fin_user_key,
            master_private_key,
            keep_old_accesses=True,
        )
        with self.assertRaises(Exception):
            cover_crypt.decrypt(confidential_rd_fin_user_key, protected_rd_ciphertext)

        # Removing an axis
        policy.remove_axis("Security Level")

        # updating the keys will remove all access to previous ciphertext encrypted for `Security Level`
        cover_crypt.update_master_keys(policy, master_private_key, public_key)
        with self.assertRaises(Exception):
            cover_crypt.generate_user_secret_key(
                master_private_key,
                "Department::FIN && Security Level::Confidential",  # `Security Level` can no longer be used here
                policy,
            )


class TestCoverCryptKMS(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.client = KmsClient("http://localhost:9998")
        self.cc_interface = CoverCrypt()

        # Create Policy
        self.policy = Policy()
        self.policy.add_axis(
            PolicyAxis(
                "Security Level",
                [("Protected", False), ("Confidential", False), ("Top Secret", False)],
                hierarchical=True,
            )
        )
        self.policy.add_axis(
            PolicyAxis(
                "Department",
                [("FIN", False), ("MKG", False), ("HR", False)],
                hierarchical=False,
            )
        )

        # Generate master key pair
        (
            self.pubkey_uid,
            self.privkey_uid,
        ) = await self.client.create_cover_crypt_master_key_pair(self.policy)

    async def test_doc_example_kms(self) -> None:
        protected_mkg_data = b"protected_mkg_message"
        protected_mkg_ciphertext = await self.client.cover_crypt_encryption(
            "Department::MKG && Security Level::Protected",
            protected_mkg_data,
            self.pubkey_uid,
        )

        top_secret_mkg_data = b"top_secret_mkg_message"
        top_secret_mkg_ciphertext = await self.client.cover_crypt_encryption(
            "Department::MKG && Security Level::Top Secret",
            top_secret_mkg_data,
            self.pubkey_uid,
        )

        protected_fin_data = b"protected_fin_message"
        protected_fin_ciphertext = await self.client.cover_crypt_encryption(
            "Department::FIN && Security Level::Protected",
            protected_fin_data,
            self.pubkey_uid,
        )

        confidential_mkg_user_uid = (
            await self.client.create_cover_crypt_user_decryption_key(
                "Department::MKG && Security Level::Confidential",
                self.privkey_uid,
            )
        )

        topSecret_mkg_fin_user_uid = (
            await self.client.create_cover_crypt_user_decryption_key(
                "(Department::MKG || Department::FIN) && Security Level::Top Secret",
                self.privkey_uid,
            )
        )

        protected_mkg_plaintext, _ = await self.client.cover_crypt_decryption(
            protected_mkg_ciphertext, confidential_mkg_user_uid
        )
        self.assertEqual(protected_mkg_plaintext, protected_mkg_data)

        with self.assertRaises(Exception):
            # will throw
            await self.client.cover_crypt_decryption(
                top_secret_mkg_ciphertext, confidential_mkg_user_uid
            )

        with self.assertRaises(Exception):
            # will throw
            await self.client.cover_crypt_decryption(
                protected_fin_ciphertext, confidential_mkg_user_uid
            )

        protected_mkg_plaintext2, _ = await self.client.cover_crypt_decryption(
            protected_mkg_ciphertext, topSecret_mkg_fin_user_uid
        )
        self.assertEqual(protected_mkg_plaintext2, protected_mkg_data)

        topSecret_mkg_plaintext, _ = await self.client.cover_crypt_decryption(
            top_secret_mkg_ciphertext, topSecret_mkg_fin_user_uid
        )
        self.assertEqual(topSecret_mkg_plaintext, top_secret_mkg_data)

        protected_fin_plaintext, _ = await self.client.cover_crypt_decryption(
            protected_fin_ciphertext, topSecret_mkg_fin_user_uid
        )
        self.assertEqual(protected_fin_plaintext, protected_fin_data)

        # make a copy of the current user key
        old_confidential_mkg_user_key = (
            await self.client.retrieve_cover_crypt_user_decryption_key(
                confidential_mkg_user_uid
            )
        )

        # rekey MKG attribute
        await self.client.rekey_cover_crypt_access_policy(
            "Department::MKG", self.privkey_uid
        )

        confidential_mkg_data = b"confidential_secret_mkg_message"
        confidential_mkg_ciphertext = await self.client.cover_crypt_encryption(
            "Department::MKG && Security Level::Confidential",
            confidential_mkg_data,
            self.pubkey_uid,
        )

        # decrypting the "old" `protected marketing` message
        old_protected_mkg_plaintext, _ = await self.client.cover_crypt_decryption(
            protected_mkg_ciphertext, confidential_mkg_user_uid
        )
        self.assertEqual(old_protected_mkg_plaintext, protected_mkg_data)

        # decrypting the "new" `confidential marketing` message
        new_confidential_mkg_plaintext, _ = await self.client.cover_crypt_decryption(
            confidential_mkg_ciphertext, confidential_mkg_user_uid
        )
        self.assertEqual(new_confidential_mkg_plaintext, confidential_mkg_data)

        # Importing NON rekeyed key
        old_confidential_mkg_user_uid = (
            await self.client.import_cover_crypt_user_decryption_key(
                old_confidential_mkg_user_key.to_bytes(),
                False,
                self.privkey_uid,
                "Department::MKG && Security Level::Confidential",
            )
        )

        # decrypting the "old" `protected marketing` message with the old key works
        old_protected_mkg_plaintext, _ = await self.client.cover_crypt_decryption(
            protected_mkg_ciphertext, old_confidential_mkg_user_uid
        )
        self.assertEqual(old_protected_mkg_plaintext, protected_mkg_data)

        # decrypting the "new" `confidential marketing` message with the old key fails
        with self.assertRaises(Exception):
            await self.client.cover_crypt_decryption(
                confidential_mkg_ciphertext, old_confidential_mkg_user_uid
            )

        # Remove old keys for the MKG attribute
        await self.client.prune_cover_crypt_access_policy(
            "Department::MKG", self.privkey_uid
        )

        # decrypting old messages will fail
        with self.assertRaises(Exception):
            old_protected_mkg_plaintext, _ = await self.client.cover_crypt_decryption(
                protected_mkg_ciphertext, confidential_mkg_user_uid
            )

        # Edit Policy

        # Rename attribute "Department::MKG" to "Department::Marketing"
        await self.client.rename_cover_crypt_attribute(
            "Department::MKG", "Marketing", self.privkey_uid
        )

        # Decryption rights have not been modified even for previously generated keys and ciphers
        confidential_mkg_plaintext, _ = await self.client.cover_crypt_decryption(
            confidential_mkg_ciphertext,
            confidential_mkg_user_uid,
        )
        self.assertEqual(confidential_mkg_plaintext, confidential_mkg_data)

        # New encryption or user key generation must use the new attribute name
        topSecret_marketing_data = b"top_secret_marketing_message"
        topSecret_marketing_ciphertext = await self.client.cover_crypt_encryption(
            "Department::Marketing && Security Level::Top Secret",
            topSecret_marketing_data,
            self.pubkey_uid,
        )

        # new "Marketing" message can still be decrypted with "MKG" keys
        topSecret_marketing_plaintext, _ = await self.client.cover_crypt_decryption(
            topSecret_marketing_ciphertext, topSecret_mkg_fin_user_uid
        )
        self.assertEqual(topSecret_marketing_plaintext, topSecret_marketing_data)

        # Addition
        await self.client.add_cover_crypt_attribute(
            "Department::R&D", False, self.privkey_uid
        )

        # hierarchical axis are immutable (no addition nor deletion allowed)
        with self.assertRaises(Exception):
            await self.client.add_cover_crypt_attribute(
                "Security Level::Classified", False, self.privkey_uid
            )

        # master keys are automatically updated with the new attributes
        protected_rd_data = b"protected_mkg_message"
        protected_rd_ciphertext = await self.client.cover_crypt_encryption(
            "Department::R&D && Security Level::Protected",
            protected_rd_data,
            self.pubkey_uid,
        )
        confidential_rd_fin_user_key_uid = (
            await self.client.create_cover_crypt_user_decryption_key(
                "(Department::R&D || Department::FIN) && Security Level::Confidential",
                self.privkey_uid,
            )
        )

        protected_rd_plaintext, _ = await self.client.cover_crypt_decryption(
            protected_rd_ciphertext, confidential_rd_fin_user_key_uid
        )
        self.assertEqual(protected_rd_plaintext, protected_rd_data)

        # Removing access to an attribute
        # 1 - Keep decryption access to ciphertext from old attributes but remove the right to encrypt new data

        await self.client.disable_cover_crypt_attribute(
            "Department::R&D", self.privkey_uid
        )
        # this method can also be used on hierarchical axis
        await self.client.disable_cover_crypt_attribute(
            "Security Level::Protected", self.privkey_uid
        )

        # disabled attributes can no longer be used to encrypt data

        # New data encryption for `Department::R&D` will fail
        with self.assertRaises(Exception):
            await self.client.cover_crypt_encryption(
                "Department::R&D && Security Level::Protected",
                protected_rd_data,
                self.pubkey_uid,
            )

        # Decryption of old ciphertext is still possible
        new_protected_rd_plaintext, _ = await self.client.cover_crypt_decryption(
            protected_rd_ciphertext, confidential_rd_fin_user_key_uid
        )
        self.assertEqual(new_protected_rd_plaintext, protected_rd_data)

        # /!\ this operation is irreversible and may cause data loss

        await self.client.remove_cover_crypt_attribute(
            "Department::R&D", self.privkey_uid
        )
        # removing attribute from hierarchical axis is prohibited
        with self.assertRaises(Exception):
            await self.client.remove_cover_crypt_attribute(
                "Security Level::Protected", self.privkey_uid
            )

        # removed attributes can no longer be used to encrypt or decrypt
        with self.assertRaises(Exception):
            await self.client.decrypt(
                protected_rd_ciphertext,
                confidential_rd_fin_user_key_uid,
            )

    async def test_combined_kms_native(self) -> None:
        # Retrieve public key
        pubkey = await self.client.retrieve_cover_crypt_public_master_key(
            self.pubkey_uid
        )
        self.assertIsInstance(pubkey, MasterPublicKey)

        # Retrieve private key
        privkey = await self.client.retrieve_cover_crypt_private_master_key(
            self.privkey_uid
        )
        self.assertIsInstance(privkey, MasterSecretKey)

        # Create user
        confidential_mkg_user_uid = (
            await self.client.create_cover_crypt_user_decryption_key(
                "Department::MKG && Security Level::Confidential", self.privkey_uid
            )
        )

        # Retrieve user key
        confidential_mkg_user_key = (
            await self.client.retrieve_cover_crypt_user_decryption_key(
                confidential_mkg_user_uid
            )
        )
        self.assertIsInstance(confidential_mkg_user_key, UserSecretKey)

        # Encrypt data using KMS
        kms_ciphertext = await self.client.cover_crypt_encryption(
            encryption_policy_str="Department::MKG && Security Level::Protected",
            data=b"kms_message",
            public_key_identifier=self.pubkey_uid,
            header_metadata=b"kms_header",
            authentication_data=b"token1",
        )

        # Decrypting KMS data using native instance
        msg, header = self.cc_interface.decrypt(
            confidential_mkg_user_key,
            kms_ciphertext,
            authentication_data=b"token1",
        )
        self.assertEqual(msg, b"kms_message")
        self.assertEqual(header, b"kms_header")

        # Encrypt data using native instance
        native_ciphertext = self.cc_interface.encrypt(
            self.policy,
            "Department::MKG && Security Level::Confidential",
            pubkey,
            b"native_message",
            header_metadata=b"native_header",
            authentication_data=b"token2",
        )

        # Decrypt using KMS
        msg, header = await self.client.cover_crypt_decryption(
            native_ciphertext, confidential_mkg_user_uid, authentication_data=b"token2"
        )
        self.assertEqual(msg, b"native_message")
        self.assertEqual(header, b"native_header")


if __name__ == "__main__":
    unittest.main()
