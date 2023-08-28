# -*- coding: utf-8 -*-
import unittest

from cloudproof_py.cover_crypt import (
    Attribute,
    CoverCrypt,
    MasterSecretKey,
    Policy,
    PolicyAxis,
    PublicKey,
    UserSecretKey,
)
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

        CoverCryptInstance = CoverCrypt()
        master_private_key, public_key = CoverCryptInstance.generate_master_keys(policy)

        protected_mkg_data = b"protected_mkg_message"
        protected_mkg_ciphertext = CoverCryptInstance.encrypt(
            policy,
            "Department::MKG && Security Level::Protected",
            public_key,
            protected_mkg_data,
        )

        topSecret_mkg_data = b"top_secret_mkg_message"
        topSecret_mkg_ciphertext = CoverCryptInstance.encrypt(
            policy,
            "Department::MKG && Security Level::Top Secret",
            public_key,
            topSecret_mkg_data,
        )

        protected_fin_data = b"protected_fin_message"
        protected_fin_ciphertext = CoverCryptInstance.encrypt(
            policy,
            "Department::FIN && Security Level::Protected",
            public_key,
            protected_fin_data,
        )

        confidential_mkg_userKey = CoverCryptInstance.generate_user_secret_key(
            master_private_key,
            "Department::MKG && Security Level::Confidential",
            policy,
        )

        topSecret_mkg_fin_userKey = CoverCryptInstance.generate_user_secret_key(
            master_private_key,
            "(Department::MKG || Department::FIN) && Security Level::Top Secret",
            policy,
        )

        protected_mkg_plaintext, _ = CoverCryptInstance.decrypt(
            confidential_mkg_userKey, protected_mkg_ciphertext
        )
        self.assertEqual(protected_mkg_plaintext, protected_mkg_data)

        with self.assertRaises(Exception):
            # will throw
            CoverCryptInstance.decrypt(
                confidential_mkg_userKey, topSecret_mkg_ciphertext
            )

        with self.assertRaises(Exception):
            # will throw
            CoverCryptInstance.decrypt(
                confidential_mkg_userKey, protected_fin_ciphertext
            )

        protected_mkg_plaintext2, _ = CoverCryptInstance.decrypt(
            topSecret_mkg_fin_userKey, protected_mkg_ciphertext
        )
        self.assertEqual(protected_mkg_plaintext2, protected_mkg_data)

        topSecret_mkg_plaintext, _ = CoverCryptInstance.decrypt(
            topSecret_mkg_fin_userKey, topSecret_mkg_ciphertext
        )
        self.assertEqual(topSecret_mkg_plaintext, topSecret_mkg_data)

        protected_fin_plaintext, _ = CoverCryptInstance.decrypt(
            topSecret_mkg_fin_userKey, protected_fin_ciphertext
        )
        self.assertEqual(protected_fin_plaintext, protected_fin_data)

        # make a copy of the current user key
        old_confidential_mkg_userKey = confidential_mkg_userKey.deep_copy()

        # rotate MKG attribute
        policy.rotate(Attribute("Department", "MKG"))

        # update master keys
        CoverCryptInstance.update_master_keys(policy, master_private_key, public_key)

        # update user key
        CoverCryptInstance.refresh_user_secret_key(
            confidential_mkg_userKey,
            "Department::MKG && Security Level::Confidential",
            master_private_key,
            policy,
            keep_old_accesses=True,
        )

        confidential_mkg_data = b"confidential_secret_mkg_message"
        confidential_mkg_ciphertext = CoverCryptInstance.encrypt(
            policy,
            "Department::MKG && Security Level::Confidential",
            public_key,
            confidential_mkg_data,
        )

        # decrypting the "old" `protected marketing` message
        old_protected_mkg_plaintext, _ = CoverCryptInstance.decrypt(
            confidential_mkg_userKey, protected_mkg_ciphertext
        )
        self.assertEqual(old_protected_mkg_plaintext, protected_mkg_data)

        # decrypting the "new" `confidential marketing` message
        new_confidential_mkg_plaintext, _ = CoverCryptInstance.decrypt(
            confidential_mkg_userKey, confidential_mkg_ciphertext
        )
        self.assertEqual(new_confidential_mkg_plaintext, confidential_mkg_data)

        # Decrypting the messages with the NON rekeyed key

        # decrypting the "old" `protected marketing` message with the old key works
        old_protected_mkg_plaintext, _ = CoverCryptInstance.decrypt(
            old_confidential_mkg_userKey, protected_mkg_ciphertext
        )
        self.assertEqual(old_protected_mkg_plaintext, protected_mkg_data)

        # decrypting the "new" `confidential marketing` message with the old key fails
        with self.assertRaises(Exception):
            new_confidential_mkg_plaintext, _ = CoverCryptInstance.decrypt(
                old_confidential_mkg_userKey, confidential_mkg_ciphertext
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

        # rotate MKG attribute
        (
            new_pubkey_uid,
            new_privkey_uid,
        ) = await self.client.rotate_cover_crypt_attributes(
            ["Department::MKG"], self.privkey_uid
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
            await self.client.import_cover_crypt_user_decryption_key_request(
                old_confidential_mkg_user_key.to_bytes(),
                False,
                self.privkey_uid,
                "Department::MKG && Security Level::Confidential",
                None,
                False,
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

    async def test_combined_kms_native(self) -> None:
        # Retrieve public key
        pubkey = await self.client.retrieve_cover_crypt_public_master_key(
            self.pubkey_uid
        )
        self.assertIsInstance(pubkey, PublicKey)

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
            "Department::MKG && Security Level::Protected",
            b"kms_message",
            self.pubkey_uid,
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
