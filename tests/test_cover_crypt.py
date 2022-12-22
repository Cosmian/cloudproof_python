# -*- coding: utf-8 -*-
import unittest
from cloudproof_py.cover_crypt import Policy, PolicyAxis, Attribute, CoverCrypt


class TestCoverCrypt(unittest.TestCase):
    def test_doc_example(self) -> None:
        policy = Policy()
        policy.add_axis(
            PolicyAxis(
                "Security Level",
                ["Protected", "Confidential", "Top Secret"],
                hierarchical=True,
            )
        )
        policy.add_axis(
            PolicyAxis("Department", ["FIN", "MKG", "HR"], hierarchical=False)
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


if __name__ == "__main__":
    unittest.main()
