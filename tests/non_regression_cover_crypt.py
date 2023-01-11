# -*- coding: utf-8 -*-
import json
from base64 import b64encode, b64decode
from typing import Union
import os
import argparse

from cloudproof_py.cover_crypt import (
    Policy,
    PolicyAxis,
    CoverCrypt,
    MasterSecretKey,
    PublicKey,
    UserSecretKey,
)


def base64_str(input: Union[str, bytes], encoding="utf-8") -> str:
    if isinstance(input, bytes):
        return b64encode(input).decode(encoding)
    return b64encode(input.encode(encoding)).decode(encoding)


def generate_user(
    instance: CoverCrypt,
    master_private_key: MasterSecretKey,
    policy: Policy,
    access_policy: str,
):
    user_key = instance.generate_user_secret_key(
        master_private_key,
        access_policy,
        policy,
    )
    return {
        "key": base64_str(user_key.to_bytes()),
        "access_policy": access_policy,
    }


def generate_ciphertext(
    instance: CoverCrypt,
    public_key: PublicKey,
    policy: Policy,
    access_policy: str,
    plaintext: bytes,
    header_metadata: bytes,
    authentication_data: bytes,
):
    ciphertext = instance.encrypt(
        policy,
        access_policy,
        public_key,
        plaintext,
        header_metadata,
        authentication_data,
    )
    return {
        "encryption_policy": access_policy,
        "plaintext": base64_str(plaintext),
        "ciphertext": base64_str(ciphertext),
        "header_metadata": base64_str(header_metadata),
        "authentication_data": base64_str(authentication_data),
    }


def generate_non_regression_vector():
    non_regression_vector = {}

    policy = Policy()
    policy.add_axis(
        PolicyAxis(
            "Security Level",
            [
                "Protected",
                "Low Secret",
                "Medium Secret",
                "High Secret",
                "Top Secret",
            ],
            hierarchical=True,
        )
    )
    policy.add_axis(
        PolicyAxis("Department", ["R&D", "HR", "MKG", "FIN"], hierarchical=False)
    )
    instance = CoverCrypt()

    master_private_key, public_key = instance.generate_master_keys(policy)

    non_regression_vector["public_key"] = base64_str(public_key.to_bytes())
    non_regression_vector["master_secret_key"] = base64_str(
        master_private_key.to_bytes()
    )
    non_regression_vector["policy"] = base64_str(policy.to_json())

    # Generate user secret keys
    non_regression_vector["top_secret_mkg_fin_key"] = generate_user(
        instance,
        master_private_key,
        policy,
        "(Department::MKG || Department::FIN) && Security Level::Top Secret",
    )

    non_regression_vector["medium_secret_mkg_key"] = generate_user(
        instance,
        master_private_key,
        policy,
        "Department::MKG && Security Level::Medium Secret",
    )

    non_regression_vector["top_secret_fin_key"] = generate_user(
        instance,
        master_private_key,
        policy,
        "Department::FIN && Security Level::Top Secret",
    )

    # Generate ciphertexts
    non_regression_vector["top_secret_mkg_test_vector"] = generate_ciphertext(
        instance,
        public_key,
        policy,
        "Department::MKG && Security Level::Top Secret",
        b"TopSecretMkgPlaintext",
        header_metadata=b"12345",
        authentication_data=b"auth678",
    )

    non_regression_vector["low_secret_mkg_test_vector"] = generate_ciphertext(
        instance,
        public_key,
        policy,
        "Department::MKG && Security Level::Low Secret",
        b"LowSecretMkgPlaintext",
        header_metadata=b"45678",
        authentication_data=b"",
    )

    non_regression_vector["low_secret_fin_test_vector"] = generate_ciphertext(
        instance,
        public_key,
        policy,
        "Department::FIN && Security Level::Low Secret",
        b"LowSecretFinPlaintext",
        header_metadata=b"",
        authentication_data=b"",
    )

    return non_regression_vector


def write_non_regression_vector(
    dest_path: str = "tests/data/export/non_regression_vector.json",
) -> None:
    vector = generate_non_regression_vector()
    with open(dest_path, "w") as file:
        json.dump(vector, file, indent=2)


def test_decrypt(instance: CoverCrypt, ciphertext: dict, key: dict):
    user_key = UserSecretKey.from_bytes(b64decode(key["key"]))

    plaintext, header = instance.decrypt(
        user_key,
        b64decode(ciphertext["ciphertext"]),
        b64decode(ciphertext["authentication_data"]),
    )

    assert plaintext == b64decode(ciphertext["plaintext"])
    assert header == b64decode(ciphertext["header_metadata"])


def test_non_regression_vector(vector: dict) -> None:
    instance = CoverCrypt()

    #
    # Import policy and master keys
    #
    Policy.from_json(b64decode(vector["policy"]).decode("utf-8"))
    MasterSecretKey.from_bytes(b64decode(vector["master_secret_key"]))
    PublicKey.from_bytes(b64decode(vector["public_key"]))

    #
    # Decrypt with top secret fin key
    #
    test_decrypt(
        instance, vector["low_secret_fin_test_vector"], vector["top_secret_fin_key"]
    )

    try:
        test_decrypt(
            instance, vector["low_secret_mkg_test_vector"], vector["top_secret_fin_key"]
        )
        print("ERROR: Should not be able to decrypt")
        exit(1)
    except Exception:
        pass  # failing expected

    try:
        test_decrypt(
            instance, vector["top_secret_mkg_test_vector"], vector["top_secret_fin_key"]
        )
        print("ERROR: Should not be able to decrypt")
        exit(1)
    except Exception:
        pass  # failing expected

    #
    # Decrypt with top secret mkg fin key
    #
    test_decrypt(
        instance, vector["low_secret_fin_test_vector"], vector["top_secret_mkg_fin_key"]
    )
    test_decrypt(
        instance, vector["low_secret_mkg_test_vector"], vector["top_secret_mkg_fin_key"]
    )
    test_decrypt(
        instance, vector["top_secret_mkg_test_vector"], vector["top_secret_mkg_fin_key"]
    )

    #
    # Decrypt with medium secret mkg key
    #
    try:
        test_decrypt(
            instance,
            vector["low_secret_fin_test_vector"],
            vector["medium_secret_mkg_key"],
        )
        print("ERROR: Should not be able to decrypt")
        exit(1)
    except Exception:
        pass  # failing expected

    test_decrypt(
        instance, vector["low_secret_mkg_test_vector"], vector["medium_secret_mkg_key"]
    )

    try:
        test_decrypt(
            instance,
            vector["top_secret_mkg_test_vector"],
            vector["medium_secret_mkg_key"],
        )
        print("ERROR: Should not be able to decrypt")
        exit(1)
    except Exception:
        pass  # failing expected


def read_test_non_regression_vectors(folder: str = "tests/data/cover_crypt/"):
    for filename in os.listdir(folder):
        if filename[-4:] == "json":
            with open(os.path.join(folder, filename)) as json_file:
                non_regression_vector = json.load(json_file)
                test_non_regression_vector(non_regression_vector)
            print(filename, "successfully tested")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Non Regression Tests for CloudProof Python."
    )
    parser.add_argument(
        "--write", action="store_true", help="Write a new test vector on disk"
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="Check all test vectors in tests/data/cover_crypt/non_regression",
    )

    args = parser.parse_args()

    if args.write:
        write_non_regression_vector()
    if args.test:
        read_test_non_regression_vectors()

    elif not args.write and not args.test:
        parser.print_help()
