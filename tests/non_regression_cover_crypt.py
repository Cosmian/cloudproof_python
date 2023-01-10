# -*- coding: utf-8 -*-
import json
from cloudproof_py.cover_crypt import (
    Policy,
    PolicyAxis,
    CoverCrypt,
    MasterSecretKey,
    PublicKey,
)
from base64 import b64encode
from typing import Union


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


if __name__ == "__main__":
    vector = generate_non_regression_vector()
    with open(
        "tests/data/cover_crypt/non_regression/non_regression_test_vector.json", "w"
    ) as file:
        json.dump(vector, file, indent=2)
