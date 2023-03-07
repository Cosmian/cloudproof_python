# Cloudproof Python Library

[![PyPI version](https://badge.fury.io/py/cloudproof_py.svg)](https://badge.fury.io/py/cloudproof_py)
![Build status](https://github.com/Cosmian/cloudproof_python/actions/workflows/ci.yml/badge.svg)

The library provides a Python API to the **Cloudproof Encryption** product of the [Cosmian Ubiquitous Encryption platform](https://cosmian.com).

<!-- toc -->

- [Licensing](#licensing)
- [Cryptographic primitives](#cryptographic-primitives)
- [Getting started](#getting-started)
- [Demo](#demo)
- [Building and testing](#building-and-testing)
- [Versions Correspondence](#versions-correspondence)

<!-- tocstop -->

## Licensing

The library is available under a dual licensing scheme Affero GPL/v3 and commercial. See [LICENSE.md](LICENSE.md) for details.

## Cryptographic primitives

The library is based on:

- [CoverCrypt](https://github.com/Cosmian/cover_crypt) algorithm which allows
  creating ciphertexts for a set of attributes and issuing user keys with access
  policies over these attributes. `CoverCrypt` offers Post-Quantum resistance.

- [Findex](https://github.com/Cosmian/findex) which is a cryptographic protocol designed to securely make search queries on
  an untrusted cloud server. Thanks to its encrypted indexes, large databases can

## Getting started

This library requires `Python >= 3.7`.

To install the current release:

```sh
pip install cloudproof_py
```

Code examples are available in [./examples](./examples) to get you started.
Please [check the online documentation](https://docs.cosmian.com/cloudproof_encryption/use_cases_benefits/) for more details on using the CloudProof APIs.

## Demo

An interactive CLI demo combining policy-based encryption with searchable keywords.

Users data from `./examples/cli_demo/data.json` are encrypted using CoverCrypt and indexed via Findex.

Try the demo:

```sh
examples/cli_demo/run_demo.sh
```

## Building and testing

To build from source:

```sh
scripts/build.sh [-i]
```

**Note**: add `-i` to install after build.

To build and run the tests:

```sh
scripts/build.sh -it
```

To build the documentation:

```sh
scripts/build.sh -d
```

The generated documentation will be in `./docs/_build/html`.

## Versions Correspondence

This library depends on [CoverCrypt](https://github.com/Cosmian/cover_crypt) and [Findex](https://github.com/Cosmian/findex).

This table shows the minimum version correspondence between the various components.

| `cloudproof_py` | CoverCrypt | Findex      | KMS   |
| --------------- | ---------- | ----------- | ----- |
| >=3.0.0         | 11.0.0     | 3.0.0       | 4.3.3 |
| >=2.0.0         | 10.0.0     | 2.0.1,2.1.0 | 4.2.0 |
| >=1.0.0         | 8.0.1      | 2.0.0       | -     |
