# Cloudproof Encryption Python Library

[![PyPI version](https://badge.fury.io/py/cloudproof_py.svg)](https://badge.fury.io/py/cloudproof_py)
![Build status](https://github.com/Cosmian/cloudproof_python/actions/workflows/ci.yml/badge.svg)

The library provides a Python API to the **Cloudproof Encryption** product of the [Cosmian Ubiquitous Encryption platform](https://cosmian.com).

<!-- toc -->

- [Getting started](#getting-started)
- [Demo](#demo)
- [Building and testing](#building-and-testing)
- [Versions Correspondence](#versions-correspondence)

<!-- tocstop -->

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

| `cloudproof_py` | CoverCrypt | Findex |
| --------------- | ---------- | ------ |
| >=1.0.0         | 8.0.1      | 1.0.1  |
