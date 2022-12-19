# Cloudproof Encryption Python Library

![ci status](https://github.com/Cosmian/cloudproof_python/actions/workflows/ci.yml/badge.svg)

The library provides a Python API to the **Cloudproof Encryption** product of the [Cosmian Ubiquitous Encryption platform](https://cosmian.com).

Please [check the online documentation](https://docs.cosmian.com/cloudproof_encryption/use_cases_benefits/) for details on using the CloudProof APIs.

## Build package

```sh
pip install -r requirements.txt
scripts/build.sh [-i] [-t]
```

## Build docs

```sh
pip install -r docs/requirements.txt
cd docs
make html
```

## Demo

An interactive CLI demo combining policy-based encryption with searchable keywords.

Users from `./examples/cli_demo/data.json` are encrypted using CoverCrypt and indexed via Findex.

- Run

```sh
scripts/run_demo.sh
```

## Versions Correspondence

This library depends on [CoverCrypt](https://github.com/Cosmian/cover_crypt) and [Findex](https://github.com/Cosmian/findex).

This table shows the minimum version correspondence between the various components.

| `cloudproof_py` | CoverCrypt | Findex |
| --------------- | ---------- | ------ |
| 1.0.0           | 8.0.0      | 1.0.0  |
