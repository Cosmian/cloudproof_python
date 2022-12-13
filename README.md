# Cloudproof Encryption Python Library

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

> An interactive cli demo combining policy based encryption with searchable keywords
> Users from `./tests/demo/data.json` are encrypted using CoverCrypt and indexed via Findex

- Run

```sh
tests/run_demo.sh
```
