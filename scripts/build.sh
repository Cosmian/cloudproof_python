#!/bin/sh
set -eux

python3 scripts/lib_typing.py
python3 -m build
