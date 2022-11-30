#!/bin/sh
set -euEx

python3 scripts/lib_typing.py
python3 -m build
