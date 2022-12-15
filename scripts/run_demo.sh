#!/bin/sh
set -eux

pip install termcolor==2.1.1 types-termcolor==1.1.6
cd "$(dirname "$0")/../tests/demo"
python3 main.py
