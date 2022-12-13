#!/bin/sh
set -eux

cd "$(dirname "$0")/demo"
python3 main.py
