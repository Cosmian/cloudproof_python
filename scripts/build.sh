#!/bin/sh

install=0
test=0

while getopts "hit" opt; do
  case "$opt" in
    h|\?)
      echo "Args:"
      echo "-i  install"
      echo "-t  run tests"
      exit 0
      ;;
    i)  install=1
      ;;
    t)  test=1
      ;;
  esac
done

# Get py interfaces from pyo3 libs
python3 scripts/lib_typing.py
# Build package
python3 -m build
# Optional: automatic install
[ $install -gt 0 ] && pip install --force-reinstall dist/cloudproof_py*.whl
# Optional: run tests
[ $test -gt 0 ] && python3 tests/test*.py
