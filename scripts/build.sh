#!/bin/sh

install=0
test=0
doc=0

while getopts "hitd" opt; do
  case "$opt" in
    h|\?)
      echo "Args:"
      echo "-i  install"
      echo "-t  run tests"
      echo "-d  make doc"
      exit 0
      ;;
    i)  install=1
      ;;
    t)  test=1
      ;;
    d)  doc=1
      ;;
  esac
done

cd "$(dirname "$0")/.."
# Install requirements
pip install -r requirements.txt
# Build package
python3 -m build
# Optional: automatic install
[ $install -gt 0 ] && pip install --force-reinstall dist/cloudproof_py*.whl
# Optional: run tests
[ $test -gt 0 ] && python3 -m unittest tests/test*.py
# Optional: make doc
[ $doc -gt 0 ] && python3 scripts/extract_lib_types.py && cd docs \
&& pip install -r requirements.txt && make html
