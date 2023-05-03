#!/bin/sh
set -e

# Optional flags
install_pyo3_build=0 # install pyo3 builds from package.cosmian.com
test=0               # run tests after build
doc=0                # make doc

cd "$(dirname "$0")/.."

# Setup python virtual environment
venv_dir="$(pwd)/venv"
rm -rf "$venv_dir"
mkdir -p "$venv_dir"
python3 -m venv "$venv_dir"

export PATH="$venv_dir/bin:$PATH"

# Remove old build
rm -v dist/*
# Install requirements
pip install -r requirements.txt
# Build package
python3 -m build

while getopts "hitd" opt; do
  case "$opt" in
  h | \?)
    echo "Args:"
    echo "-i  install last pyo3 builds"
    echo "-t  run tests"
    echo "-d  make doc"
    exit 0
    ;;
  i)
    install_pyo3_build=1
    ;;
  t)
    test=1
    ;;
  d)
    doc=1
    ;;
  esac
done

[ $install_pyo3_build -gt 0 ] && scripts/ci_install_pyo3_builds.sh
[ $test -gt 0 ] && pip install dist/cloudproof_py*.whl && python3 -m unittest tests/test*.py
[ $doc -gt 0 ] && pip install dist/cloudproof_py*.whl && python3 scripts/extract_lib_types.py &&
  cd docs && pip install -r requirements.txt && make html
