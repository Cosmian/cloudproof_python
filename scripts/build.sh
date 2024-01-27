#!/bin/bash
set -ex

# Optional flags
install_pyo3_build=0 # install pyo3 builds from package.cosmian.com
test=0               # run tests after build
doc=0                # make doc

cd "$(dirname "$0")/.."

# Setup python virtual environment
venv_dir="$(pwd)/build/venv"
rm -rf "$venv_dir"
mkdir -p "$venv_dir"
python3 -m venv "$venv_dir"

export PATH="$venv_dir/bin:$PATH"

# Remove old build
rm -v dist/* || true
# Install requirements
pip install -r requirements.txt
# Build package
python3 -m build

check=0
while getopts "hitdc" opt; do
  case "$opt" in
  h | \?)
    echo "Args:"
    echo "-i  install last pyo3 builds"
    echo "-t  run tests"
    echo "-d  make doc"
    echo "-c  mypy checks"
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
  c)
    check=1
    ;;
  esac
done

if [ $install_pyo3_build -gt 0 ]; then
  pip install -r requirements.txt
  bash scripts/ci_install_pyo3_builds.sh
  pip install mypy "types-termcolor>=1.1" "types_redis>=4.3" "requests>=2.28" "types-requests>=2.28"
fi
if [ $test -gt 0 ]; then
  pip install dist/cloudproof_py*.whl
  python3 -m unittest tests/test*.py
fi
if [ $doc -gt 0 ]; then
  pip install dist/cloudproof_py*.whl
  python3 scripts/extract_lib_types.py
  pushd docs
  pip install -r requirements.txt
  make html
  popd
fi
if [ $check -gt 0 ]; then
  mypy src/cloudproof_py/anonymization/
  mypy src/cloudproof_py/cover_crypt/
  mypy src/cloudproof_py/findex/
  mypy src/cloudproof_py/fpe/
  mypy tests/
  mypy examples/cli_demo/
  mypy examples/findex_upsert_search/
  mypy examples/cover_crypt/
fi
