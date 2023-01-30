#!/bin/sh
set -eux

install_lib() {
    wget "https://package.cosmian.com/$1/$2/linux.zip"
    unzip linux.zip
    pip install --force-reinstall x86_64-unknown-linux-gnu/python-x86_64-unknown-linux-gnu/$1*.whl
    rm linux.zip && rm -rf x86_64-unknown-linux-gnu
}

install_lib "cover_crypt" ${COVER_CRYPT_TAG:-last_build}
install_lib "findex" ${FINDEX_TAG:-last_build}
