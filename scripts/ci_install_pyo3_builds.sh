#!/bin/sh
set -ux

install_lib() {
    wget "https://package.cosmian.com/cloudproof_rust/$1/linux.zip" &&
        unzip -o linux.zip &&
        pip install --force-reinstall x86_64-unknown-linux-gnu/python-x86_64-unknown-linux-gnu/*.whl &&
        rm linux.zip && rm -rf x86_64*
}

install_lib "v1.0.0"
if [ $? -ne 0 ]; then
    install_lib "last_build/feature/add_findex"
fi
