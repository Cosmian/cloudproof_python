#!/bin/sh
set -ux

install_lib() {
    wget "https://package.cosmian.com/cloudproof_rust/$1/all.zip" &&
        unzip -o all.zip &&
        pip install --force-reinstall x86_64-unknown-linux-gnu/python-x86_64-unknown-linux-gnu/*.whl &&
        rm all.zip && rm -rf x86_64*
}

install_lib "v1.0.0"
if [ $? -ne 0 ]; then
    install_lib "last_build"
fi
