#!/bin/sh
set -ux

install_lib() {
    wget "https://package.cosmian.com/cloudproof_rust/$1/linux.zip" &&
        unzip -o linux.zip &&
        pip install --force-reinstall x86_64-unknown-linux-gnu/python-x86_64-unknown-linux-gnu/*.whl &&
        rm linux.zip && rm -rf x86_64*
}

install_lib "v2.5.0"
if [ $? -ne 0 ]; then
    branch="feature/covercrypt_rekey"
    echo installing python from branch ${branch}
    install_lib "last_build/${branch}"
fi

exit 0
