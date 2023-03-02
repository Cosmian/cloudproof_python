#!/bin/sh
set -ux

install_lib() {
    wget "https://package.cosmian.com/$1/$2/linux.zip" &&
        unzip -o linux.zip &&
        pip install --force-reinstall x86_64-unknown-linux-gnu/python-x86_64-unknown-linux-gnu/$1*.whl &&
        rm linux.zip && rm -rf x86_64-unknown-linux-gnu
}

install_lib "cover_crypt" "v11.0.0"
if [ $? -ne 0 ]; then
    install_lib "cover_crypt" "last_build"
fi

install_lib "findex" "v3.0.0"
if [ $? -ne 0 ]; then
    install_lib "findex" "last_build"
fi
