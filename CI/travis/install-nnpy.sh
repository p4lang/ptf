#!/bin/sh
set -e
git clone https://github.com/nanomsg/nnpy.git
cd nnpy
sudo pip3 install cffi
sudo pip3 install --upgrade cffi
sudo pip3 install .
cd ..
