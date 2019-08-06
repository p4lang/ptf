#!/bin/sh
set -e
git clone https://github.com/nanomsg/nnpy.git
cd nnpy
sudo pip2 install cffi
sudo pip2 install --upgrade cffi
sudo pip2 install .
cd ..
