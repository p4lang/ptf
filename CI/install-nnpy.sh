#!/bin/sh
set -e
git clone https://github.com/nanomsg/nnpy.git
cd nnpy
python3 -m pip install cffi
python3 -m pip install --upgrade cffi
python3 -m pip install .
cd ..
