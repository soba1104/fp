#!/bin/sh

cd src/ss
cmake -D DEBUG_BUILD=${1} . && make clean && make VERBOSE=true && make install
cd ../../

make clean
cmake -D DEBUG_BUILD=${1} .
make VERBOSE=true
